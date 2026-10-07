'use strict';

// ClamAV detection uplink API, mounted at /clamav by mqtt.js.
// Contract and rationale: docs/clamav-uplink-api-plan.md in uct-iq9075.
//
// - POST /clamav                        ingest (X-Clamav-Report-Key; value = SSH_SIGN_API_KEY)
// - GET  /clamav/devices                summary (X-Clamav-Read-Key; value = SSH_SIGN_API_KEY)
// - GET  /clamav/devices/:id/events     list    (X-Clamav-Read-Key)
//
// Both credentials fail closed (503) when not configured and are never
// logged. Events are metadata only; unknown fields are dropped.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SCHEMA_VERSION = 1;
const DEVICE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const EVENT_ID_RE = /^[A-Za-z0-9._:-]{8,128}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const TRIGGER_RE = /^[a-z_]{1,32}$/;
const EVENT_TYPES = new Set(['malware-detected', 'scan-skipped', 'monitoring-degraded', 'scan-error']);
const MAX_EVENTS_PER_REQUEST = 100;
const MAX_BODY_BYTES = 256 * 1024;
const MAX_FUTURE_MS = 24 * 3600 * 1000;
const DAY_MS = 24 * 3600 * 1000;

function intEnv(env, name, fallback) {
  const value = parseInt(env[name], 10);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

function digest(value) {
  return crypto.createHash('sha256').update(String(value)).digest();
}

function keyMatches(expected, supplied) {
  // Compare fixed-length digests so neither the value nor its length leaks.
  return crypto.timingSafeEqual(digest(expected), digest(supplied || ''));
}

function isString(value, max, min = 1) {
  return typeof value === 'string' && value.length >= min && value.length <= max && !value.includes('\0');
}

function isCount(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

// Returns { event } or { error }. Only whitelisted fields survive.
function normalizeEvent(raw, deviceId, now) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { error: 'event must be an object' };
  const type = raw.event === undefined ? 'malware-detected' : raw.event;
  if (!EVENT_TYPES.has(type)) return { error: 'unsupported event type' };

  const event = { device_id: deviceId, event: type };

  if (raw.timestamp === undefined) return { error: 'timestamp required' };
  const when = typeof raw.timestamp === 'string' ? Date.parse(raw.timestamp) : NaN;
  if (!Number.isFinite(when)) return { error: 'invalid timestamp' };
  if (when - now > MAX_FUTURE_MS) return { error: 'timestamp too far in the future' };
  event.timestamp = new Date(when).toISOString();

  if (raw.trigger !== undefined) {
    if (typeof raw.trigger !== 'string' || !TRIGGER_RE.test(raw.trigger)) return { error: 'invalid trigger' };
    event.trigger = raw.trigger;
  }
  if (raw.path !== undefined) {
    if (!isString(raw.path, 4096) || raw.path[0] !== '/') return { error: 'invalid path' };
    event.path = raw.path;
  }
  for (const field of ['device', 'inode', 'size']) {
    if (raw[field] !== undefined) {
      if (!isCount(raw[field])) return { error: `invalid ${field}` };
      event[field] = raw[field];
    }
  }
  if (raw.sha256 !== undefined) {
    if (typeof raw.sha256 !== 'string' || !SHA256_RE.test(raw.sha256)) return { error: 'invalid sha256' };
    event.sha256 = raw.sha256;
  }
  if (raw.signature !== undefined) {
    if (!isString(raw.signature, 256)) return { error: 'invalid signature' };
    event.signature = raw.signature;
  }
  for (const [field, max] of [['db_version', 64], ['scanner_output', 2048], ['reason', 256]]) {
    if (raw[field] !== undefined) {
      if (!isString(raw[field], max, 0)) return { error: `invalid ${field}` };
      event[field] = raw[field];
    }
  }
  if (type === 'malware-detected' && !(event.path && event.sha256 && event.signature)) {
    return { error: 'malware-detected requires path, sha256 and signature' };
  }

  if (raw.event_id !== undefined) {
    if (typeof raw.event_id !== 'string' || !EVENT_ID_RE.test(raw.event_id)) return { error: 'invalid event_id' };
    event.event_id = raw.event_id;
  } else {
    const basis = [deviceId, type, event.device, event.inode, event.sha256, event.signature, event.timestamp].join('|');
    event.event_id = crypto.createHash('sha256').update(basis).digest('hex').slice(0, 32);
  }
  return { event };
}

class EventStore {
  constructor(stateDir, options) {
    this.dir = stateDir;
    this.maxEvents = options.maxEventsPerDevice;
    this.retentionMs = options.retentionDays * DAY_MS;
    this.maxDevices = options.maxDevices;
    this.now = options.now;
    this.cache = new Map(); // deviceId -> { events: [], ids: Set, fileLines }
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    this.known = new Set(fs.readdirSync(this.dir).filter((name) => DEVICE_ID_RE.test(name)));
  }

  deviceDir(deviceId) {
    const resolved = path.join(this.dir, deviceId);
    if (path.dirname(resolved) !== path.resolve(this.dir)) throw new Error('invalid device path');
    return resolved;
  }

  load(deviceId) {
    let entry = this.cache.get(deviceId);
    if (entry) return entry;
    const events = [];
    let fileLines = 0;
    const cutoff = this.now() - this.retentionMs;
    try {
      const text = fs.readFileSync(path.join(this.deviceDir(deviceId), 'events.jsonl'), 'utf8');
      for (const line of text.split('\n')) {
        if (!line) continue;
        fileLines += 1;
        try {
          const event = JSON.parse(line);
          if (event && event.event_id && Date.parse(event.received_at) >= cutoff) events.push(event);
        } catch (err) { /* skip a torn or corrupt line; never fail the device */ }
      }
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
    entry = { events, ids: new Set(events.map((e) => e.event_id)), fileLines };
    this.cache.set(deviceId, entry);
    return entry;
  }

  append(deviceId, incoming) {
    if (!this.known.has(deviceId) && this.known.size >= this.maxDevices) {
      const err = new Error('device limit reached');
      err.code = 'too_many_devices';
      throw err;
    }
    const entry = this.load(deviceId);
    const fresh = [];
    let duplicates = 0;
    for (const event of incoming) {
      if (entry.ids.has(event.event_id)) { duplicates += 1; continue; }
      entry.ids.add(event.event_id);
      fresh.push({ ...event, received_at: new Date(this.now()).toISOString() });
    }
    if (fresh.length) {
      const dir = this.deviceDir(deviceId);
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      fs.appendFileSync(path.join(dir, 'events.jsonl'), fresh.map((e) => JSON.stringify(e)).join('\n') + '\n', { mode: 0o600 });
      entry.events.push(...fresh);
      entry.fileLines += fresh.length;
      this.known.add(deviceId);
      if (entry.fileLines > this.maxEvents + Math.max(100, Math.ceil(this.maxEvents * 0.25))) this.compact(deviceId, entry);
    }
    return { accepted: fresh.length, duplicates };
  }

  compact(deviceId, entry) {
    const cutoff = this.now() - this.retentionMs;
    entry.events = entry.events.filter((e) => Date.parse(e.received_at) >= cutoff).slice(-this.maxEvents);
    entry.ids = new Set(entry.events.map((e) => e.event_id));
    const file = path.join(this.deviceDir(deviceId), 'events.jsonl');
    const tmp = `${file}.tmp`;
    fs.writeFileSync(tmp, entry.events.map((e) => JSON.stringify(e)).join('\n') + (entry.events.length ? '\n' : ''), { mode: 0o600 });
    fs.renameSync(tmp, file);
    entry.fileLines = entry.events.length;
  }

  list(deviceId, { since, event, limit }) {
    const cutoff = this.now() - this.retentionMs;
    let events = this.load(deviceId).events.filter((e) => Date.parse(e.received_at) >= cutoff).slice(-this.maxEvents);
    if (since !== undefined) events = events.filter((e) => Date.parse(e.timestamp) >= since);
    if (event) events = events.filter((e) => e.event === event);
    return events.slice().reverse().slice(0, limit);
  }

  summary() {
    return Array.from(this.known).sort().map((deviceId) => {
      const events = this.list(deviceId, { limit: this.maxEvents });
      return {
        device_id: deviceId,
        event_count: events.length,
        last_event_at: events.length ? events[0].timestamp : null,
        last_received_at: events.length ? events[0].received_at : null
      };
    });
  }
}

function createClamavRouter(express, options = {}) {
  const env = options.env || process.env;
  const log = options.log || console;
  const now = options.now || (() => Date.now());
  const store = new EventStore(options.stateDir, {
    maxEventsPerDevice: intEnv(env, 'CLAMAV_MAX_EVENTS_PER_DEVICE', 10000),
    retentionDays: intEnv(env, 'CLAMAV_RETENTION_DAYS', 90),
    maxDevices: intEnv(env, 'CLAMAV_MAX_DEVICES', 1000),
    now
  });
  const router = express.Router();

  // Keys are read per request (like the other gated endpoints) and are never
  // written to the log; only the outcome is.  A gate accepts any configured
  // key from its list, so a gate can accept more than one variable if ever needed.
  function gate(envNames, headerName, label) {
    return (req, res, next) => {
      const expected = envNames.map((name) => env[name]).filter(Boolean);
      if (expected.length === 0) {
        log.error(`[clamav] ${envNames.join('/')} not configured - refusing all ${label} requests (fail closed)`);
        return res.status(503).json({ status: 'error', message: 'clamav API not configured' });
      }
      const supplied = req.get(headerName);
      // Evaluate every candidate so timing does not reveal which one matched.
      const ok = expected.map((key) => keyMatches(key, supplied)).some(Boolean);
      if (!ok) {
        log.warn(`[clamav] ${label} request rejected: bad credential`);
        return res.status(401).json({ status: 'error', message: 'unauthorized' });
      }
      return next();
    };
  }
  // Ingest and read both reuse SSH_SIGN_API_KEY (no dedicated key, like /api/logs).  The
  // manufacturing IDEVID_ISSUE_API_KEY is deliberately NOT accepted here.  The
  // header name stays X-Clamav-Report-Key so the DUT reporter is unchanged.
  const ingestGate = gate(['SSH_SIGN_API_KEY'], 'X-Clamav-Report-Key', 'ingest');
  const readGate = gate(['SSH_SIGN_API_KEY'], 'X-Clamav-Read-Key', 'read');

  router.post('/', ingestGate, (req, res) => {
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({ status: 'error', message: 'JSON object body required' });
    }
    if (Buffer.byteLength(JSON.stringify(body)) > MAX_BODY_BYTES) {
      return res.status(413).json({ status: 'error', message: 'body too large' });
    }

    let deviceId;
    let events;
    if (Array.isArray(body.events)) {
      if (body.schema_version !== undefined && body.schema_version !== SCHEMA_VERSION) {
        return res.status(400).json({ status: 'error', message: 'unsupported schema_version' });
      }
      deviceId = body.device_id;
      events = body.events;
    } else if (body.event !== undefined || body.version === 1) {
      // Legacy single record as emitted by clamav-event-scanner.py today.
      deviceId = req.get('X-Device-Id');
      events = [body];
    } else {
      return res.status(400).json({ status: 'error', message: 'events array or single record required' });
    }
    if (typeof deviceId !== 'string' || !DEVICE_ID_RE.test(deviceId)) {
      return res.status(400).json({ status: 'error', message: 'invalid or missing device_id' });
    }
    if (events.length === 0) {
      return res.status(400).json({ status: 'error', message: 'no events' });
    }
    if (events.length > MAX_EVENTS_PER_REQUEST) {
      return res.status(413).json({ status: 'error', message: `at most ${MAX_EVENTS_PER_REQUEST} events per request` });
    }

    const valid = [];
    const rejected = [];
    const nowMs = now();
    events.forEach((raw, index) => {
      const result = normalizeEvent(raw, deviceId, nowMs);
      if (result.event) valid.push(result.event);
      else rejected.push({ index, event_id: raw && typeof raw.event_id === 'string' ? raw.event_id.slice(0, 128) : undefined, reason: result.error });
    });
    if (valid.length === 0) {
      return res.status(400).json({ status: 'error', message: 'no valid events', rejected });
    }

    try {
      const { accepted, duplicates } = store.append(deviceId, valid);
      log.log(`[clamav] device=${deviceId} accepted=${accepted} duplicates=${duplicates} rejected=${rejected.length}`);
      return res.json({ status: 'ok', schema_version: SCHEMA_VERSION, accepted, duplicates, rejected });
    } catch (err) {
      if (err.code === 'too_many_devices') {
        return res.status(429).json({ status: 'error', message: 'device limit reached' });
      }
      log.error(`[clamav] store failure for device=${deviceId}: ${err.message}`);
      return res.status(500).json({ status: 'error', message: 'storage failure' });
    }
  });

  router.get('/devices', readGate, (req, res) => {
    res.json({ status: 'ok', devices: store.summary() });
  });

  router.get('/devices/:deviceId/events', readGate, (req, res) => {
    const { deviceId } = req.params;
    if (!DEVICE_ID_RE.test(deviceId)) {
      return res.status(400).json({ status: 'error', message: 'invalid device_id' });
    }
    const limit = req.query.limit === undefined ? 100 : parseInt(req.query.limit, 10);
    if (!Number.isInteger(limit) || limit < 1 || limit > 500) {
      return res.status(400).json({ status: 'error', message: 'limit must be 1..500' });
    }
    let since;
    if (req.query.since !== undefined) {
      since = Date.parse(req.query.since);
      if (!Number.isFinite(since)) return res.status(400).json({ status: 'error', message: 'invalid since' });
    }
    const type = req.query.event;
    if (type !== undefined && !EVENT_TYPES.has(type)) {
      return res.status(400).json({ status: 'error', message: 'unsupported event type' });
    }
    if (!store.known.has(deviceId)) return res.status(404).json({ status: 'error', message: 'unknown device' });
    return res.json({ status: 'ok', device_id: deviceId, events: store.list(deviceId, { since, event: type, limit }) });
  });

  return router;
}

module.exports = { createClamavRouter, normalizeEvent, EventStore, SCHEMA_VERSION };
