const tls = require('tls');
const https = require('node:https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const util = require('util');

// Loads /app/.env (mounted read-only from /etc/app/certs/.env on the host,
// see docker-compose.yml) into process.env before anything else reads it.
// override: true is required — docker-compose.yml's `${VAR:-}` substitution
// pre-sets every one of these keys in process.env (as "" when unset in
// Portainer), and dotenv's default behavior is to never touch a key that
// already exists, even if its value is an empty string. Without override,
// every var with an empty compose default silently never gets the .env
// file's value. Silently a no-op if the file doesn't exist.
const dotenvResult = require('dotenv').config({ path: '/app/.env', override: true });

// File logging — mirrors every console.log/warn/error line into
// /app/logs/mqtt-server.log (in addition to stdout, unchanged for
// `docker logs`/Portainer's own log viewer). Requested explicitly without
// an auth-gated read endpoint (see GET /api/logs below) — no filtering of
// sensitive content is applied.
const LOG_DIR = path.join(__dirname, 'logs');
const LOG_FILE = path.join(LOG_DIR, 'mqtt-server.log');
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
const logStream = fs.createWriteStream(LOG_FILE, { flags: 'a' });

function wrapConsole(method) {
  const original = console[method].bind(console);
  return (...args) => {
    original(...args);
    // JSON.stringify(Error) yields "{}" — its message/stack aren't own
    // enumerable properties — which was silently dropping every error
    // detail written to the file. util.inspect handles Error, circular
    // refs, undefined, etc. correctly.
    const line = args.map((a) => {
      if (typeof a === 'string') return a;
      if (a instanceof Error) return a.stack || a.message;
      return util.inspect(a, { depth: 5 });
    }).join(' ');
    logStream.write(`[${new Date().toISOString()}] [${method}] ${line}\n`);
  };
}
console.log = wrapConsole('log');
console.warn = wrapConsole('warn');
console.error = wrapConsole('error');

// Any env var or header name that looks like it carries a credential.
// Applied to both the startup dotenv dump and every request's headers below
// — both were leaking live Vault tokens/API keys in plaintext via GET
// /api/logs until this fix (2026-07-31 incident: confirmed external
// scanning activity against this server before the leak was caught).
const SENSITIVE_NAME_PATTERN = /token|key|secret|password|pin|authorization|cookie/i;
function redactSensitive(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj || {})) {
    out[k] = SENSITIVE_NAME_PATTERN.test(k) ? (v ? '<redacted>' : '<empty>') : v;
  }
  return out;
}

// Log the dotenv.config() result (error, or parsed key/value map with any
// credential-shaped value redacted).
if (dotenvResult.error) {
  console.error('[dotenv] failed to load /app/.env:', dotenvResult.error.message);
} else {
  console.log('[dotenv] loaded /app/.env, parsed (secrets redacted):', redactSensitive(dotenvResult.parsed));
}

// Catch-all crash/rejection logging — without this, an uncaught exception
// or unhandled rejection prints to stderr only and is lost the moment the
// container restarts, before it can be inspected via GET /api/logs.
process.on('uncaughtException', (err) => {
  console.error('[uncaughtException]', err && err.stack ? err.stack : err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[unhandledRejection]', reason && reason.stack ? reason.stack : reason);
});

// 2. 變更：必須使用 async 函數來包裝初始化邏輯
async function startMqttServer() {
  try {
    // 1. 變更：使用動態 import() 載入 ESM 模組
    const { Aedes } = await import('aedes');
    const express = (await import('express')).default;

    // 3. 變更：改用 await Aedes.createBroker() 進行非同步初始化
    const aedes = await Aedes.createBroker();

    // Diagnostic only - Node's EventEmitter silently drops events with no
    // listener (unless it's the special 'error' event), so without these,
    // any protocol-level rejection Aedes makes before assigning a client id
    // (and thus before the 'client' event below) is invisible - it looks
    // identical to "nothing happened" in the logs.
    aedes.on('connectionError', (client, err) => {
      console.error(`[aedes connectionError] client=${client && client.id}:`, err);
    });
    aedes.on('clientError', (client, err) => {
      console.error(`[aedes clientError] client=${client && client.id}:`, err);
    });
    aedes.on('keepaliveTimeout', (client) => {
      console.warn(`[aedes keepaliveTimeout] client=${client && client.id}`);
    });
    aedes.on('connackSent', (packet, client) => {
      console.log(`[aedes connackSent] client=${client && client.id}:`, packet);
    });

    // Trust anchors for client certs on this mTLS broker: the existing
    // operational (LDevID) CA, plus the dedicated IDevID CA (see
    // docs/kms/provision-server-commission-endpoint-plan.md in uct-iq9075) —
    // kept as a separate file/CA so IDevID commissioning and operational MQTT
    // traffic can both terminate here without merging trust domains.
    const brokerCaCerts = [
      fs.readFileSync('./certs/intermediate-ca.crt'),
      fs.readFileSync('./certs/root-ca.crt')
    ];
    if (fs.existsSync('./certs/idevid-ca.crt')) {
      brokerCaCerts.push(fs.readFileSync('./certs/idevid-ca.crt'));
    } else {
      console.warn('[commission] ./certs/idevid-ca.crt not found — IDevID commissioning over MQTT will fail mTLS verification until it is provisioned (fetch via `vault read -field=certificate pki_idevid/cert/ca`)');
    }

    const options = {
  	key: fs.readFileSync('./certs/privkey.pem'),
	cert: fs.readFileSync('./certs/fullchain.pem'),
	ca: brokerCaCerts,
      // mTLS 核心設定
      requestCert: true,
      rejectUnauthorized: true
    };

    const server = tls.createServer(options, aedes.handle);
    const PORT = 8443;

    // THE actual missing piece: with rejectUnauthorized:true, Node does its
    // own server-side client-cert authorization check immediately after the
    // raw TLS handshake completes, separate from (and in addition to) the
    // cryptographic handshake itself. A client can complete the crypto
    // handshake successfully (SSL_connect() returns success) and still get
    // silently disconnected right after if this check fails - and unlike
    // aedes's own connectionError/clientError events, this happens at the
    // Node tls layer BEFORE aedes.handle is ever invoked, so none of the
    // aedes-level diagnostics added above see it either. This is the only
    // place that failure is ever actually reported.
    server.on('tlsClientError', (err, tlsSocket) => {
      console.error(
        `[tlsClientError] ${tlsSocket.remoteAddress}:${tlsSocket.remotePort} - ${err.message}`,
        err
      );
    });
    server.on('secureConnection', (tlsSocket) => {
      console.log(
        `[secureConnection] ${tlsSocket.remoteAddress}:${tlsSocket.remotePort} ` +
        `authorized=${tlsSocket.authorized} authorizationError=${tlsSocket.authorizationError}`
      );
    });

    // Track connected MQTT clients
    const connectedClients = new Map();

    // Pending wait-for-result requests (currently /api/ssh-principals-refresh)
    // awaiting a correlated kms/<deviceId>/result
    // message. Keyed by `${deviceId}:${requestId}`, value
    // { resolve, timer }. Shared across every such endpoint — the
    // correlation logic in the aedes.on('publish', ...) hook below only
    // matches on deviceId/request_id, not which endpoint created the
    // pending entry, so this is safe to reuse as more endpoints adopt the
    // same wait-for-result pattern.
    const pendingDeviceRequests = new Map();

    // AVC denial report store — Map<deviceId, MergedState>
    // MergedState: { device_id, first/last_upload_timestamp, last_received_at, upload_count,
    //   total_raw_denials, firmware metadata fields, denialMap: Map<key, denialEntry> }
    const avcStore = new Map();
    const MERGED_FILENAME = 'avc-denials.json';

    // Persistent storage directory for AVC reports (survives server restarts)
    const AVC_DIR = path.join(__dirname, 'avc-reports');
    if (!fs.existsSync(AVC_DIR)) fs.mkdirSync(AVC_DIR, { recursive: true });

    // Dedup key — mirrors selinux-avc-reporter.py: (scontext, tcontext, tclass, sorted_perms)
    function denialKey(d) {
      const perms = Array.isArray(d.perms) ? [...d.perms].sort().join(',') : String(d.perms || '');
      return `${d.scontext}|${d.tcontext}|${d.tclass}|${perms}`;
    }

    // Lazy-load merged state from avc-denials.json on first POST for a device
    function loadMergedState(deviceId) {
      const filePath = path.join(AVC_DIR, deviceId, MERGED_FILENAME);
      if (!fs.existsSync(filePath)) return null;
      try {
        const disk = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        const denialMap = new Map();
        (disk.denials || []).forEach(d => denialMap.set(denialKey(d), d));
        return { ...disk, denialMap };
      } catch (e) {
        console.error(`[AVC] Failed to load merged state for ${deviceId}:`, e);
        return null;
      }
    }

    // Write merged state atomically (tmp → rename) to avc-denials.json
    function saveMergedState(merged) {
      const deviceDir = path.join(AVC_DIR, merged.device_id);
      if (!fs.existsSync(deviceDir)) fs.mkdirSync(deviceDir, { recursive: true });
      const denials = Array.from(merged.denialMap.values())
        .sort((a, b) => (b.occurrence_count || 0) - (a.occurrence_count || 0));
      const diskState = {
        device_id:                 merged.device_id,
        first_upload_timestamp:    merged.first_upload_timestamp,
        last_upload_timestamp:     merged.last_upload_timestamp,
        last_received_at:          merged.last_received_at,
        upload_count:              merged.upload_count,
        total_raw_denials:         merged.total_raw_denials,
        total_unique_denial_types: denials.length,
        firmware_version:          merged.firmware_version,
        fw_build:                  merged.fw_build,
        selinux_policy_version:    merged.selinux_policy_version,
        wnc_local_version:         merged.wnc_local_version,
        wnc_local_te_lines:        merged.wnc_local_te_lines,
        wnc_local_fc_lines:        merged.wnc_local_fc_lines,
        selinux_mode:              merged.selinux_mode,
        denials
      };
      const finalPath = path.join(deviceDir, MERGED_FILENAME);
      const tmpPath   = finalPath + '.tmp';
      fs.writeFileSync(tmpPath, JSON.stringify(diskState, null, 2));
      fs.renameSync(tmpPath, finalPath);
      return diskState;
    }

    server.listen(PORT, function () {
      console.log(`MQTT mTLS 伺服器已啟動，正在監聽連接埠 ${PORT}`);
    });

    aedes.on('client', function (client) {
	const clientInfo = {
		id: client.id,
		connected_at: new Date().toISOString(),
		tls: false,
		cert: null
	};

	if (client.conn && typeof client.conn.getPeerCertificate === 'function') {

		// 傳入 true 參數可以取得包含完整憑證鏈的詳細資訊 (可選)
		const cert = client.conn.getPeerCertificate();

		// 檢查憑證是否為空
		if (cert && Object.keys(cert).length > 0) {
			console.log(`[mTLS 驗證成功] 客戶端 ID: ${client.id}`);

      // 1. 取得 Node.js 原始的連續大寫序號字串
      const rawSerial = cert.serialNumber;

      // 2. 轉換為小寫，並使用正規表達式每兩個字元插入一個冒號
      let formattedSerial = '';
      if (rawSerial) {
        formattedSerial = rawSerial
          .toLowerCase()
          .match(/.{1,2}/g)
          .join(':');
      }

      // 3. 輸出與 DUT 完全相同的格式
      console.log(`  - 憑證序號 (Serial): ${formattedSerial}`);

			// 記錄憑證的關鍵欄位
			console.log(`  - 設備/通用名稱 (CN):`, cert.subject.CN);
			console.log(`  - 頒發機構 (Issuer CN):`, cert.issuer.CN);
			console.log(`  - 憑證指紋 (Fingerprint):`, cert.fingerprint);
			console.log(`  - 有效期限至:`, cert.valid_to);

			if (cert.subjectaltname) {
				console.log(`  - 替代名稱 (SAN):`, cert.subjectaltname);
			}

			clientInfo.tls = true;
			clientInfo.cert = {
				cn: cert.subject.CN,
				issuer: cert.issuer.CN,
				serial: formattedSerial,
				fingerprint: cert.fingerprint,
				valid_to: cert.valid_to,
				san: cert.subjectaltname || ''
			};
		} else {
			console.warn(`[警告] 客戶端 ${client.id} 未提供憑證。`);
		}
	}
	else {
		console.log(`客戶端已連線: ${client.id} (非 TLS 連線)`);
	}

	connectedClients.set(client.id, clientInfo);
    });

    aedes.on('clientDisconnect', function (client) {
      console.log(`客戶端已斷線: ${client ? client.id : client}`);
      if (client) {
        connectedClients.delete(client.id);
      }
    });

    aedes.on('publish', function (packet, client) {
      if (client) {
        console.log(`收到來自 ${client.id} 的訊息，主題: ${packet.topic}`);
      }

      // Correlate DUT result messages back to a pending wait-for-result
      // request (/api/ssh-principals-refresh, ...).
      // kms-mqtt-trigger publishes to kms/<deviceId>/result with whatever
      // JSON kms-cert-manager returned, including the request_id we sent
      // it (see kms-cert-manager.py's _handle_client echo).
      const resultMatch = /^kms\/([^/]+)\/result$/.exec(packet.topic);
      if (resultMatch) {
        const deviceId = resultMatch[1];
        let payload;
        try {
          payload = JSON.parse(packet.payload.toString());
        } catch (e) {
          // A pending /api/ssh-principals-refresh request would otherwise
          // just time out with no clue why - log it.
          console.warn(`[result] unparseable payload on kms/${deviceId}/result:`, packet.payload.toString());
          return;
        }
        if (payload && payload.request_id) {
          const key = `${deviceId}:${payload.request_id}`;
          const pending = pendingDeviceRequests.get(key);
          if (pending) {
            clearTimeout(pending.timer);
            pendingDeviceRequests.delete(key);
            pending.resolve(payload);
          }
        }
      }

      // Device-commission (Endpoint A): a device with a freshly-enrolled IDevID
      // cert requests its real Vault AppRole role_id/secret_id over this same
      // mTLS broker, rather than a separate HTTP endpoint - see
      // docs/kms/provision-server-commission-endpoint-plan.md in uct-iq9075.
      const commissionMatch = /^commission\/([^/]+)\/request$/.exec(packet.topic);
      if (commissionMatch && client) {
        const topicDeviceId = commissionMatch[1];
        let payload = {};
        try {
          payload = JSON.parse(packet.payload.toString());
        } catch (e) {
          // tolerate empty/non-JSON payload - identity comes from the cert either way
        }
        handleCommissionRequest(client, topicDeviceId, payload);
      }
    });

    server.on('error', function (err) {
      console.error('伺服器發生錯誤:', err);
    });

    //The http part
    const app = express();
    app.use(express.json({ limit: '10mb' }));  // AVC reports can be large

    // Full HTTP access logging — every request/response, headers and body
    // included. Header values are redacted via redactSensitive() (any
    // X-*-Key/Authorization/Cookie-shaped name) so a signing/issue request's
    // own auth header never ends up in the log or GET /api/logs.
    app.use((req, res, next) => {
      const start = Date.now();
      console.log(`[http] --> ${req.method} ${req.originalUrl} headers=${JSON.stringify(redactSensitive(req.headers))} body=${JSON.stringify(req.body)}`);
      res.on('finish', () => {
        console.log(`[http] <-- ${req.method} ${req.originalUrl} status=${res.statusCode} (${Date.now() - start}ms)`);
      });
      next();
    });

    // Version endpoint — update version in package.json on every code change
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
    const startedAt = new Date().toISOString();
    app.get('/version', (req, res) => {
      res.json({
        version: pkg.version,
        started: startedAt
      });
    });

    // MQTT client connection status endpoint
    app.get('/api/clients', (req, res) => {
      const clients = Array.from(connectedClients.values());
      res.json({
        total: clients.length,
        clients: clients
      });
    });

    // 建立觸發輪替的 HTTP POST 路由
    app.post('/api/rotate/:deviceId', (req, res) => {
      const deviceId = req.params.deviceId;
      const requestPayload = req.body; // 取得 HTTP 傳入的 JSON

      // 檢查 Payload 格式是否正確
      if (!requestPayload || !requestPayload.service) {
        return res.status(400).json({ error: '無效的請求：缺少必要的 JSON 欄位' });
      }

      // 構建要發布的 MQTT 封包
      const packet = {
        cmd: 'publish',
        qos: 1, // 使用 QoS 1 確保指令到達
        topic: `kms/${deviceId}/rotate`,
        payload: Buffer.from(JSON.stringify(requestPayload)),
        retain: false
      };

      // 透過 Aedes 內部 API 直接發布訊息
      aedes.publish(packet, function (err) {
        if (err) {
          console.error(`[HTTP 橋接] 觸發設備 ${deviceId} 輪替失敗:`, err);
          return res.status(500).json({ status: 'error', message: '內部 MQTT 轉發失敗' });
        }
        
        console.log(`[HTTP 橋接] 成功將輪替指令轉發至主題: ${packet.topic}`);
        res.status(200).json({ 
          status: 'ok', 
          message: `已觸發 ${deviceId} 的憑證輪替`,
          delivered_payload: requestPayload
        });
      });
    });

    // Docker pull endpoint — publishes to kms/<deviceId>/pull
    app.post('/api/pull/:deviceId', (req, res) => {
      const deviceId = req.params.deviceId;
      const requestPayload = req.body;

      if (!requestPayload || !requestPayload.image || !requestPayload.digest || !requestPayload.vault_path) {
        return res.status(400).json({ error: 'Missing required fields: image, digest, vault_path' });
      }

      const packet = {
        cmd: 'publish',
        qos: 1,
        topic: `kms/${deviceId}/pull`,
        payload: Buffer.from(JSON.stringify(requestPayload)),
        retain: false
      };

      aedes.publish(packet, function (err) {
        if (err) {
          console.error(`[HTTP Bridge] Failed to publish pull command for ${deviceId}:`, err);
          return res.status(500).json({ status: 'error', message: 'MQTT publish failed' });
        }

        console.log(`[HTTP Bridge] Pull command published to topic: ${packet.topic}`);
        res.status(200).json({
          status: 'ok',
          message: `Pull command sent to ${deviceId}`,
          delivered_payload: requestPayload
        });
      });
    });

    // KEK provision endpoint — publishes to kms/<deviceId>/provision
    app.post('/api/provision/:deviceId', (req, res) => {
      const deviceId = req.params.deviceId;
      const requestPayload = req.body;

      if (!requestPayload || !requestPayload.key_name || !requestPayload.key_data) {
        return res.status(400).json({ error: 'Missing required fields: key_name, key_data' });
      }

      const packet = {
        cmd: 'publish',
        qos: 1,
        topic: `kms/${deviceId}/provision`,
        payload: Buffer.from(JSON.stringify(requestPayload)),
        retain: false
      };

      aedes.publish(packet, function (err) {
        if (err) {
          console.error(`[HTTP Bridge] Failed to publish provision command for ${deviceId}:`, err);
          return res.status(500).json({ status: 'error', message: 'MQTT publish failed' });
        }

        console.log(`[HTTP Bridge] Provision command published to topic: ${packet.topic}`);
        res.status(200).json({
          status: 'ok',
          message: `KEK provision sent to ${deviceId}`,
          delivered_payload: requestPayload
        });
      });
    });

    // ── SSH Certificate Authority: user login cert signing ─────────────────
    // Signs SSH login certificates directly against Vault's SSH secrets
    // engine, using this server's OWN dedicated Vault credential — NOT any
    // device's TPM-provisioned AppRole. The DUT is never involved in this
    // request path at all; it only ever trusts the resulting CA public key
    // (fetched separately by kms-cert-manager's own read-only Vault call).
    // See docs/kms/ssh-ca-user-and-host-certs-plan.md in the uct-iq9075 repo.
    //
    // Required env vars (set via Portainer stack config — never commit
    // real values to this repo):
    //   VAULT_ADDR         e.g. https://vault.csyang.org
    //   VAULT_TOKEN        token scoped to ssh/sign/user-login on this role
    //                      (also used by vaultSshHostIssue below for
    //                      cert_type 'host' against the same mount/role) —
    //                      must NOT be shared with any device's own AppRole
    //   VAULT_SSH_MOUNT    defaults to "ssh"
    //   VAULT_SSH_ROLE     defaults to "user-login"
    //   SSH_SIGN_API_KEY   shared secret required in the X-SSH-Sign-Key
    //                      header. If unset, this endpoint refuses every
    //                      request (fails closed) rather than silently
    //                      allowing unauthenticated issuance of human login
    //                      credentials — that blast radius is categorically
    //                      different from the other endpoints above.
    function vaultSshSign(publicKey, principal, engineerId, ttl) {
      return new Promise((resolve, reject) => {
        const vaultAddr = process.env.VAULT_ADDR;
        const vaultToken = process.env.VAULT_TOKEN;
        if (!vaultAddr || !vaultToken) {
          return reject(new Error('VAULT_ADDR/VAULT_TOKEN not configured on this server'));
        }
        const mount = process.env.VAULT_SSH_MOUNT || 'ssh';
        const role = process.env.VAULT_SSH_ROLE || 'user-login';

        // principal = which local account the cert may log in as (authorization),
        // already device-scoped ("<role>@<device_id>") by the caller below so
        // this cert cannot be reused to log into a different device.
        // engineerId = the actual requesting human, wired through as Vault's
        // key_id — deliberately distinct fields. Conflating the two would
        // silently defeat the IEC 62443 SR 6.1 non-repudiation requirement
        // this endpoint exists to satisfy (sshd logs the Key ID on every
        // successful cert login, so this is what makes "who logged in as
        // the shared account, and when" traceable).
        const body = JSON.stringify({
          public_key: publicKey,
          valid_principals: principal,
          key_id: engineerId,
          cert_type: 'user',
          // Without this, Vault issues a cert with an empty Extensions
          // list, and OpenSSH denies pty/forwarding/etc. by default for
          // any capability not explicitly granted via a cert extension —
          // confirmed live 2026-07-31: "Allocating a pty not permitted for
          // this connection" on every login, even though authentication
          // itself succeeded. Only requesting what an interactive admin
          // session actually needs (least privilege) — not forwarding,
          // agent-forwarding, or X11. Empty string value matches Vault's
          // SSH secrets engine convention for boolean-style extensions.
          extensions: {
            'permit-pty': ''
          },
          ...(ttl ? { ttl } : {})
        });

        const url = new URL(`/v1/${mount}/sign/${role}`, vaultAddr);
        const vaultReq = https.request(url, {
          method: 'PUT',
          headers: {
            'X-Vault-Token': vaultToken,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body)
          }
        }, (vaultRes) => {
          let data = '';
          vaultRes.on('data', (chunk) => { data += chunk; });
          vaultRes.on('end', () => {
            let parsed;
            try {
              parsed = JSON.parse(data);
            } catch (e) {
              return reject(new Error(`Vault returned non-JSON response (HTTP ${vaultRes.statusCode}): ${data}`));
            }
            if (vaultRes.statusCode !== 200) {
              const errMsg = (parsed.errors || []).join('; ') || `HTTP ${vaultRes.statusCode}`;
              return reject(new Error(`Vault SSH sign failed: ${errMsg}`));
            }
            if (!parsed.data || !parsed.data.signed_key) {
              return reject(new Error(`Unexpected Vault response: ${data}`));
            }
            resolve(parsed.data.signed_key);
          });
        });
        vaultReq.on('error', reject);
        vaultReq.write(body);
        vaultReq.end();
      });
    }

    // Operator-driven SSH host-identity issuance (mirrors vaultIdevidSign's
    // shape, and the same Vault "ssh" mount as vaultSshSign above, but the
    // "host-cert" role instead of "user-login"). Replaces the old
    // device-initiated flow (device signed its OWN host key via its own
    // AppRole, triggered by the now-removed /api/ssh-host-renew) — the host
    // keypair/cert are now production-line-provisioned, fixed for the
    // device's lifetime, the same convention as IDevID. See
    // docs/kms/ssh-ca-user-and-host-certs-plan.md in uct-iq9075.
    //
    // Unlike vaultIdevidSign's CSR, Vault's SSH secrets engine signs a raw
    // OpenSSH public key directly — there is no CSR concept for SSH certs.
    //
    // Required env vars (Portainer stack config — never commit real values):
    //   VAULT_ADDR                  same Vault server as vaultSshSign
    //   VAULT_SSH_HOST_CERT_TOKEN   DEDICATED token, distinct from
    //                                VAULT_TOKEN (2026-07-31: narrower-scoped
    //                                on purpose — bound only to
    //                                ssh-host-cert-policy, granting
    //                                create/update on ssh/sign/host-cert and
    //                                read on ssh/config/ca; VAULT_TOKEN is
    //                                not touched by either function below)
    //   VAULT_SSH_MOUNT              same mount as vaultSshSign above
    //                                (defaults "ssh") — host and user certs
    //                                share one mount, different roles/tokens
    //   VAULT_SSH_HOST_ROLE          defaults to "host-cert" — a DEDICATED
    //                                role, distinct from VAULT_SSH_ROLE's
    //                                "user-login" (confirmed 2026-07-31:
    //                                Vault rejects cert_type 'host' against
    //                                the user-login role — "cert_type
    //                                'host' is not allowed by role". The
    //                                real, already-provisioned "host-cert"
    //                                role has allow_host_certificates=true,
    //                                allow_user_certificates=false,
    //                                allowed_domains=csyang.org,
    //                                allow_subdomains=true)
    //   VAULT_SSH_HOST_TTL           defaults to "8760h" (1 year) — matches
    //                                the "host-cert" role's own max_ttl
    //                                (confirmed 2026-07-31: Vault does NOT
    //                                silently cap an over-limit request —
    //                                it hard-rejects with "ttl is larger
    //                                than maximum allowed 31536000". A
    //                                longer-lived cert needs the role's
    //                                max_ttl raised first, not just this
    //                                env var.
    function vaultSshHostIssue(publicKey, deviceId) {
      return new Promise((resolve, reject) => {
        const vaultAddr = process.env.VAULT_ADDR;
        const vaultToken = process.env.VAULT_SSH_HOST_CERT_TOKEN;
        if (!vaultAddr || !vaultToken) {
          return reject(new Error('VAULT_ADDR/VAULT_SSH_HOST_CERT_TOKEN not configured on this server'));
        }
        const mount = process.env.VAULT_SSH_MOUNT || 'ssh';
        const role = process.env.VAULT_SSH_HOST_ROLE || 'host-cert';

        const body = JSON.stringify({
          public_key: publicKey,
          cert_type: 'host',
          // Matches the naming convention device-commission.py's IDevID CN
          // already uses ("<device_id>.provision.csyang.org") so both
          // identities are recognizable as belonging to the same device.
          valid_principals: `${deviceId}.provision.csyang.org`,
          ttl: process.env.VAULT_SSH_HOST_TTL || '8760h'
        });

        const url = new URL(`/v1/${mount}/sign/${role}`, vaultAddr);
        const vaultReq = https.request(url, {
          method: 'PUT',
          headers: {
            'X-Vault-Token': vaultToken,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body)
          }
        }, (vaultRes) => {
          let data = '';
          vaultRes.on('data', (chunk) => { data += chunk; });
          vaultRes.on('end', () => {
            let parsed;
            try {
              parsed = JSON.parse(data);
            } catch (e) {
              return reject(new Error(`Vault returned non-JSON response (HTTP ${vaultRes.statusCode}): ${data}`));
            }
            if (vaultRes.statusCode !== 200) {
              const errMsg = (parsed.errors || []).join('; ') || `HTTP ${vaultRes.statusCode}`;
              return reject(new Error(`Vault SSH host-cert sign failed: ${errMsg}`));
            }
            if (!parsed.data || !parsed.data.signed_key) {
              return reject(new Error(`Unexpected Vault response: ${data}`));
            }
            resolve({
              certificate: parsed.data.signed_key,
              serial_number: parsed.data.serial_number
            });
          });
        });
        vaultReq.on('error', reject);
        vaultReq.write(body);
        vaultReq.end();
      });
    }

    // Read-only fetch of the SSH CA's public key (Vault "ssh" mount's
    // config/ca) — used by the operator to install
    // /var/persist/ssh-trust/client/ca.pub at production-line time. No
    // signing capability is exposed here, matching the removed on-device
    // fetch_ca_public_key()'s "read-only, no signing capability" framing.
    // Uses the broader VAULT_TOKEN (same as vaultSshSign), NOT the dedicated
    // VAULT_SSH_HOST_CERT_TOKEN — that token is scoped to host-cert
    // ISSUANCE only (2026-07-31, explicit operator decision); VAULT_TOKEN's
    // policy was separately granted read on ssh/config/ca for this
    // function. See docs/kms/ssh-ca-user-and-host-certs-plan.md in
    // uct-iq9075.
    function vaultSshCaPubkey() {
      return new Promise((resolve, reject) => {
        const vaultAddr = process.env.VAULT_ADDR;
        const vaultToken = process.env.VAULT_TOKEN;
        if (!vaultAddr || !vaultToken) {
          return reject(new Error('VAULT_ADDR/VAULT_TOKEN not configured on this server'));
        }
        const mount = process.env.VAULT_SSH_MOUNT || 'ssh';
        const url = new URL(`/v1/${mount}/config/ca`, vaultAddr);
        const vaultReq = https.request(url, {
          method: 'GET',
          headers: { 'X-Vault-Token': vaultToken }
        }, (vaultRes) => {
          let data = '';
          vaultRes.on('data', (chunk) => { data += chunk; });
          vaultRes.on('end', () => {
            let parsed;
            try {
              parsed = JSON.parse(data);
            } catch (e) {
              return reject(new Error(`Vault returned non-JSON response (HTTP ${vaultRes.statusCode}): ${data}`));
            }
            if (vaultRes.statusCode !== 200) {
              const errMsg = (parsed.errors || []).join('; ') || `HTTP ${vaultRes.statusCode}`;
              return reject(new Error(`Vault CA pubkey fetch failed: ${errMsg}`));
            }
            if (!parsed.data || !parsed.data.public_key) {
              return reject(new Error(`Unexpected Vault response: ${data}`));
            }
            resolve(parsed.data.public_key);
          });
        });
        vaultReq.on('error', reject);
        vaultReq.end();
      });
    }

    // Local accounts a cert may claim. Vault's user-login role allows any
    // username (allowed_users=*) because device-scoped principals
    // (admin@<device_id>) can't be enumerated per-device in Vault without
    // manual admin work for every new device — so this allowlist is now
    // the real enforcement point for "which role names are legitimate",
    // not Vault. Keep this narrow and update deliberately, not blanket.
    const ALLOWED_PRINCIPAL_ROLES = ['admin'];
    const DEVICE_ID_PATTERN = /^kms-[a-zA-Z0-9]+$/;

    // ────────────────────────────────────────────────────────────────────────
    // Device-commission (Endpoint A): mints a real Vault AppRole role_id/
    // secret_id for a device presenting its IDevID cert over this mTLS broker.
    // See docs/kms/provision-server-commission-endpoint-plan.md in uct-iq9075.
    // ────────────────────────────────────────────────────────────────────────

    // The IDevID cert's CN/SAN is "<device_id>.provision.csyang.org" - a naming
    // convention baked in at IDevID issuance time (Endpoint B), not a resolvable
    // hostname. Parse the device_id back out for cross-checking.
    const COMMISSION_CN_PATTERN = /^([a-zA-Z0-9-]+)\.provision\.csyang\.org$/;

    function extractDeviceIdFromCommissionCN(cn) {
      const m = COMMISSION_CN_PATTERN.exec(cn || '');
      return m ? m[1] : null;
    }

    // Minimal raw-HTTP Vault client (mirrors vaultSshSign's shape below) — GET
    // the shared AppRole's role_id, then mint a fresh secret_id scoped (via
    // metadata, for audit traceability only — Vault has no native per-device
    // scoping for this shared role) to this specific device_id.
    function vaultRequest(method, urlPath, body) {
      return new Promise((resolve, reject) => {
        const vaultAddr = process.env.VAULT_ADDR;
        if (!vaultAddr) {
          return reject(new Error('VAULT_ADDR not configured on this server'));
        }
        const bodyStr = body ? JSON.stringify(body) : undefined;
        const url = new URL(urlPath, vaultAddr);
        const headers = { 'X-Vault-Token': process.env.VAULT_COMMISSION_TOKEN || '' };
        if (bodyStr) {
          headers['Content-Type'] = 'application/json';
          headers['Content-Length'] = Buffer.byteLength(bodyStr);
        }
        const vaultReq = https.request(url, { method, headers }, (vaultRes) => {
          let data = '';
          vaultRes.on('data', (chunk) => { data += chunk; });
          vaultRes.on('end', () => {
            let parsed;
            try {
              parsed = JSON.parse(data);
            } catch (e) {
              return reject(new Error(`Vault returned non-JSON response (HTTP ${vaultRes.statusCode}): ${data}`));
            }
            if (vaultRes.statusCode !== 200) {
              const errMsg = (parsed.errors || []).join('; ') || `HTTP ${vaultRes.statusCode}`;
              return reject(new Error(`Vault request failed: ${errMsg}`));
            }
            resolve(parsed);
          });
        });
        vaultReq.on('error', reject);
        if (bodyStr) vaultReq.write(bodyStr);
        vaultReq.end();
      });
    }

    async function vaultCommission(deviceId) {
      if (!process.env.VAULT_COMMISSION_TOKEN) {
        throw new Error('VAULT_COMMISSION_TOKEN not configured on this server');
      }
      const role = process.env.VAULT_APPROLE_ROLE || 'my-app-role';

      const roleIdResp = await vaultRequest('GET', `/v1/auth/approle/role/${role}/role-id`);
      if (!roleIdResp.data || !roleIdResp.data.role_id) {
        throw new Error(`Unexpected Vault role-id response: ${JSON.stringify(roleIdResp)}`);
      }

      const secretIdResp = await vaultRequest('POST', `/v1/auth/approle/role/${role}/secret-id`, {
        metadata: JSON.stringify({
          commissioned_device_id: deviceId,
          commissioned_at: new Date().toISOString()
        })
      });
      if (!secretIdResp.data || !secretIdResp.data.secret_id) {
        throw new Error(`Unexpected Vault secret-id response: ${JSON.stringify(secretIdResp)}`);
      }

      return { role_id: roleIdResp.data.role_id, secret_id: secretIdResp.data.secret_id };
    }

    function publishCommissionResult(deviceId, payload) {
      aedes.publish({
        topic: `commission/${deviceId}/result`,
        payload: JSON.stringify(payload),
        qos: 1,
        retain: false
      }, (err) => {
        if (err) console.error(`[commission] failed to publish result for ${deviceId}:`, err);
      });
    }

    async function handleCommissionRequest(client, topicDeviceId, payload) {
      const clientInfo = connectedClients.get(client.id);
      const certCn = clientInfo && clientInfo.cert ? clientInfo.cert.cn : null;
      const certDeviceId = extractDeviceIdFromCommissionCN(certCn);

      if (!clientInfo || !clientInfo.tls || !certDeviceId) {
        console.warn(`[commission] rejected: client ${client.id} has no verified IDevID cert`);
        return publishCommissionResult(topicDeviceId, { status: 'error', message: 'no verified IDevID client certificate' });
      }

      // The broker's `ca:` list trusts BOTH the operational CA and the
      // dedicated IDevID CA (see brokerCaCerts above) — a client cert passes
      // the TLS handshake if it chains to *either* one; TLS itself doesn't
      // tell you which. A cert's CN matching the <device_id>.commission.
      // csyang.org pattern is not proof it was actually issued by the IDevID
      // CA (an operational cert could coincidentally match the pattern, or
      // be deliberately crafted to). Only the issuer field distinguishes
      // them, so gate on it explicitly — fail closed if unconfigured, same
      // convention as the other secrets on this server.
      const expectedIssuer = process.env.IDEVID_CA_ISSUER_CN;
      if (!expectedIssuer) {
        console.error('[commission] IDEVID_CA_ISSUER_CN not configured — refusing all commission requests (fail closed)');
        return publishCommissionResult(topicDeviceId, { status: 'error', message: 'commission endpoint not configured' });
      }
      if (clientInfo.cert.issuer !== expectedIssuer) {
        console.warn(`[commission] rejected: client ${client.id} cert issued by "${clientInfo.cert.issuer}", expected IDevID CA "${expectedIssuer}"`);
        return publishCommissionResult(topicDeviceId, { status: 'error', message: 'certificate not issued by the IDevID CA' });
      }

      if (!DEVICE_ID_PATTERN.test(certDeviceId)) {
        console.warn(`[commission] rejected: cert device_id "${certDeviceId}" fails pattern check`);
        return publishCommissionResult(topicDeviceId, { status: 'error', message: 'invalid device_id in certificate' });
      }
      // Cross-check identity from three independent sources: the topic the
      // device published to, the verified IDevID cert's CN, and the JSON body
      // — reject on any mismatch rather than silently trusting the least
      // authenticated one (the body).
      if (certDeviceId !== topicDeviceId || (payload.device_id && payload.device_id !== certDeviceId)) {
        console.warn(`[commission] rejected: identity mismatch (cert=${certDeviceId} topic=${topicDeviceId} body=${payload.device_id})`);
        return publishCommissionResult(topicDeviceId, { status: 'error', message: 'device_id mismatch between cert, topic, and request body' });
      }

      try {
        const { role_id, secret_id } = await vaultCommission(certDeviceId);
        console.log(`[commission] issued role_id/secret_id for device_id=${certDeviceId}`);
        publishCommissionResult(certDeviceId, { role_id, secret_id });
      } catch (err) {
        console.error(`[commission] Vault mint failed for ${certDeviceId}:`, err);
        publishCommissionResult(certDeviceId, { status: 'error', message: err.message });
      }
    }

    // ────────────────────────────────────────────────────────────────────────
    // IDevID issuance (Endpoint B): a human OPERATOR calls this — plain HTTPS,
    // no mTLS — to sign a CSR (extracted from a DUT after tpm2tss-genkey runs
    // locally there) against a dedicated Vault PKI mount for IDevID, separate
    // from the operational pki/sign/gateway mount. Operator manually installs
    // the returned certificate back onto the DUT at idevid-cert.pem. See
    // docs/kms/provision-server-commission-endpoint-plan.md in uct-iq9075.
    // ────────────────────────────────────────────────────────────────────────

    async function vaultIdevidSign(csrPem, deviceId) {
      if (!process.env.VAULT_IDEVID_PKI_TOKEN) {
        throw new Error('VAULT_IDEVID_PKI_TOKEN not configured on this server');
      }
      const vaultAddr = process.env.VAULT_ADDR;
      if (!vaultAddr) {
        throw new Error('VAULT_ADDR not configured on this server');
      }
      const mount = process.env.VAULT_IDEVID_PKI_MOUNT || 'pki_idevid';
      const role = process.env.VAULT_IDEVID_PKI_ROLE || 'idevid';
      const commonName = `${deviceId}.provision.csyang.org`;

      const body = JSON.stringify({
        csr: csrPem,
        common_name: commonName,
        // IDevID is meant to last the device's lifetime — long TTL, not the
        // short-lived rotation cadence used for operational (LDevID) certs.
        ttl: process.env.VAULT_IDEVID_TTL || '87600h'
      });

      return new Promise((resolve, reject) => {
        const url = new URL(`/v1/${mount}/sign/${role}`, vaultAddr);
        const vaultReq = https.request(url, {
          method: 'POST',
          headers: {
            'X-Vault-Token': process.env.VAULT_IDEVID_PKI_TOKEN,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body)
          }
        }, (vaultRes) => {
          let data = '';
          vaultRes.on('data', (chunk) => { data += chunk; });
          vaultRes.on('end', () => {
            let parsed;
            try {
              parsed = JSON.parse(data);
            } catch (e) {
              return reject(new Error(`Vault returned non-JSON response (HTTP ${vaultRes.statusCode}): ${data}`));
            }
            if (vaultRes.statusCode !== 200) {
              const errMsg = (parsed.errors || []).join('; ') || `HTTP ${vaultRes.statusCode}`;
              return reject(new Error(`Vault IDevID sign failed: ${errMsg}`));
            }
            if (!parsed.data || !parsed.data.certificate) {
              return reject(new Error(`Unexpected Vault response: ${data}`));
            }
            resolve({
              certificate: parsed.data.certificate,
              ca_chain: parsed.data.ca_chain || [],
              serial_number: parsed.data.serial_number
            });
          });
        });
        vaultReq.on('error', reject);
        vaultReq.write(body);
        vaultReq.end();
      });
    }

    // Dedicated operator credential, separate from SSH_SIGN_API_KEY — this
    // issues a device's permanent hardware identity, a materially more
    // consequential action than a short-lived SSH login cert.
    app.post('/api/idevid-issue/:deviceId', (req, res) => {
      const apiKey = process.env.IDEVID_ISSUE_API_KEY;
      if (!apiKey) {
        console.error('[idevid-issue] IDEVID_ISSUE_API_KEY not configured — refusing all requests (fail closed)');
        return res.status(503).json({ status: 'error', message: 'idevid-issue endpoint not configured' });
      }
      if (req.get('X-IDevID-Issue-Key') !== apiKey) {
        return res.status(401).json({ status: 'error', message: 'unauthorized' });
      }

      const { deviceId } = req.params;
      const { csr } = req.body || {};
      if (!DEVICE_ID_PATTERN.test(deviceId)) {
        return res.status(400).json({ status: 'error', message: `Invalid device_id: ${deviceId}` });
      }
      if (!csr || !csr.includes('BEGIN CERTIFICATE REQUEST')) {
        return res.status(400).json({ status: 'error', message: 'Missing or malformed CSR (expected PEM)' });
      }

      vaultIdevidSign(csr, deviceId)
        .then((result) => {
          console.log(`[idevid-issue] Issued IDevID cert for device_id=${deviceId} serial=${result.serial_number}`);
          res.json({ status: 'ok', ...result });
        })
        .catch((err) => {
          console.error('[idevid-issue] Vault sign failed:', err);
          res.status(502).json({ status: 'error', message: err.message });
        });
    });

    // Operator-driven SSH host-identity issuance — see vaultSshHostIssue
    // above and docs/kms/ssh-ca-user-and-host-certs-plan.md in uct-iq9075.
    // Reuses SSH_SIGN_API_KEY/X-SSH-Sign-Key rather than a dedicated
    // credential — same operator key already gates /api/ssh-sign below.
    const PUBLIC_KEY_PATTERN = /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/=]+/;
    app.post('/api/ssh-host-issue/:deviceId', (req, res) => {
      const apiKey = process.env.SSH_SIGN_API_KEY;
      if (!apiKey) {
        console.error('[ssh-host-issue] SSH_SIGN_API_KEY not configured — refusing all requests (fail closed)');
        return res.status(503).json({ status: 'error', message: 'ssh-host-issue endpoint not configured' });
      }
      if (req.get('X-SSH-Sign-Key') !== apiKey) {
        return res.status(401).json({ status: 'error', message: 'unauthorized' });
      }

      const { deviceId } = req.params;
      const { public_key: publicKey } = req.body || {};
      if (!DEVICE_ID_PATTERN.test(deviceId)) {
        return res.status(400).json({ status: 'error', message: `Invalid device_id: ${deviceId}` });
      }
      if (!publicKey || !PUBLIC_KEY_PATTERN.test(publicKey.trim())) {
        return res.status(400).json({ status: 'error', message: 'Missing or malformed public_key (expected OpenSSH pubkey text)' });
      }

      vaultSshHostIssue(publicKey.trim(), deviceId)
        .then((result) => {
          console.log(`[ssh-host-issue] Issued host cert for device_id=${deviceId} serial=${result.serial_number}`);
          res.json({ status: 'ok', ...result, principal: `admin@${deviceId}` });
        })
        .catch((err) => {
          console.error('[ssh-host-issue] Vault sign failed:', err);
          res.status(502).json({ status: 'error', message: err.message });
        });
    });

    // Read-only, unauthenticated: the SSH CA's public key has no
    // confidentiality requirement (same reasoning as TrustedUserCAKeys'
    // removed on-device fetch), matching the existing unauthenticated
    // /api/clients and /version info endpoints rather than the API-key-
    // gated signing endpoints above.
    app.get('/api/ssh-ca-pubkey', (req, res) => {
      vaultSshCaPubkey()
        .then((publicKey) => {
          res.json({ status: 'ok', public_key: publicKey });
        })
        .catch((err) => {
          console.error('[ssh-ca-pubkey] Vault fetch failed:', err);
          res.status(502).json({ status: 'error', message: err.message });
        });
    });

    app.post('/api/ssh-sign', (req, res) => {
      const apiKey = process.env.SSH_SIGN_API_KEY;
      if (!apiKey) {
        console.error('[ssh-sign] SSH_SIGN_API_KEY not configured — refusing all requests (fail closed)');
        return res.status(503).json({ status: 'error', message: 'ssh-sign endpoint not configured' });
      }
      if (req.get('X-SSH-Sign-Key') !== apiKey) {
        return res.status(401).json({ status: 'error', message: 'unauthorized' });
      }

      const { public_key, principal, device_id, engineer_id, ttl } = req.body || {};
      if (!public_key || !principal || !device_id || !engineer_id) {
        return res.status(400).json({
          status: 'error',
          message: 'Missing required fields: public_key, principal, device_id, engineer_id'
        });
      }
      if (!ALLOWED_PRINCIPAL_ROLES.includes(principal)) {
        return res.status(400).json({ status: 'error', message: `Unknown principal role: ${principal}` });
      }
      if (!DEVICE_ID_PATTERN.test(device_id)) {
        return res.status(400).json({ status: 'error', message: `Invalid device_id: ${device_id}` });
      }

      // Device-scoped principal: a cert issued for one device must not be
      // usable to log into a different device running the same image.
      // Each device's own /etc/ssh/auth_principals/<account> only lists
      // its own "<role>@<device_id>" (see kms-cert-manager's
      // _do_rotate_ssh_ca), so this cert will only match on device_id.
      const scopedPrincipal = `${principal}@${device_id}`;

      vaultSshSign(public_key, scopedPrincipal, engineer_id, ttl)
        .then((signedKey) => {
          console.log(`[ssh-sign] Issued cert for engineer_id=${engineer_id} principal=${scopedPrincipal}`);
          res.json({ status: 'ok', certificate: signedKey });
        })
        .catch((err) => {
          console.error('[ssh-sign] Vault sign failed:', err);
          res.status(502).json({ status: 'error', message: err.message });
        });
    });

    // Shared timeout for the wait-for-result endpoint below
    // (/api/ssh-principals-refresh). Vault sign + local file write is
    // normally sub-second; generous margin for MQTT round-trip.
    const DEVICE_REQUEST_TIMEOUT_MS = 25000;

    // Trigger a refresh of this device's writable, dynamic auth_principals
    // entry (/etc/ssh/auth_principals/sysadmin on-device — merged by sshd
    // with the fixed /var/persist/ssh-trust recovery baseline via
    // AuthorizedPrincipalsCommand) on a specific device over MQTT.
    // Renamed from /api/ssh-ca-refresh: the on-device action it triggers
    // was renamed from "ssh-ca" to "ssh-principals" (it never actually
    // touched the CA trust anchor — that's production-line-provisioned,
    // see docs/kms/ssh-ca-user-and-host-certs-plan.md in uct-iq9075).
    // Keeping the old URL with this new payload would be misleading: the
    // path would still say "ca" while touching no CA material at all.
    // Replaces kms-ssh-ca-refresh.timer (removed on the DUT side) as the
    // trigger path. NOTE: this does NOT gate cert-based login the way it
    // used to — the fixed recovery baseline at
    // /var/persist/ssh-trust/auth_principals already grants access even if
    // this is never called; this only adds/updates the dynamic, in-field
    // supplementary principal.
    app.post('/api/ssh-principals-refresh/:deviceId', (req, res) => {
      const apiKey = process.env.SSH_SIGN_API_KEY;
      if (!apiKey) {
        console.error('[ssh-principals-refresh] SSH_SIGN_API_KEY not configured — refusing all requests (fail closed)');
        return res.status(503).json({ status: 'error', message: 'ssh-principals-refresh endpoint not configured' });
      }
      if (req.get('X-SSH-Sign-Key') !== apiKey) {
        return res.status(401).json({ status: 'error', message: 'unauthorized' });
      }

      const deviceId = req.params.deviceId;
      if (!DEVICE_ID_PATTERN.test(deviceId)) {
        return res.status(400).json({ status: 'error', message: `Invalid device_id: ${deviceId}` });
      }

      // No online fast-fail check: connectedClients is keyed by
      // kms-mqtt-trigger's MQTT client_id (`kms-${device_id.slice(0,12)}`),
      // not the device_id itself — that mapping is lossy (truncated to 12
      // chars, distinct devices could even collide), so reconstructing it
      // here would be fragile and misleading. Rely on the timeout below
      // instead of a broken "is it connected" check.
      const requestId = crypto.randomUUID();
      const key = `${deviceId}:${requestId}`;
      const packet = {
        cmd: 'publish',
        qos: 1,
        topic: `kms/${deviceId}/rotate`,
        payload: Buffer.from(JSON.stringify({ service: 'ssh-principals', request_id: requestId })),
        retain: false
      };

      const resultPromise = new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          pendingDeviceRequests.delete(key);
          reject(new Error('timeout'));
        }, DEVICE_REQUEST_TIMEOUT_MS);
        pendingDeviceRequests.set(key, { resolve, timer });
      });

      aedes.publish(packet, function (err) {
        if (err) {
          pendingDeviceRequests.delete(key);
          console.error(`[ssh-principals-refresh] 觸發設備 ${deviceId} 更新失敗:`, err);
          return res.status(500).json({ status: 'error', message: '內部 MQTT 轉發失敗' });
        }
        console.log(`[ssh-principals-refresh] Requested ssh-principals refresh for ${deviceId}, request_id=${requestId}`);
      });

      resultPromise
        .then((result) => {
          res.status(200).json(result);
        })
        .catch(() => {
          res.status(504).json({
            status: 'error',
            message: `No response from ${deviceId} within ${DEVICE_REQUEST_TIMEOUT_MS / 1000}s`
          });
        });
    });
    // ────────────────────────────────────────────────────────────────────────

    // ── SELinux AVC Denial Reporting Endpoints ──────────────────────────────
    // DUT posts JSON batches; server merges into a single avc-denials.json per device.

    // POST /api/avc-report  — receive AVC denial batch and merge into single per-device file
    app.post('/api/avc-report', (req, res) => {
      const report = req.body;

      if (!report || !report.device_id) {
        return res.status(400).json({ error: 'Missing required field: device_id' });
      }

      const deviceId   = report.device_id;
      const receivedAt = new Date().toISOString();

      // Lazy-load merged state from disk if not in memory
      if (!avcStore.has(deviceId)) {
        const disk = loadMergedState(deviceId);
        if (disk) {
          avcStore.set(deviceId, disk);
        } else {
          avcStore.set(deviceId, {
            device_id:              deviceId,
            first_upload_timestamp: report.upload_timestamp || receivedAt,
            last_upload_timestamp:  null,
            last_received_at:       null,
            upload_count:           0,
            total_raw_denials:      0,
            denialMap:              new Map()
          });
        }
      }

      const merged = avcStore.get(deviceId);
      const incomingDenials = report.denials || [];
      let newTypes = 0;

      for (const d of incomingDenials) {
        const key = denialKey(d);
        if (merged.denialMap.has(key)) {
          const existing = merged.denialMap.get(key);
          existing.occurrence_count = (existing.occurrence_count || 1) + (d.occurrence_count || 1);
          if (d.first_seen && (!existing.first_seen || d.first_seen < existing.first_seen))
            existing.first_seen = d.first_seen;
          if (d.last_seen && (!existing.last_seen || d.last_seen > existing.last_seen))
            existing.last_seen = d.last_seen;
        } else {
          merged.denialMap.set(key, { ...d });
          newTypes++;
        }
      }

      // Accumulate counters and refresh metadata from this upload
      merged.upload_count    = (merged.upload_count || 0) + 1;
      merged.total_raw_denials = (merged.total_raw_denials || 0) + (report.raw_denial_count || 0);
      merged.last_upload_timestamp = report.upload_timestamp || receivedAt;
      merged.last_received_at      = receivedAt;
      merged.firmware_version      = report.firmware_version;
      merged.fw_build              = report.fw_build;
      merged.selinux_policy_version = report.selinux_policy_version;
      merged.wnc_local_version     = report.wnc_local_version;
      merged.wnc_local_te_lines    = report.wnc_local_te_lines;
      merged.wnc_local_fc_lines    = report.wnc_local_fc_lines;
      merged.selinux_mode          = report.selinux_mode;

      let savedState = null;
      try {
        savedState = saveMergedState(merged);
        console.log(`[AVC] ${deviceId}: +${incomingDenials.length} incoming (+${newTypes} new) ` +
                    `→ ${merged.denialMap.size} total unique types (upload #${merged.upload_count})`);
      } catch (e) {
        console.error('[AVC] Failed to persist merged state:', e);
      }

      res.json({
        status:                'ok',
        incoming_unique_types: incomingDenials.length,
        new_types_added:       newTypes,
        total_unique_types:    merged.denialMap.size,
        upload_count:          merged.upload_count
      });
    });

    // GET /api/avc-report/:deviceId  — return merged denial set for a device
    app.get('/api/avc-report/:deviceId', (req, res) => {
      const deviceId = req.params.deviceId;
      let merged = avcStore.get(deviceId);
      if (!merged) {
        const disk = loadMergedState(deviceId);
        if (!disk) return res.json({ device_id: deviceId, upload_count: 0, denials: [] });
        avcStore.set(deviceId, disk);
        merged = disk;
      }
      const denials = Array.from(merged.denialMap.values())
        .sort((a, b) => (b.occurrence_count || 0) - (a.occurrence_count || 0));
      res.json({
        device_id:                 merged.device_id,
        first_upload_timestamp:    merged.first_upload_timestamp,
        last_upload_timestamp:     merged.last_upload_timestamp,
        last_received_at:          merged.last_received_at,
        upload_count:              merged.upload_count,
        total_raw_denials:         merged.total_raw_denials,
        total_unique_denial_types: denials.length,
        firmware_version:          merged.firmware_version,
        selinux_policy_version:    merged.selinux_policy_version,
        wnc_local_version:         merged.wnc_local_version,
        selinux_mode:              merged.selinux_mode,
        denials
      });
    });

    // GET /api/avc-report  — summary of all devices with AVC data
    app.get('/api/avc-report', (req, res) => {
      // Scan disk so we surface devices that exist on disk but not yet in avcStore
      const onDisk = fs.existsSync(AVC_DIR)
        ? fs.readdirSync(AVC_DIR)
            .filter(d => d !== 'backup' && fs.existsSync(path.join(AVC_DIR, d, MERGED_FILENAME)))
        : [];
      const summary = onDisk.map(deviceId => {
        try {
          const data = JSON.parse(fs.readFileSync(path.join(AVC_DIR, deviceId, MERGED_FILENAME), 'utf8'));
          return {
            device_id:                 deviceId,
            upload_count:              data.upload_count,
            last_upload_timestamp:     data.last_upload_timestamp,
            last_received_at:          data.last_received_at,
            total_unique_denial_types: data.total_unique_denial_types,
            total_raw_denials:         data.total_raw_denials,
            selinux_mode:              data.selinux_mode,
            selinux_policy_version:    data.selinux_policy_version,
            firmware_version:          data.firmware_version
          };
        } catch (_) {
          return { device_id: deviceId };
        }
      });
      res.json({ total_devices: summary.length, devices: summary });
    });

    // GET /api/avc-files  — list each device's single merged file
    app.get('/api/avc-files', (req, res) => {
      try {
        const devices = fs.existsSync(AVC_DIR)
          ? fs.readdirSync(AVC_DIR).filter(d => d !== 'backup' && fs.statSync(path.join(AVC_DIR, d)).isDirectory())
          : [];
        const summary = devices.map(deviceId => {
          const filePath = path.join(AVC_DIR, deviceId, MERGED_FILENAME);
          if (!fs.existsSync(filePath)) return { device_id: deviceId, file: null };
          try {
            const stat = fs.statSync(filePath);
            const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            return {
              device_id:                 deviceId,
              file:                      MERGED_FILENAME,
              size_bytes:                stat.size,
              upload_count:              data.upload_count,
              last_upload_timestamp:     data.last_upload_timestamp,
              total_unique_denial_types: data.total_unique_denial_types,
              selinux_mode:              data.selinux_mode,
              selinux_policy_version:    data.selinux_policy_version,
              wnc_local_version:         data.wnc_local_version,
              firmware_version:          data.firmware_version
            };
          } catch (_) {
            return { device_id: deviceId, file: MERGED_FILENAME };
          }
        });
        res.json({ total_devices: summary.length, devices: summary });
      } catch (e) {
        console.error('[AVC] /api/avc-files failed:', e);
        res.status(500).json({ error: e.message });
      }
    });

    // GET /api/avc-files/:deviceId  — metadata for the single merged file of a device
    app.get('/api/avc-files/:deviceId', (req, res) => {
      const deviceId = req.params.deviceId;
      const filePath = path.join(AVC_DIR, deviceId, MERGED_FILENAME);
      if (!fs.existsSync(filePath)) {
        return res.json({ device_id: deviceId, file: null });
      }
      try {
        const stat = fs.statSync(filePath);
        const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        res.json({
          device_id:                 deviceId,
          file:                      MERGED_FILENAME,
          size_bytes:                stat.size,
          upload_count:              data.upload_count,
          first_upload_timestamp:    data.first_upload_timestamp,
          last_upload_timestamp:     data.last_upload_timestamp,
          last_received_at:          data.last_received_at,
          total_unique_denial_types: data.total_unique_denial_types,
          total_raw_denials:         data.total_raw_denials,
          selinux_mode:              data.selinux_mode,
          selinux_policy_version:    data.selinux_policy_version,
          wnc_local_version:         data.wnc_local_version,
          firmware_version:          data.firmware_version
        });
      } catch (e) {
        console.error(`[AVC] /api/avc-files/${deviceId} failed:`, e);
        res.status(500).json({ error: e.message });
      }
    });

    // GET /api/avc-files/:deviceId/:filename  — download a specific report JSON file
    app.get('/api/avc-files/:deviceId/:filename', (req, res) => {
      const filePath = path.join(AVC_DIR, req.params.deviceId, req.params.filename);
      if (!fs.existsSync(filePath) || !req.params.filename.endsWith('.json')) {
        return res.status(404).json({ error: 'File not found' });
      }
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="${req.params.filename}"`);
      fs.createReadStream(filePath).pipe(res);
    });

    // POST /api/avc-request/:deviceId  — request immediate upload from a device (via MQTT)
    app.post('/api/avc-request/:deviceId', (req, res) => {
      const deviceId = req.params.deviceId;
      const packet = {
        cmd: 'publish',
        qos: 1,
        topic: `kms/${deviceId}/avc-request`,
        payload: Buffer.from(JSON.stringify({ action: 'upload_now' })),
        retain: false
      };
      aedes.publish(packet, (err) => {
        if (err) return res.status(500).json({ status: 'error', message: err.message });
        console.log(`[AVC] Upload request sent to ${deviceId}`);
        res.json({ status: 'ok', message: `Upload request sent to ${deviceId}` });
      });
    });
    // GET /api/avc-download  — single combined file with all devices' merged AVC denials.
    // After sending the response the originals are moved to avc-reports/backup/<timestamp>/
    // and cleared from the in-memory cache so the next upload cycle starts fresh.
    app.get('/api/avc-download', (req, res) => {
      try {
        const devices = fs.existsSync(AVC_DIR)
          ? fs.readdirSync(AVC_DIR).filter(d => d !== 'backup' && fs.statSync(path.join(AVC_DIR, d)).isDirectory())
          : [];

        const combined = {
          generated_at: new Date().toISOString(),
          total_devices: 0,
          total_unique_denial_types: 0,
          total_raw_denials: 0,
          devices: []
        };

        // Collect which files were successfully read so we know what to back up
        const toBackup = [];
        for (const deviceId of devices) {
          const filePath = path.join(AVC_DIR, deviceId, MERGED_FILENAME);
          if (!fs.existsSync(filePath)) continue;
          try {
            const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            combined.devices.push(data);
            combined.total_unique_denial_types += data.total_unique_denial_types || 0;
            combined.total_raw_denials         += data.total_raw_denials || 0;
            toBackup.push({ deviceId, filePath });
          } catch (_) {}
        }
        combined.total_devices = combined.devices.length;

        const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);

        // After the response is fully sent: move originals to backup/, clear cache
        res.on('finish', () => {
          if (toBackup.length === 0) return;
          const backupDir = path.join(AVC_DIR, 'backup', ts);
          try {
            fs.mkdirSync(backupDir, { recursive: true });
            for (const { deviceId, filePath } of toBackup) {
              const destDir = path.join(backupDir, deviceId);
              fs.mkdirSync(destDir, { recursive: true });
              fs.renameSync(filePath, path.join(destDir, MERGED_FILENAME));
              avcStore.delete(deviceId);
            }
            console.log(`[AVC] download: ${toBackup.length} file(s) moved to backup/${ts}/`);
          } catch (e) {
            console.error('[AVC] backup after download failed:', e);
          }
        });

        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="avc-denials-combined-${ts}.json"`);
        res.json(combined);
      } catch (e) {
        console.error('[AVC] avc-download failed:', e);
        res.status(500).json({ error: e.message });
      }
    });
    // ────────────────────────────────────────────────────────────────────────

    // ────────────────────────────────────────────────────────────────────────
    // Log read endpoint. Auth-gated (2026-07-31 incident: this was
    // unauthenticated and, combined with the dotenv/header leaks fixed
    // above, exposed live Vault tokens/API keys in plaintext to anyone —
    // confirmed external scanning activity was already occurring). Values
    // logged going forward are redacted at the source (redactSensitive()),
    // so this is defense in depth, not the only fix.
    // Reads /app/logs/mqtt-server.log, the file every console.log/warn/error
    // call is mirrored into (see wrapConsole above).
    // ────────────────────────────────────────────────────────────────────────
    const LOG_TAIL_DEFAULT = 500;
    const LOG_TAIL_MAX = 10000;

    app.get('/api/logs', (req, res) => {
      // Reuses SSH_SIGN_API_KEY/X-SSH-Sign-Key rather than a dedicated
      // credential — same operator key already gates /api/ssh-sign and
      // /api/ssh-host-issue above.
      const apiKey = process.env.SSH_SIGN_API_KEY;
      if (!apiKey) {
        console.error('[logs] SSH_SIGN_API_KEY not configured — refusing all requests (fail closed)');
        return res.status(503).json({ status: 'error', message: 'logs endpoint not configured' });
      }
      if (req.get('X-SSH-Sign-Key') !== apiKey) {
        return res.status(401).json({ status: 'error', message: 'unauthorized' });
      }

      let tail = parseInt(req.query.tail, 10);
      if (!Number.isFinite(tail) || tail <= 0) tail = LOG_TAIL_DEFAULT;
      tail = Math.min(tail, LOG_TAIL_MAX);

      fs.readFile(LOG_FILE, 'utf8', (err, data) => {
        if (err) {
          return res.status(500).json({ status: 'error', message: err.message });
        }
        const lines = data.split('\n').filter((l) => l.length > 0);
        const selected = lines.slice(-tail);
        res.json({ status: 'ok', total_lines: lines.length, returned: selected.length, logs: selected.join('\n') });
      });
    });
    // ────────────────────────────────────────────────────────────────────────

    // 3. 啟動 HTTP 伺服器 (強烈建議綁定 127.0.0.1 確保僅限本機存取)
    const HTTP_PORT = 3000;
    app.listen(HTTP_PORT, '0.0.0.0', () => {
      console.log(`HTTP 本機控制介面已啟動: http://127.0.0.1:${HTTP_PORT}`);
    });

  } catch (error) {
    console.error('Aedes Broker 初始化失敗:', error);
  }
}

startMqttServer();
