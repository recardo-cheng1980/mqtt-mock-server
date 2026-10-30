'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const DEFAULT_TAIL = 500;
const MAX_TAIL = 10000;
// Even one very long line must not make the response or retained data unbounded.
const MAX_RESPONSE_BYTES = 1024 * 1024;
const READ_SIZE = 64 * 1024;

function createLogFile(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  const name = `mqtt-server-${new Date().toISOString().replace(/[:.]/g, '-')}-${crypto.randomBytes(6).toString('hex')}.log`;
  const filename = path.join(directory, name);
  // Fail startup instead of running silently without a protected log.
  const fd = fs.openSync(filename, 'wx', 0o600);
  return { filename, fd };
}

// Count the complete snapshot while keeping only the requested tail in memory.
// Bytes beyond the snapshot's size are excluded if the active log grows.
async function readLogTail(filename, tail, maxBytes = MAX_RESPONSE_BYTES) {
  if (!Number.isSafeInteger(tail) || tail < 1 || tail > MAX_TAIL ||
      !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_RESPONSE_BYTES) {
    throw new RangeError('invalid log tail limit');
  }
  const handle = await fs.promises.open(filename, 'r');
  try {
    const size = (await handle.stat()).size;
    const buffer = Buffer.allocUnsafe(READ_SIZE);
    let position = 0;
    let totalLines = 0;
    let current = [];
    let currentSize = 0;
    let currentHasData = false;
    let currentTruncated = false;
    const records = [];
    let retainedSize = 0;

    function addBytes(segment) {
      if (!segment.length) return;
      currentHasData = true;
      // Copy because the read buffer is reused on the next read.
      const part = Buffer.from(segment.length > maxBytes ? segment.subarray(segment.length - maxBytes) : segment);
      if (segment.length > maxBytes) currentTruncated = true;
      current.push(part);
      currentSize += part.length;
      while (currentSize > maxBytes) {
        const excess = currentSize - maxBytes;
        const first = current[0];
        currentTruncated = true;
        if (first.length <= excess) {
          current.shift();
          currentSize -= first.length;
        } else {
          current[0] = first.subarray(excess);
          currentSize -= excess;
        }
      }
    }

    function endLine() {
      if (currentHasData) {
        totalLines++;
        const bytes = Buffer.concat(current, currentSize);
        records.push({ bytes, truncated: currentTruncated });
        retainedSize += bytes.length;
        while (records.length > tail) retainedSize -= records.shift().bytes.length;
        // JSON joins lines with a newline; count these separators as well.
        while (records.length > 1 && retainedSize + records.length - 1 > maxBytes) {
          retainedSize -= records.shift().bytes.length;
        }
      }
      current = [];
      currentSize = 0;
      currentHasData = false;
      currentTruncated = false;
    }

    while (position < size) {
      const wanted = Math.min(buffer.length, size - position);
      const { bytesRead } = await handle.read(buffer, 0, wanted, position);
      if (!bytesRead) throw new Error('log file was truncated during read');
      position += bytesRead;
      let start = 0;
      while (start < bytesRead) {
        const newline = buffer.indexOf(10, start);
        if (newline < 0 || newline >= bytesRead) {
          addBytes(buffer.subarray(start, bytesRead));
          break;
        }
        addBytes(buffer.subarray(start, newline));
        endLine();
        start = newline + 1;
      }
    }
    endLine();
    const truncated = records.length < Math.min(totalLines, tail) || records.some((item) => item.truncated);
    return {
      status: 'ok', total_lines: totalLines, returned: records.length,
      logs: records.map((item) => item.bytes.toString('utf8')).join('\n'), truncated
    };
  } finally {
    await handle.close();
  }
}

function createLogsHandler(filename, getApiKey) {
  return async (req, res) => {
    const apiKey = getApiKey();
    if (!apiKey) {
      console.error('[logs] SSH_SIGN_API_KEY not configured — refusing all requests (fail closed)');
      return res.status(503).json({ status: 'error', message: 'logs endpoint not configured' });
    }
    if (req.get('X-SSH-Sign-Key') !== apiKey) {
      return res.status(401).json({ status: 'error', message: 'unauthorized' });
    }
    let tail = parseInt(req.query.tail, 10);
    if (!Number.isFinite(tail) || tail <= 0) tail = DEFAULT_TAIL;
    tail = Math.min(tail, MAX_TAIL);
    try {
      return res.json(await readLogTail(filename, tail));
    } catch (error) {
      console.error('[logs] log read failed:', error.message);
      return res.status(500).json({ status: 'error', message: 'log read failed' });
    }
  };
}

module.exports = { createLogFile, createLogsHandler, readLogTail, DEFAULT_TAIL, MAX_TAIL, MAX_RESPONSE_BYTES };
