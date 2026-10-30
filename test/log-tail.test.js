'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const express = require('express');
const { createLogFile, createLogsHandler, readLogTail, MAX_TAIL } = require('../log-tail');

function sandbox(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mqtt-tail-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test('startup creates distinct private files without replacing existing logs', (t) => {
  const dir = sandbox(t);
  const old = path.join(dir, 'mqtt-server.log');
  fs.writeFileSync(old, 'existing log');
  const first = createLogFile(dir);
  const second = createLogFile(dir);
  fs.closeSync(first.fd);
  fs.closeSync(second.fd);
  assert.notEqual(first.filename, second.filename);
  assert.equal(fs.readFileSync(old, 'utf8'), 'existing log');
  assert.equal(fs.statSync(first.filename).mode & 0o777, 0o600);
  assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
});

test('counts nonempty lines and returns the final requested lines', async (t) => {
  const dir = sandbox(t);
  const filename = path.join(dir, 'log');
  fs.writeFileSync(filename, 'alpha\n\nβeta\nlast');
  assert.deepEqual(await readLogTail(filename, 2), {
    status: 'ok', total_lines: 3, returned: 2, logs: 'βeta\nlast', truncated: false
  });
  fs.writeFileSync(filename, '\n\n');
  assert.equal((await readLogTail(filename, 2)).total_lines, 0);
});

test('preserves multibyte characters split across input buffers', async (t) => {
  const dir = sandbox(t);
  const filename = path.join(dir, 'log');
  const line = 'a'.repeat(65535) + '€ end';
  fs.writeFileSync(filename, line + '\n');
  assert.equal((await readLogTail(filename, 1)).logs, line);
});

test('bounds output including oversized individual lines', async (t) => {
  const dir = sandbox(t);
  const filename = path.join(dir, 'log');
  fs.writeFileSync(filename, '0123456789');
  let result = await readLogTail(filename, 1, 6);
  assert.equal(result.logs, '456789');
  assert.equal(result.truncated, true);
  fs.writeFileSync(filename, 'abc\ndef\nghi\n');
  result = await readLogTail(filename, 3, 7);
  assert.equal(result.logs, 'def\nghi');
  assert.equal(result.total_lines, 3);
  assert.equal(result.truncated, true);
});

test('snapshot ignores appended bytes and fails on concurrent truncation', async (t) => {
  const dir = sandbox(t);
  const filename = path.join(dir, 'log');
  const initial = 'a'.repeat(65536) + '\noriginal\n';
  const originalOpen = fs.promises.open;
  async function runWithMutation(mutate) {
    fs.writeFileSync(filename, initial);
    fs.promises.open = async (...args) => {
      const handle = await originalOpen.apply(fs.promises, args);
      const read = handle.read.bind(handle);
      let first = true;
      handle.read = async (...readArgs) => {
        const result = await read(...readArgs);
        if (first) { first = false; mutate(); }
        return result;
      };
      return handle;
    };
    try {
      return await readLogTail(filename, 2);
    } finally {
      fs.promises.open = originalOpen;
    }
  }
  const result = await runWithMutation(() => fs.appendFileSync(filename, 'new line\n'));
  assert.equal(result.total_lines, 2);
  assert.ok(result.logs.endsWith('\noriginal'));
  await assert.rejects(runWithMutation(() => fs.truncateSync(filename, 0)), /truncated during read/);
});

test('tails a file larger than Node string limit with bounded memory', { timeout: 120000 }, async (t) => {
  const dir = sandbox(t);
  const filename = path.join(dir, 'sparse.log');
  const fd = fs.openSync(filename, 'w');
  try {
    const bytes = 512 * 1024 * 1024 + 4096;
    fs.ftruncateSync(fd, bytes);
    fs.writeSync(fd, Buffer.from('\nlast-1\nlast-2\n'), 0, 15, bytes);
  } finally {
    fs.closeSync(fd);
  }
  const result = await readLogTail(filename, 3, 1024);
  assert.equal(result.total_lines, 3);
  assert.equal(result.logs, 'last-1\nlast-2');
  assert.equal(result.truncated, true);
});

test('endpoint retains authentication, tail limits and bounded errors', async (t) => {
  const dir = sandbox(t);
  const filename = path.join(dir, 'log');
  fs.writeFileSync(filename, Array.from({ length: 10005 }, (_, i) => `line-${i}`).join('\n'));
  let key = '';
  const app = express();
  app.get('/api/logs', createLogsHandler(filename, () => key));
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}/api/logs`;
  assert.equal((await fetch(base)).status, 503);
  key = 'fixture-test-key';
  assert.equal((await fetch(base)).status, 401);
  let response = await fetch(base + '?tail=999999', { headers: { 'X-SSH-Sign-Key': key } });
  let result = await response.json();
  assert.equal(response.status, 200);
  assert.equal(result.total_lines, 10005);
  assert.equal(result.returned, MAX_TAIL);
  assert.ok(result.logs.endsWith('line-10004'));
  response = await fetch(base + '?tail=0', { headers: { 'X-SSH-Sign-Key': key } });
  result = await response.json();
  assert.equal(result.returned, 500);
  fs.unlinkSync(filename);
  response = await fetch(base, { headers: { 'X-SSH-Sign-Key': key } });
  assert.equal(response.status, 500);
  assert.equal((await response.json()).message, 'log read failed');
});
