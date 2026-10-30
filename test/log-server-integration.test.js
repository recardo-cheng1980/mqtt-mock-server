'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawn, execFileSync } = require('node:child_process');
const { test } = require('node:test');

test('real server starts a fresh log and exposes recent CA errors', { timeout: 30000 }, async (t) => {
  const src = path.resolve(__dirname, '..');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mqtt-server-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  for (const name of ['mqtt.js', 'log-tail.js', 'ssh-sign-policy.js', 'ssh-plane-policy.js', 'clamav-api.js', 'package.json']) {
    fs.copyFileSync(path.join(src, name), path.join(dir, name));
  }
  fs.symlinkSync(path.join(src, 'node_modules'), path.join(dir, 'node_modules'), 'dir');
  fs.mkdirSync(path.join(dir, 'certs'));
  fs.mkdirSync(path.join(dir, 'logs'));
  fs.writeFileSync(path.join(dir, 'logs', 'mqtt-server.log'), 'old log retained\n');
  const cert = path.join(dir, 'certs', 'fullchain.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-keyout', path.join(dir, 'certs', 'privkey.pem'), '-out', cert], { stdio: 'ignore' });
  fs.copyFileSync(cert, path.join(dir, 'certs', 'root-ca.crt'));
  fs.copyFileSync(cert, path.join(dir, 'certs', 'intermediate-ca.crt'));
  const reserve = http.createServer();
  await new Promise((resolve) => reserve.listen(0, '127.0.0.1', resolve));
  const port = reserve.address().port;
  await new Promise((resolve) => reserve.close(resolve));
  const shim = path.join(dir, 'local-listen.js');
  fs.writeFileSync(shim, `const net = require('node:net');
const original = net.Server.prototype.listen;
net.Server.prototype.listen = function(...args) {
  if (typeof args[0] === 'number') {
    args[0] = args[0] === 3000 ? Number(process.env.TEST_HTTP_PORT) : 0;
    if (typeof args[1] === 'function') args.splice(1, 0, '127.0.0.1');
    else args[1] = '127.0.0.1';
  }
  return original.apply(this, args);
};\n`);
  const child = spawn(process.execPath, [path.join(dir, 'mqtt.js')], {
    cwd: dir,
    env: { PATH: process.env.PATH, HOME: dir, NODE_OPTIONS: `--require=${shim}`,
      TEST_HTTP_PORT: String(port), SSH_SIGN_API_KEY: 'fixture-key' },
    stdio: 'ignore'
  });
  t.after(() => {
    if (child.exitCode === null) child.kill('SIGTERM');
  });
  const base = `http://127.0.0.1:${port}`;
  let ready = false;
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw new Error(`server exited ${child.exitCode}`);
    try {
      if ((await fetch(base + '/version')).ok) { ready = true; break; }
    } catch (_) { /* still starting */ }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.ok(ready, 'server did not start');
  assert.equal((await fetch(base + '/api/ssh-user-ca-pubkey/host')).status, 503);
  const response = await fetch(base + '/api/logs?tail=100', { headers: { 'X-SSH-Sign-Key': 'fixture-key' } });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.match(body.logs, /\[ssh-plane-ca\] host\/user CA fetch failed/);
  assert.doesNotMatch(body.logs, /fixture-key/);
  assert.equal(fs.readFileSync(path.join(dir, 'logs', 'mqtt-server.log'), 'utf8'), 'old log retained\n');
  assert.equal(fs.readdirSync(path.join(dir, 'logs')).filter((name) => name !== 'mqtt-server.log').length, 1);
  child.kill('SIGTERM');
  await new Promise((resolve) => child.once('exit', resolve));
});
