'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { X509Certificate } = require('node:crypto');
const { loadOperationalClientCa } = require('../mqtt-client-trust');

test('accepts the configured operational CA and rejects expired CA', () => {
  const filename = path.join(__dirname, '..', 'operational-client-ca.pem');
  const cert = new X509Certificate(loadOperationalClientCa(filename));
  assert.equal(cert.ca, true);
  assert.throws(() => loadOperationalClientCa(filename, Date.parse(cert.validTo) + 1000));
});

test('rejects missing and malformed trust material', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mqtt-client-ca-'));
  try {
    assert.throws(() => loadOperationalClientCa(path.join(directory, 'missing.pem')));
    const invalid = path.join(directory, 'invalid.pem');
    fs.writeFileSync(invalid, 'not a certificate');
    assert.throws(() => loadOperationalClientCa(invalid));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
