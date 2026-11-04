'use strict';

const fs = require('node:fs');
const { X509Certificate } = require('node:crypto');

// A separate, public CA is added to existing broker trust. Fail closed if the
// configured file is missing, expired, or not a self-signed CA certificate.
function loadOperationalClientCa(filename, now = Date.now()) {
  const pem = fs.readFileSync(filename);
  const ca = new X509Certificate(pem);
  if (!ca.ca || !ca.checkIssued(ca) || !ca.verify(ca.publicKey) ||
      now < Date.parse(ca.validFrom) || now >= Date.parse(ca.validTo)) {
    throw new Error('Invalid operational MQTT client CA');
  }
  return pem;
}

module.exports = { loadOperationalClientCa };
