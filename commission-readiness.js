'use strict';

const crypto = require('node:crypto');

function parseTrustedRoots(bundle) {
  const pems = bundle.toString('utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
  return pems.map(pem => new crypto.X509Certificate(pem));
}

// The TLS peer must have an IDevID certificate actually signed by one of the
// configured factory roots, not merely an issuer with the same common name.
function isFactoryPeer(client, deviceId, roots, expectedIssuer, subjectSuffix) {
  try {
    const socket = client && client.conn;
    if (!socket || socket.authorized !== true || !expectedIssuer || !subjectSuffix) return false;
    const peer = socket.getPeerCertificate();
    if (!peer || !peer.raw || !peer.subject || !peer.issuer ||
        peer.subject.CN !== `${deviceId}.${subjectSuffix}` ||
        peer.issuer.CN !== expectedIssuer) return false;
    const leaf = new crypto.X509Certificate(peer.raw);
    return roots.some(root => leaf.checkIssued(root) && leaf.verify(root.publicKey));
  } catch (_) {
    return false;
  }
}

class ReadinessChallenges {
  constructor({ publish, timeoutMs = 20000 }) {
    this.publish = publish;
    this.timeoutMs = timeoutMs;
    this.pending = new Map();
  }

  request(deviceId) {
    const requestId = crypto.randomUUID();
    return new Promise((resolve) => {
      const finish = ready => {
        const item = this.pending.get(requestId);
        if (!item) return;
        clearTimeout(item.timer);
        this.pending.delete(requestId);
        resolve(ready);
      };
      const timer = setTimeout(() => finish(false), this.timeoutMs);
      this.pending.set(requestId, { deviceId, finish, timer });
      try {
        this.publish(deviceId, requestId, error => { if (error) finish(false); });
      } catch (_) {
        finish(false);
      }
    });
  }

  receive(deviceId, payload, authenticated) {
    if (!authenticated || !payload || payload.version !== 1 || typeof payload.request_id !== 'string') return false;
    const pending = this.pending.get(payload.request_id);
    if (!pending || pending.deviceId !== deviceId || typeof payload.ready !== 'boolean') return false;
    pending.finish(payload.ready);
    return true;
  }
}

function clientPublishAllowed(client, packet, roots, expectedIssuer, subjectSuffix) {
  if (packet.topic.startsWith('$SYS/')) return false;
  if (/^commission\/[^/]+\/(?:command|result|readiness-request)$/.test(packet.topic)) return false;
  const match = /^commission\/([^/]+)\/(?:request|command-status|readiness-response)$/.exec(packet.topic);
  return !match || (!packet.retain && isFactoryPeer(client, match[1], roots, expectedIssuer, subjectSuffix));
}

function forwardAllowed(client, packet, roots, expectedIssuer, subjectSuffix) {
  const match = /^commission\/([^/]+)\/(?:result|command|readiness-request)$/.exec(packet.topic);
  return !match || isFactoryPeer(client, match[1], roots, expectedIssuer, subjectSuffix);
}

module.exports = { parseTrustedRoots, isFactoryPeer, ReadinessChallenges, clientPublishAllowed, forwardAllowed };
