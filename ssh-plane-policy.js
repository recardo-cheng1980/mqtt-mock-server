'use strict';

const crypto = require('node:crypto');

// New plane-specific certificates are bound to the decimal SoC serial.  Keep
// the legacy endpoint's looser validation in mqtt.js for compatibility, but do
// not let the new provisioning flow issue a plane certificate for a synthetic
// or machine-id-derived identity.
const DEVICE_ID_PATTERN = /^kms-[0-9]+$/;
const ENGINEER_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._@:/-]{0,127}$/;
const PUBLIC_KEY_PATTERN = /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521))\s+[A-Za-z0-9+/]+={0,2}(?:\s[^\r\n]*)?$/;
const MAX_USER_TTL_MINUTES = 1440;
const LOGIN_ACCOUNT_PATTERN = /^[a-z][a-z0-9_-]{0,31}$/;
const MAX_HOST_TTL_HOURS = 8760;
const CA_READ_TOKEN_ENV = 'VAULT_SSH_CA_READ_TOKEN';

const PLANE_POLICIES = Object.freeze({
  host: Object.freeze({
    userMountEnv: 'VAULT_SSH_USER_MOUNT_HOST',
    hostMountEnv: 'VAULT_SSH_HOST_MOUNT_HOST',
    hostRoleEnv: 'VAULT_SSH_HOST_ROLE_HOST',
    hostTokenEnv: 'VAULT_SSH_HOST_TOKEN_HOST',
    hostTtlEnv: 'VAULT_SSH_HOST_TTL_HOST',
    roles: Object.freeze({
      'host-admin': Object.freeze({
        roleEnv: 'VAULT_SSH_USER_ROLE_HOST_ADMIN',
        tokenEnv: 'VAULT_SSH_USER_TOKEN_HOST_ADMIN',
        ttlEnv: 'VAULT_SSH_USER_TTL_HOST_ADMIN',
        principal: 'host-admin'
      }),
      auditor: Object.freeze({
        roleEnv: 'VAULT_SSH_USER_ROLE_AUDITOR',
        tokenEnv: 'VAULT_SSH_USER_TOKEN_AUDITOR',
        ttlEnv: 'VAULT_SSH_USER_TTL_AUDITOR',
        principal: 'auditor'
      })
    })
  }),
  otns: Object.freeze({
    userMountEnv: 'VAULT_SSH_USER_MOUNT_OTNS',
    hostMountEnv: 'VAULT_SSH_HOST_MOUNT_OTNS',
    hostRoleEnv: 'VAULT_SSH_HOST_ROLE_OTNS',
    hostTokenEnv: 'VAULT_SSH_HOST_TOKEN_OTNS',
    hostTtlEnv: 'VAULT_SSH_HOST_TTL_OTNS',
    roles: Object.freeze({
      'ot-admin': Object.freeze({
        roleEnv: 'VAULT_SSH_USER_ROLE_OT_ADMIN',
        tokenEnv: 'VAULT_SSH_USER_TOKEN_OT_ADMIN',
        ttlEnv: 'VAULT_SSH_USER_TTL_OT_ADMIN',
        principal: 'ot-admin'
      }),
      'ot-operator': Object.freeze({
        roleEnv: 'VAULT_SSH_USER_ROLE_OT_OPERATOR',
        tokenEnv: 'VAULT_SSH_USER_TOKEN_OT_OPERATOR',
        ttlEnv: 'VAULT_SSH_USER_TTL_OT_OPERATOR',
        principal: 'ot-operator'
      })
    })
  }),
  dmzns: Object.freeze({
    userMountEnv: 'VAULT_SSH_USER_MOUNT_DMZNS',
    hostMountEnv: 'VAULT_SSH_HOST_MOUNT_DMZNS',
    hostRoleEnv: 'VAULT_SSH_HOST_ROLE_DMZNS',
    hostTokenEnv: 'VAULT_SSH_HOST_TOKEN_DMZNS',
    hostTtlEnv: 'VAULT_SSH_HOST_TTL_DMZNS',
    roles: Object.freeze({
      // The DMZ user CA is the first-hop audience for the Host/OT roles.
      // Reuse the existing logical-role signing credentials so the server
      // does not need a second environment-variable family; Vault must grant
      // each token only its same-role sign path in this mount and its target
      // mount. The target remains server-derived from the URL plane.
      'host-admin': Object.freeze({
        roleEnv: 'VAULT_SSH_USER_ROLE_HOST_ADMIN',
        tokenEnv: 'VAULT_SSH_USER_TOKEN_HOST_ADMIN',
        ttlEnv: 'VAULT_SSH_USER_TTL_HOST_ADMIN',
        principal: 'host-admin',
      }),
      auditor: Object.freeze({
        roleEnv: 'VAULT_SSH_USER_ROLE_AUDITOR',
        tokenEnv: 'VAULT_SSH_USER_TOKEN_AUDITOR',
        ttlEnv: 'VAULT_SSH_USER_TTL_AUDITOR',
        principal: 'auditor',
      }),
      'ot-admin': Object.freeze({
        roleEnv: 'VAULT_SSH_USER_ROLE_OT_ADMIN',
        tokenEnv: 'VAULT_SSH_USER_TOKEN_OT_ADMIN',
        ttlEnv: 'VAULT_SSH_USER_TTL_OT_ADMIN',
        principal: 'ot-admin',
      }),
      'ot-operator': Object.freeze({
        roleEnv: 'VAULT_SSH_USER_ROLE_OT_OPERATOR',
        tokenEnv: 'VAULT_SSH_USER_TOKEN_OT_OPERATOR',
        ttlEnv: 'VAULT_SSH_USER_TTL_OT_OPERATOR',
        principal: 'ot-operator',
      }),
      'dmz-admin': Object.freeze({
        roleEnv: 'VAULT_SSH_USER_ROLE_DMZ_ADMIN',
        tokenEnv: 'VAULT_SSH_USER_TOKEN_DMZ_ADMIN',
        ttlEnv: 'VAULT_SSH_USER_TTL_DMZ_ADMIN',
        principal: 'dmz-admin'
      })
    })
  }),
  itns: Object.freeze({
    userMountEnv: 'VAULT_SSH_USER_MOUNT_ITNS',
    hostMountEnv: 'VAULT_SSH_HOST_MOUNT_ITNS',
    hostRoleEnv: 'VAULT_SSH_HOST_ROLE_ITNS',
    hostTokenEnv: 'VAULT_SSH_HOST_TOKEN_ITNS',
    hostTtlEnv: 'VAULT_SSH_HOST_TTL_ITNS',
    roles: Object.freeze({
      'it-admin': Object.freeze({
        roleEnv: 'VAULT_SSH_USER_ROLE_IT_ADMIN',
        tokenEnv: 'VAULT_SSH_USER_TOKEN_IT_ADMIN',
        ttlEnv: 'VAULT_SSH_USER_TTL_IT_ADMIN',
        principal: 'it-admin'
      })
    })
  })
});

function requestError(message, statusCode) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function getPlanePolicy(plane) {
  const policy = PLANE_POLICIES[plane];
  if (!policy) {
    throw requestError(`Unknown plane: ${plane || ''}`, 400);
  }
  return policy;
}

function assertPublicKey(publicKey) {
  if (typeof publicKey !== 'string' || !PUBLIC_KEY_PATTERN.test(publicKey.trim())) {
    throw requestError('Missing or malformed public_key (expected OpenSSH public key text)', 400);
  }

  const fields = publicKey.trim().split(/\s+/);
  const keyBytes = Buffer.from(fields[1], 'base64');
  if (keyBytes.length < 16 || keyBytes.toString('base64').replace(/=+$/, '') !== fields[1].replace(/=+$/, '')) {
    throw requestError('Malformed public_key encoding', 400);
  }
  return publicKey.trim();
}

function publicKeyFingerprint(publicKey) {
  const blob = publicKey.trim().split(/\s+/)[1];
  return `SHA256:${crypto.createHash('sha256').update(Buffer.from(blob, 'base64')).digest('base64').replace(/=+$/, '')}`;
}

function validateUserTtl(ttl, role) {
  const match = /^([1-9][0-9]{0,3})m$/.exec(ttl);
  if (!match || Number(match[1]) > MAX_USER_TTL_MINUTES) {
    throw requestError(`Invalid ${role} certificate TTL: expected 1m-1440m`, 503);
  }
  return ttl;
}

function validateHostTtl(ttl, plane) {
  const match = /^([1-9][0-9]{0,3})h$/.exec(ttl);
  if (!match || Number(match[1]) > MAX_HOST_TTL_HOURS) {
    throw requestError(`Invalid ${plane} host certificate TTL: expected 1h-8760h`, 503);
  }
  return ttl;
}

function requireConfigured(env, names, description) {
  for (const name of names) {
    if (!env[name]) {
      throw requestError(`${description} is not configured; ${names.join(' and ')} are required`, 503);
    }
  }
}

function getPlaneCaConfig(plane, kind, env = process.env) {
  const policy = getPlanePolicy(plane);
  const isUser = kind === 'user';
  if (!isUser && kind !== 'host') {
    throw requestError(`Unknown CA kind: ${kind || ''}`, 400);
  }

  const mountEnv = isUser ? policy.userMountEnv : policy.hostMountEnv;
  requireConfigured(env, [mountEnv, CA_READ_TOKEN_ENV], `${plane} ${kind} CA retrieval`);
  return {
    plane,
    kind,
    mount: env[mountEnv],
    token: env[CA_READ_TOKEN_ENV],
    mountEnv,
    tokenEnv: CA_READ_TOKEN_ENV
  };
}

function rejectCallerControlled(fields, request) {
  for (const field of fields) {
    if (Object.prototype.hasOwnProperty.call(request, field)) {
      throw requestError(`${field} is server-controlled and must not be supplied`, 400);
    }
  }
}

function resolvePlaneUserSignRequest(plane, body, env = process.env) {
  const policy = getPlanePolicy(plane);
  const request = body && typeof body === 'object' ? body : {};
  const publicKey = assertPublicKey(request.public_key);

  if (!request.role || !policy.roles[request.role]) {
    throw requestError(`Role ${request.role || ''} is not allowed for plane ${plane}`, 400);
  }
  if (!request.device_id || !DEVICE_ID_PATTERN.test(request.device_id)) {
    throw requestError(`Invalid device_id: ${request.device_id || ''}`, 400);
  }
  if (!request.engineer_id || !ENGINEER_ID_PATTERN.test(request.engineer_id)) {
    throw requestError('Missing or malformed engineer_id', 400);
  }
  if (Object.prototype.hasOwnProperty.call(request, 'login_account')) {
    if (plane !== 'host' || !['host-admin', 'auditor'].includes(request.role)) {
      throw requestError('login_account is allowed only for Host host-admin or auditor certificates', 400);
    }
    if (!LOGIN_ACCOUNT_PATTERN.test(request.login_account)) {
      throw requestError('Missing or malformed login_account', 400);
    }
    if (request.engineer_id !== request.login_account) {
      throw requestError('engineer_id must match login_account for account-bound Host certificates', 400);
    }
  }
  rejectCallerControlled(['principal', 'target', 'ttl', 'vault_role', 'vault_mount', 'extensions'], request);

  const rolePolicy = policy.roles[request.role];
  requireConfigured(
    env,
    [policy.userMountEnv, rolePolicy.roleEnv, rolePolicy.tokenEnv],
    `${plane}/${request.role} signing`
  );
  const ttl = validateUserTtl(env[rolePolicy.ttlEnv] || '1440m', `${plane}/${request.role}`);

  return {
    plane,
    kind: 'user',
    role: request.role,
    target: plane,
    principal: request.login_account
      ? `${rolePolicy.principal}:${request.login_account}@${request.device_id}`
      : `${rolePolicy.principal}@${request.device_id}`,
    deviceId: request.device_id,
    engineerId: request.engineer_id,
    publicKey,
    fingerprint: publicKeyFingerprint(publicKey),
    vaultMount: env[policy.userMountEnv],
    vaultRole: env[rolePolicy.roleEnv],
    vaultToken: env[rolePolicy.tokenEnv],
    ttl,
    // DMZ transit certificates are pty-only.  The approved second-hop model
    // imports a separate target key/certificate into /run/user/<uid> on DMZ,
    // so no workstation agent capability is delegated to the transit zone.
    extensions: Object.freeze({ 'permit-pty': '' })
  };
}

function resolvePlaneHostIssueRequest(plane, deviceId, body, env = process.env) {
  const policy = getPlanePolicy(plane);
  const request = body && typeof body === 'object' ? body : {};
  const publicKey = assertPublicKey(request.public_key);

  if (!deviceId || !DEVICE_ID_PATTERN.test(deviceId)) {
    throw requestError(`Invalid device_id: ${deviceId || ''}`, 400);
  }
  rejectCallerControlled(['principal', 'target', 'ttl', 'vault_role', 'vault_mount', 'cert_type'], request);
  requireConfigured(
    env,
    [policy.hostMountEnv, policy.hostRoleEnv, policy.hostTokenEnv],
    `${plane} host signing`
  );

  const ttl = validateHostTtl(env[policy.hostTtlEnv] || '8760h', plane);
  const principal = `${deviceId}.${plane}`;
  return {
    plane,
    kind: 'host',
    deviceId,
    principal,
    publicKey,
    fingerprint: publicKeyFingerprint(publicKey),
    vaultMount: env[policy.hostMountEnv],
    vaultRole: env[policy.hostRoleEnv],
    vaultToken: env[policy.hostTokenEnv],
    ttl
  };
}

function buildPlaneSignAudit(signRequest, signed) {
  return `[ssh-plane-sign] Issued ${signRequest.kind} cert for ` +
    `plane=${signRequest.plane} role=${signRequest.role || 'host'} ` +
    `device_id=${signRequest.deviceId} fingerprint=${signRequest.fingerprint} ` +
    `serial=${signed.serial_number || 'unreported'}`;
}

module.exports = {
  DEVICE_ID_PATTERN,
  ENGINEER_ID_PATTERN,
  PLANE_POLICIES,
  PUBLIC_KEY_PATTERN,
  buildPlaneSignAudit,
  getPlaneCaConfig,
  resolvePlaneHostIssueRequest,
  resolvePlaneUserSignRequest
};
