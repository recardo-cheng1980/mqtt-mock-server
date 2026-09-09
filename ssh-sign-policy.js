'use strict';

const crypto = require('node:crypto');

const DEVICE_ID_PATTERN = /^kms-[a-zA-Z0-9]+$/;
const ENGINEER_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._@:/-]{0,127}$/;
const PUBLIC_KEY_PATTERN = /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521))\s+[A-Za-z0-9+/]+={0,2}(?:\s[^\r\n]*)?$/;
const MAX_TTL_MINUTES = 1440;

const ROLE_POLICIES = Object.freeze({
  'host-admin': Object.freeze({
    target: 'host',
    principal: 'host-admin',
    roleEnv: 'VAULT_SSH_ROLE_HOST_ADMIN',
    tokenEnv: 'VAULT_SSH_TOKEN_HOST_ADMIN',
    ttlEnv: 'VAULT_SSH_TTL_HOST_ADMIN'
  }),
  'ot-admin': Object.freeze({
    target: 'otns',
    principal: 'ot-admin',
    roleEnv: 'VAULT_SSH_ROLE_OT_ADMIN',
    tokenEnv: 'VAULT_SSH_TOKEN_OT_ADMIN',
    ttlEnv: 'VAULT_SSH_TTL_OT_ADMIN'
  }),
  'ot-operator': Object.freeze({
    target: 'otns',
    principal: 'ot-operator',
    roleEnv: 'VAULT_SSH_ROLE_OT_OPERATOR',
    tokenEnv: 'VAULT_SSH_TOKEN_OT_OPERATOR',
    ttlEnv: 'VAULT_SSH_TTL_OT_OPERATOR'
  }),
  auditor: Object.freeze({
    target: 'host',
    principal: 'auditor',
    roleEnv: 'VAULT_SSH_ROLE_AUDITOR',
    tokenEnv: 'VAULT_SSH_TOKEN_AUDITOR',
    ttlEnv: 'VAULT_SSH_TTL_AUDITOR'
  }),
  'it-admin': Object.freeze({
    target: 'itns',
    principal: 'it-admin',
    roleEnv: 'VAULT_SSH_ROLE_IT_ADMIN',
    tokenEnv: 'VAULT_SSH_TOKEN_IT_ADMIN',
    ttlEnv: 'VAULT_SSH_TTL_IT_ADMIN'
  }),
  'dmz-admin': Object.freeze({
    target: 'dmzns',
    principal: 'dmz-admin',
    roleEnv: 'VAULT_SSH_ROLE_DMZ_ADMIN',
    tokenEnv: 'VAULT_SSH_TOKEN_DMZ_ADMIN',
    ttlEnv: 'VAULT_SSH_TTL_DMZ_ADMIN'
  })
});

function requestError(message, statusCode) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
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

function validateTtl(ttl, role) {
  const match = /^([1-9][0-9]{0,3})m$/.exec(ttl);
  if (!match || Number(match[1]) > MAX_TTL_MINUTES) {
    throw requestError(`Invalid ${role} certificate TTL: expected 1m-1440m`, 503);
  }
  return ttl;
}

function getConfiguredPolicy(role, env) {
  const policy = ROLE_POLICIES[role];
  if (!policy) {
    throw requestError(`Unknown role: ${role}`, 400);
  }

  const vaultRole = env[policy.roleEnv];
  const vaultToken = env[policy.tokenEnv];
  if (!vaultRole || !vaultToken) {
    throw requestError(
      `${role} signing is not configured; ${policy.roleEnv} and ${policy.tokenEnv} are required`,
      503
    );
  }

  const ttl = validateTtl(env[policy.ttlEnv] || '1440m', role);
  return { ...policy, role, vaultRole, vaultToken, ttl };
}

function resolveSshSignRequest(body, env = process.env) {
  const request = body && typeof body === 'object' ? body : {};
  const publicKey = assertPublicKey(request.public_key);

  if (!request.device_id || !DEVICE_ID_PATTERN.test(request.device_id)) {
    throw requestError(`Invalid device_id: ${request.device_id || ''}`, 400);
  }
  if (!request.engineer_id || !ENGINEER_ID_PATTERN.test(request.engineer_id)) {
    throw requestError('Missing or malformed engineer_id', 400);
  }

  // The new API is role-based. The old principal/ttl fields are deliberately
  // not accepted here because they let a caller influence authorization or
  // certificate lifetime. A temporary, explicitly enabled compatibility path
  // is handled below and still uses a fixed Vault role, token, and TTL.
  if (Object.prototype.hasOwnProperty.call(request, 'ttl')) {
    throw requestError('ttl is server-controlled and must not be supplied', 400);
  }

  let role = request.role;
  let target;
  let principal;
  let policy;

  if (role) {
    if (Object.prototype.hasOwnProperty.call(request, 'principal')) {
      throw requestError('principal is server-controlled; supply role instead', 400);
    }
    policy = getConfiguredPolicy(role, env);
    target = policy.target;
    principal = `${policy.principal}@${request.device_id}`;
  } else if (env.SSH_SIGN_ALLOW_LEGACY_ADMIN === 'true' && request.principal === 'admin') {
    const vaultRole = env.VAULT_SSH_ROLE_LEGACY_ADMIN;
    const vaultToken = env.VAULT_SSH_TOKEN_LEGACY_ADMIN;
    if (!vaultRole || !vaultToken) {
      throw requestError(
        'legacy admin signing is enabled but VAULT_SSH_ROLE_LEGACY_ADMIN and VAULT_SSH_TOKEN_LEGACY_ADMIN are missing',
        503
      );
    }
    role = 'admin';
    target = 'host';
    principal = `admin@${request.device_id}`;
    policy = {
      role,
      target,
      principal: 'admin',
      vaultRole,
      vaultToken,
      ttl: validateTtl(env.VAULT_SSH_TTL_LEGACY_ADMIN || '1440m', role),
      legacy: true
    };
  } else {
    throw requestError(
      'Missing role (expected host-admin, ot-admin, ot-operator, auditor, it-admin, or dmz-admin)',
      400
    );
  }

  if (request.target !== undefined && request.target !== target) {
    throw requestError(`Role ${role} is bound to target ${target}`, 400);
  }

  return {
    role,
    target,
    principal,
    deviceId: request.device_id,
    engineerId: request.engineer_id,
    publicKey,
    fingerprint: publicKeyFingerprint(publicKey),
    vaultRole: policy.vaultRole,
    vaultToken: policy.vaultToken,
    ttl: policy.ttl,
    legacy: Boolean(policy.legacy)
  };
}

function buildSshSignAudit(signRequest, signed) {
  return `[ssh-sign] Issued cert for engineer_id=${signRequest.engineerId} ` +
    `role=${signRequest.role} target=${signRequest.target} ` +
    `device_id=${signRequest.deviceId} fingerprint=${signRequest.fingerprint} ` +
    `serial=${signed.serial_number || 'unreported'}`;
}

module.exports = {
  DEVICE_ID_PATTERN,
  ENGINEER_ID_PATTERN,
  PUBLIC_KEY_PATTERN,
  ROLE_POLICIES,
  buildSshSignAudit,
  resolveSshSignRequest
};
