/**
 * MFA Service — Time-based One-Time Password (TOTP)
 *
 * Compatible with Google Authenticator, Authy, 1Password, etc.
 * RFC 6238 compliant — 30-second windows, SHA-1 HMAC, 6-digit codes.
 *
 * Flow:
 *  1. POST /auth/mfa/setup     → returns secret + QR URI
 *  2. POST /auth/mfa/verify    → confirm first code (activates MFA)
 *  3. POST /auth/login (step2) → provide TOTP code after password
 *  4. POST /auth/mfa/disable   → turn off (requires valid code)
 *  5. POST /auth/mfa/backup    → generate one-time backup codes
 */

'use strict';

const crypto = require('crypto');
const db     = require('../config/database');
const redis  = require('../config/redis');
const AuditService = require('./audit.service');
const logger = require('../config/logger');

// ─── CONSTANTS ────────────────────────────────────────────────
const TOTP_WINDOW    = 1;      // ±1 window = 90s grace
const TOTP_STEP      = 30;     // seconds per code
const TOTP_DIGITS    = 6;
const BACKUP_COUNT   = 8;
const APP_NAME       = 'TenantOS';

// ─── SECRET GENERATION ────────────────────────────────────────

/**
 * Generate a cryptographically random Base32 secret.
 * 20 bytes → 160 bits of entropy.
 */
function generateSecret() {
  const bytes  = crypto.randomBytes(20);
  return base32Encode(bytes);
}

/**
 * Build a otpauth:// URI for QR code generation.
 * Compatible with any TOTP app.
 */
function buildOtpAuthUri(secret, email, tenantName) {
  const label   = encodeURIComponent(`${APP_NAME}:${email}`);
  const issuer  = encodeURIComponent(`${APP_NAME} (${tenantName})`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_STEP}`;
}

// ─── TOTP COMPUTATION ─────────────────────────────────────────

/**
 * Generate a TOTP code for a given secret and timestamp.
 * RFC 6238 implementation using Node.js crypto.
 */
function generateTOTP(secret, timestamp = Date.now()) {
  const key      = base32Decode(secret);
  const counter  = Math.floor(timestamp / 1000 / TOTP_STEP);
  const code     = hotp(key, counter);
  return code.toString().padStart(TOTP_DIGITS, '0');
}

/**
 * HMAC-based OTP (RFC 4226)
 */
function hotp(key, counter) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac  = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code   = ((hmac[offset] & 0x7f) << 24) |
                 ((hmac[offset + 1] & 0xff) << 16) |
                 ((hmac[offset + 2] & 0xff) << 8)  |
                  (hmac[offset + 3] & 0xff);
  return code % Math.pow(10, TOTP_DIGITS);
}

/**
 * Verify a TOTP code with clock drift tolerance.
 * Checks current window ± TOTP_WINDOW adjacent windows.
 */
function verifyTOTP(secret, code, timestamp = Date.now()) {
  if (!code || code.length !== TOTP_DIGITS) return false;
  const inputCode = code.toString().trim();
  for (let delta = -TOTP_WINDOW; delta <= TOTP_WINDOW; delta++) {
    const t       = timestamp + (delta * TOTP_STEP * 1000);
    const expected = generateTOTP(secret, t);
    // Constant-time comparison
    if (safeEqual(inputCode, expected)) return true;
  }
  return false;
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// ─── BASE32 ───────────────────────────────────────────────────

const B32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = 0, value = 0, output = '';
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits  += 8;
    while (bits >= 5) {
      output += B32_CHARS[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += B32_CHARS[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(str) {
  const s = str.toUpperCase().replace(/=+$/, '');
  const buf = Buffer.alloc(Math.floor(s.length * 5 / 8));
  let bits = 0, value = 0, index = 0;
  for (const char of s) {
    const v = B32_CHARS.indexOf(char);
    if (v === -1) throw new Error(`Invalid base32 character: ${char}`);
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      buf[index++] = (value >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  return buf;
}

// ─── BACKUP CODES ─────────────────────────────────────────────

/**
 * Generate one-time backup codes.
 * Format: XXXX-XXXX (8 codes, each 8 hex chars split by dash)
 */
function generateBackupCodes() {
  return Array.from({ length: BACKUP_COUNT }, () => {
    const bytes = crypto.randomBytes(4);
    const hex   = bytes.toString('hex').toUpperCase();
    return `${hex.slice(0, 4)}-${hex.slice(4)}`;
  });
}

function hashBackupCode(code) {
  return crypto.createHash('sha256').update(code.replace('-', '').toUpperCase()).digest('hex');
}

// ─── SERVICE METHODS ──────────────────────────────────────────

/**
 * Step 1: Initiate MFA setup.
 * Returns the secret and QR URI but does NOT enable MFA yet.
 * MFA is only activated after the user verifies their first code.
 */
async function setupMfa(userId, tenantId) {
  const userRes = await db.query(
    'SELECT email, mfa_enabled FROM users WHERE id = $1 AND tenant_id = $2',
    [userId, tenantId]
  );
  const user = userRes.rows[0];
  if (!user) throw Object.assign(new Error('User not found'), { status: 404 });
  if (user.mfa_enabled) throw Object.assign(new Error('MFA already enabled'), { status: 409 });

  const tenantRes = await db.query('SELECT name FROM tenants WHERE id = $1', [tenantId]);
  const tenantName = tenantRes.rows[0]?.name || 'TenantOS';

  const secret = generateSecret();
  const uri    = buildOtpAuthUri(secret, user.email, tenantName);

  // Store pending secret in Redis (expires in 10 min if not confirmed)
  await redis.redis.setex(
    `mfa:pending:${userId}`,
    600,
    JSON.stringify({ secret, createdAt: Date.now() })
  );

  logger.info('MFA setup initiated', { userId, tenantId });

  return {
    secret,
    otpAuthUri: uri,
    qrCodeUrl:  `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(uri)}`,
    backupCodes: null,  // issued after confirmation
    message: 'Scan the QR code with your authenticator app, then verify with a code.',
  };
}

/**
 * Step 2: Confirm the first TOTP code to activate MFA.
 * Also generates and returns backup codes.
 */
async function confirmMfa(userId, tenantId, code, ipAddress) {
  const pendingRaw = await redis.redis.get(`mfa:pending:${userId}`);
  if (!pendingRaw) {
    throw Object.assign(new Error('MFA setup expired or not initiated'), { status: 400 });
  }

  const { secret } = JSON.parse(pendingRaw);
  if (!verifyTOTP(secret, code)) {
    await AuditService.log({
      tenantId, userId, type: 'auth', severity: 'warning',
      action: 'MFA_CONFIRM_FAILED', ipAddress,
      metadata: { reason: 'invalid_code' },
    });
    throw Object.assign(new Error('Invalid TOTP code'), { status: 401, code: 'INVALID_MFA_CODE' });
  }

  // Generate backup codes
  const backupCodes = generateBackupCodes();
  const backupHashes = backupCodes.map(hashBackupCode);

  // Activate MFA in DB + store backup code hashes
  await db.withTransaction(async (client) => {
    await client.query(
      `UPDATE users
       SET mfa_enabled = TRUE, mfa_secret = $1, updated_at = NOW()
       WHERE id = $2`,
      [secret, userId]
    );
    // Store backup codes as hashed JSON array
    await client.query(
      `UPDATE users SET metadata = jsonb_set(metadata, '{mfa_backup_codes}', $1::jsonb)
       WHERE id = $2`,
      [JSON.stringify(backupHashes), userId]
    );
  });

  // Clear pending secret from Redis
  await redis.redis.del(`mfa:pending:${userId}`);

  await AuditService.log({
    tenantId, userId, type: 'auth', severity: 'info',
    action: 'MFA_ENABLED', ipAddress,
  });

  logger.info('MFA enabled', { userId, tenantId });

  return {
    enabled: true,
    backupCodes,  // shown ONCE — user must save these
    message: 'MFA enabled. Store your backup codes securely.',
  };
}

/**
 * Verify a TOTP code during login (step 2 of auth).
 * Also checks backup codes if TOTP fails.
 */
async function verifyMfaCode(userId, tenantId, code, ipAddress) {
  const userRes = await db.query(
    'SELECT mfa_secret, mfa_enabled, metadata FROM users WHERE id = $1',
    [userId]
  );
  const user = userRes.rows[0];
  if (!user?.mfa_enabled) return true; // MFA not required

  // Try TOTP first
  if (verifyTOTP(user.mfa_secret, code)) {
    // Use Redis to prevent code replay (within same 30s window)
    const replayKey = `mfa:used:${userId}:${code}`;
    const alreadyUsed = await redis.redis.exists(replayKey);
    if (alreadyUsed) {
      throw Object.assign(new Error('TOTP code already used'), { status: 401, code: 'MFA_CODE_REPLAYED' });
    }
    await redis.redis.setex(replayKey, TOTP_STEP * 3, '1');

    await AuditService.log({
      tenantId, userId, type: 'auth', severity: 'info',
      action: 'MFA_VERIFIED', ipAddress,
    });
    return true;
  }

  // Try backup code
  const backupCodes = user.metadata?.mfa_backup_codes || [];
  const inputHash   = hashBackupCode(code);
  const idx         = backupCodes.indexOf(inputHash);

  if (idx !== -1) {
    // Consume backup code (one-time use)
    backupCodes.splice(idx, 1);
    await db.query(
      `UPDATE users SET metadata = jsonb_set(metadata, '{mfa_backup_codes}', $1::jsonb) WHERE id = $2`,
      [JSON.stringify(backupCodes), userId]
    );
    await AuditService.log({
      tenantId, userId, type: 'auth', severity: 'warning',
      action: 'MFA_BACKUP_CODE_USED', ipAddress,
      metadata: { codesRemaining: backupCodes.length },
    });
    return true;
  }

  await AuditService.log({
    tenantId, userId, type: 'auth', severity: 'warning',
    action: 'MFA_VERIFY_FAILED', ipAddress,
    metadata: { reason: 'invalid_code' },
  });
  throw Object.assign(new Error('Invalid MFA code'), { status: 401, code: 'INVALID_MFA_CODE' });
}

/**
 * Disable MFA (requires current valid TOTP code).
 */
async function disableMfa(userId, tenantId, code, ipAddress) {
  const userRes = await db.query(
    'SELECT mfa_secret, mfa_enabled FROM users WHERE id = $1',
    [userId]
  );
  const user = userRes.rows[0];
  if (!user?.mfa_enabled) throw Object.assign(new Error('MFA not enabled'), { status: 400 });

  if (!verifyTOTP(user.mfa_secret, code)) {
    throw Object.assign(new Error('Invalid TOTP code'), { status: 401, code: 'INVALID_MFA_CODE' });
  }

  await db.query(
    `UPDATE users
     SET mfa_enabled = FALSE, mfa_secret = NULL,
         metadata = metadata - 'mfa_backup_codes', updated_at = NOW()
     WHERE id = $1`,
    [userId]
  );

  await AuditService.log({
    tenantId, userId, type: 'auth', severity: 'warning',
    action: 'MFA_DISABLED', ipAddress,
  });

  return { disabled: true };
}

/**
 * Regenerate backup codes (invalidates old ones).
 */
async function regenerateBackupCodes(userId, tenantId, code, ipAddress) {
  await verifyMfaCode(userId, tenantId, code, ipAddress);

  const backupCodes  = generateBackupCodes();
  const backupHashes = backupCodes.map(hashBackupCode);

  await db.query(
    `UPDATE users SET metadata = jsonb_set(metadata, '{mfa_backup_codes}', $1::jsonb) WHERE id = $2`,
    [JSON.stringify(backupHashes), userId]
  );

  await AuditService.log({
    tenantId, userId, type: 'auth', severity: 'warning',
    action: 'MFA_BACKUP_CODES_REGENERATED', ipAddress,
  });

  return { backupCodes, message: 'Old backup codes have been invalidated.' };
}

module.exports = {
  setupMfa, confirmMfa, verifyMfaCode, disableMfa, regenerateBackupCodes,
  generateTOTP, verifyTOTP, generateSecret,
};
