/**
 * Auth Service
 *
 * Implements:
 *  1. JWT access tokens (short-lived, 15 min)
 *  2. Refresh token rotation (long-lived, 7 days)
 *     - Each refresh issues a NEW refresh token
 *     - Old token is marked used immediately
 *     - Reuse of an old token = security breach → entire family revoked
 *  3. Session management (stored in Redis + PostgreSQL)
 *  4. Logout (blacklist access token + revoke refresh family)
 */

const jwt    = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const db     = require('../config/database');
const redisClient = require('../config/redis');
const { sendEmail, Metrics } = require('../config/aws');
const logger = require('../config/logger');
const AuditService = require('./audit.service');

const ACCESS_SECRET  = process.env.JWT_ACCESS_SECRET  || 'change-me-in-production';
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'change-me-in-production-2';
const ACCESS_EXP     = process.env.JWT_ACCESS_EXPIRES  || '15m';
const REFRESH_EXP    = process.env.JWT_REFRESH_EXPIRES || '7d';
const BCRYPT_ROUNDS  = parseInt(process.env.BCRYPT_ROUNDS || '12');

// ─── HELPERS ─────────────────────────────────────────────────

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function parseExpiry(exp) {
  const unit = exp.slice(-1);
  const val  = parseInt(exp.slice(0, -1));
  const map  = { s: 1, m: 60, h: 3600, d: 86400 };
  return val * (map[unit] || 1);
}

// ─── TOKEN GENERATION ────────────────────────────────────────

/**
 * Generate a signed JWT access token.
 * Contains: userId, tenantId, role, jti (for blacklisting)
 */
function generateAccessToken(user, tenantId) {
  const jti = uuidv4();
  const payload = {
    sub:      user.id,
    email:    user.email,
    role:     user.role,
    tenantId,
    jti,
    type:     'access',
  };
  return {
    token:     jwt.sign(payload, ACCESS_SECRET, { expiresIn: ACCESS_EXP, issuer: 'tenantOS', audience: tenantId }),
    jti,
    expiresIn: parseExpiry(ACCESS_EXP),
  };
}

/**
 * Generate a refresh token and store its hash.
 * Returns the raw token (sent to client) and its family ID.
 */
async function generateRefreshToken(userId, tenantId, familyId, ipAddress, userAgent) {
  const rawToken = uuidv4() + '-' + crypto.randomBytes(32).toString('hex');
  const tokenHash = hashToken(rawToken);
  const expiresAt = new Date(Date.now() + parseExpiry(REFRESH_EXP) * 1000);
  const ttlSecs   = parseExpiry(REFRESH_EXP);

  // Store in PostgreSQL (persistent, survives Redis restart)
  const result = await db.query(
    `INSERT INTO refresh_tokens (user_id, tenant_id, token_hash, family_id, ip_address, user_agent, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING id`,
    [userId, tenantId, tokenHash, familyId, ipAddress, userAgent, expiresAt]
  );

  // Store family in Redis for fast lookup
  await redisClient.storeTokenFamily(familyId, userId, tenantId, ttlSecs);

  return {
    token:     rawToken,
    tokenId:   result.rows[0].id,
    tokenHash,
    familyId,
    expiresAt,
    expiresIn: ttlSecs,
  };
}

// ─── LOGIN ───────────────────────────────────────────────────

async function login({ email, password, tenantId, ipAddress, userAgent }) {
  // 1. Find user
  const userResult = await db.query(
    `SELECT u.*, t.status as tenant_status, t.plan, t.rate_limit
     FROM users u
     JOIN tenants t ON t.id = u.tenant_id
     WHERE u.email = $1 AND u.tenant_id = $2 AND u.deleted_at IS NULL`,
    [email.toLowerCase(), tenantId]
  );

  const user = userResult.rows[0];
  const failureBase = { ipAddress, userAgent, tenantId, email };

  // 2. Check tenant status
  if (user && user.tenant_status === 'suspended') {
    await AuditService.log({ ...failureBase, type: 'auth', severity: 'warning', action: 'LOGIN_TENANT_SUSPENDED' });
    throw Object.assign(new Error('Tenant account is suspended'), { status: 403, code: 'TENANT_SUSPENDED' });
  }

  // 3. Validate credentials
  const validPassword = user && await bcrypt.compare(password, user.password_hash);

  if (!user || !validPassword) {
    await redisClient.recordLoginAttempt(email, ipAddress, false);

    // Record in PostgreSQL for long-term audit
    await db.query(
      `INSERT INTO login_attempts (tenant_id, email, ip_address, user_agent, success, failure_reason)
       VALUES ($1, $2, $3, $4, FALSE, $5)`,
      [tenantId, email, ipAddress, userAgent, user ? 'invalid_password' : 'user_not_found']
    );

    await AuditService.log({
      tenantId, type: 'auth', severity: 'warning',
      action: 'LOGIN_FAILED',
      ipAddress, userAgent,
      metadata: { email, reason: user ? 'invalid_password' : 'user_not_found' }
    });

    Metrics.loginFailure(tenantId);
    throw Object.assign(new Error('Invalid email or password'), { status: 401, code: 'INVALID_CREDENTIALS' });
  }

  // 4. Check account lock
  if (user.status === 'locked' || (user.locked_until && new Date(user.locked_until) > new Date())) {
    const lockInfo = await redisClient.getLockoutStatus(email);
    throw Object.assign(new Error('Account is locked'), {
      status: 423, code: 'ACCOUNT_LOCKED',
      retryAfter: lockInfo.retryAfter
    });
  }

  // 5. Issue tokens
  const familyId = uuidv4();
  const { token: accessToken, jti, expiresIn: accessExp } = generateAccessToken(user, tenantId);
  const { token: refreshToken, expiresAt: refreshExp } = await generateRefreshToken(
    user.id, tenantId, familyId, ipAddress, userAgent
  );

  // 6. Create session
  const sessionId = uuidv4();
  const sessionData = {
    sessionId,
    userId:   user.id,
    tenantId,
    role:     user.role,
    email:    user.email,
    familyId,
    ipAddress,
    userAgent,
    createdAt: Date.now(),
  };

  await Promise.all([
    // Store session in Redis
    redisClient.setSession(sessionId, sessionData, parseExpiry(REFRESH_EXP)),

    // Store session in PostgreSQL
    db.query(
      `INSERT INTO sessions (id, user_id, tenant_id, token_family, ip_address, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [sessionId, user.id, tenantId, familyId, ipAddress, userAgent, new Date(Date.now() + parseExpiry(REFRESH_EXP) * 1000)]
    ),

    // Clear failed attempts on success
    redisClient.recordLoginAttempt(email, ipAddress, true),

    // Update last login
    db.query(
      `UPDATE users SET last_login_at = NOW(), last_login_ip = $1, failed_attempts = 0 WHERE id = $2`,
      [ipAddress, user.id]
    ),

    // Record successful login
    db.query(
      `INSERT INTO login_attempts (tenant_id, email, ip_address, user_agent, success)
       VALUES ($1, $2, $3, $4, TRUE)`,
      [tenantId, email, ipAddress, userAgent]
    ),
  ]);

  await AuditService.log({
    tenantId, userId: user.id, type: 'auth', severity: 'info',
    action: 'LOGIN_SUCCESS', ipAddress, userAgent,
    metadata: { sessionId, familyId }
  });

  Metrics.loginSuccess(tenantId);

  return {
    accessToken,
    refreshToken,
    tokenType: 'Bearer',
    expiresIn: accessExp,
    sessionId,
    user: {
      id:        user.id,
      email:     user.email,
      firstName: user.first_name,
      lastName:  user.last_name,
      role:      user.role,
      tenantId,
    },
  };
}

// ─── REFRESH TOKEN ROTATION ───────────────────────────────────

/**
 * Exchange a refresh token for a new access + refresh token pair.
 *
 * Security: If a USED refresh token is presented again (replay attack):
 *  → Entire token family is immediately revoked
 *  → All sessions for this user are terminated
 *  → Security alert is logged and emailed
 */
async function refresh({ refreshToken: rawToken, ipAddress, userAgent }) {
  const tokenHash = hashToken(rawToken);

  // 1. Look up token in PostgreSQL
  const result = await db.query(
    `SELECT rt.*, u.email, u.role, u.status as user_status, t.status as tenant_status
     FROM refresh_tokens rt
     JOIN users u ON u.id = rt.user_id
     JOIN tenants t ON t.id = rt.tenant_id
     WHERE rt.token_hash = $1`,
    [tokenHash]
  );

  const token = result.rows[0];

  if (!token) {
    throw Object.assign(new Error('Invalid refresh token'), { status: 401, code: 'INVALID_TOKEN' });
  }

  // 2. Check expiry
  if (new Date(token.expires_at) < new Date()) {
    throw Object.assign(new Error('Refresh token expired'), { status: 401, code: 'TOKEN_EXPIRED' });
  }

  // 3. Check if revoked
  if (token.revoked) {
    throw Object.assign(new Error('Refresh token has been revoked'), { status: 401, code: 'TOKEN_REVOKED' });
  }

  // 4. ⚠️  REUSE DETECTION — token rotation security
  if (token.is_used) {
    logger.warn('SECURITY: Refresh token reuse detected — possible token theft', {
      tokenId: token.id,
      familyId: token.family_id,
      userId: token.user_id,
      ipAddress,
    });

    // Revoke entire family in PostgreSQL
    await db.query(
      `UPDATE refresh_tokens SET revoked = TRUE, revoked_at = NOW(), revoke_reason = 'reuse_detected'
       WHERE family_id = $1`,
      [token.family_id]
    );

    // Revoke family in Redis
    await redisClient.revokeTokenFamily(token.family_id, 'reuse_detected');

    // Terminate ALL sessions for this user
    await db.query(`UPDATE sessions SET is_active = FALSE WHERE user_id = $1`, [token.user_id]);
    await redisClient.revokeAllUserSessions(token.user_id);

    // Audit + alert
    await AuditService.log({
      tenantId: token.tenant_id, userId: token.user_id,
      type: 'security', severity: 'critical',
      action: 'REFRESH_TOKEN_REUSE',
      ipAddress, userAgent,
      metadata: { familyId: token.family_id, tokenId: token.id }
    });

    Metrics.bruteForceBlock(ipAddress);

    throw Object.assign(
      new Error('Security violation: refresh token reuse detected. All sessions terminated.'),
      { status: 401, code: 'TOKEN_REUSE_DETECTED' }
    );
  }

  // 5. Check family in Redis (fast path)
  const family = await redisClient.getTokenFamily(token.family_id);
  if (family?.revoked) {
    throw Object.assign(new Error('Token family has been revoked'), { status: 401, code: 'FAMILY_REVOKED' });
  }

  // 6. Check user/tenant status
  if (token.user_status !== 'active') {
    throw Object.assign(new Error('Account is not active'), { status: 403, code: 'ACCOUNT_INACTIVE' });
  }
  if (token.tenant_status !== 'active') {
    throw Object.assign(new Error('Tenant is suspended'), { status: 403, code: 'TENANT_SUSPENDED' });
  }

  // 7. Mark current token as used (atomic)
  await db.query(
    `UPDATE refresh_tokens SET is_used = TRUE, used_at = NOW() WHERE id = $1`,
    [token.id]
  );

  // 8. Issue new token pair (same family — rotation chain)
  const user = { id: token.user_id, email: token.email, role: token.role };
  const { token: accessToken, expiresIn: accessExp } = generateAccessToken(user, token.tenant_id);
  const { token: newRefreshToken, tokenId: newTokenId } = await generateRefreshToken(
    token.user_id, token.tenant_id, token.family_id, ipAddress, userAgent
  );

  // 9. Link rotation chain
  await db.query(
    `UPDATE refresh_tokens SET replaced_by_id = $1 WHERE id = $2`,
    [newTokenId, token.id]
  );

  // 10. Update session last-active
  await db.query(
    `UPDATE sessions SET last_active = NOW() WHERE token_family = $1 AND is_active = TRUE`,
    [token.family_id]
  );

  Metrics.tokenRefresh(token.tenant_id);

  logger.debug('Token rotated', { familyId: token.family_id, userId: token.user_id });

  return {
    accessToken,
    refreshToken: newRefreshToken,
    tokenType:   'Bearer',
    expiresIn:   accessExp,
  };
}

// ─── LOGOUT ──────────────────────────────────────────────────

async function logout({ userId, tenantId, jti, accessExpiresIn, refreshToken, ipAddress, userAgent }) {
  const ops = [];

  // Blacklist access token (until its natural expiry)
  if (jti) ops.push(redisClient.blacklistToken(jti, accessExpiresIn || parseExpiry(ACCESS_EXP)));

  // Revoke refresh token family
  if (refreshToken) {
    const tokenHash = hashToken(refreshToken);
    const result = await db.query(
      `UPDATE refresh_tokens SET revoked = TRUE, revoked_at = NOW(), revoke_reason = 'logout'
       WHERE token_hash = $1 AND user_id = $2
       RETURNING family_id`,
      [tokenHash, userId]
    );

    if (result.rows[0]?.family_id) {
      const familyId = result.rows[0].family_id;
      ops.push(redisClient.revokeTokenFamily(familyId, 'logout'));
      ops.push(
        db.query(
          `UPDATE sessions SET is_active = FALSE WHERE token_family = $1`,
          [familyId]
        )
      );
    }
  }

  await Promise.all(ops);

  await AuditService.log({
    tenantId, userId, type: 'auth', severity: 'info',
    action: 'LOGOUT', ipAddress, userAgent,
  });

  Metrics.sessionRevoke(tenantId);
}

// ─── LOGOUT ALL SESSIONS ─────────────────────────────────────

async function logoutAll(userId, tenantId, ipAddress) {
  // Revoke all refresh token families for this user
  await db.query(
    `UPDATE refresh_tokens SET revoked = TRUE, revoked_at = NOW(), revoke_reason = 'logout_all'
     WHERE user_id = $1 AND revoked = FALSE`,
    [userId]
  );

  // Deactivate all sessions
  await db.query(`UPDATE sessions SET is_active = FALSE WHERE user_id = $1`, [userId]);

  // Clear Redis sessions
  const count = await redisClient.revokeAllUserSessions(userId);

  await AuditService.log({
    tenantId, userId, type: 'auth', severity: 'warning',
    action: 'LOGOUT_ALL_SESSIONS', ipAddress,
    metadata: { sessionsRevoked: count }
  });

  return count;
}

// ─── PASSWORD UTILITIES ───────────────────────────────────────

async function hashPassword(plain) {
  return bcrypt.hash(plain, BCRYPT_ROUNDS);
}

async function verifyPassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}

// ─── REGISTER ────────────────────────────────────────────────

async function register({ email, password, firstName, lastName, tenantId, role = 'viewer', ipAddress }) {
  const existing = await db.query(
    'SELECT id FROM users WHERE email = $1 AND tenant_id = $2 AND deleted_at IS NULL',
    [email.toLowerCase(), tenantId]
  );
  if (existing.rows.length) {
    throw Object.assign(new Error('Email already registered'), { status: 409, code: 'EMAIL_EXISTS' });
  }

  const passwordHash = await hashPassword(password);

  const result = await db.withTransaction(async (client) => {
    // Create user
    const userRes = await client.query(
      `INSERT INTO users (tenant_id, email, password_hash, role, first_name, last_name)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, email, role, first_name, last_name, created_at`,
      [tenantId, email.toLowerCase(), passwordHash, role, firstName, lastName]
    );
    const user = userRes.rows[0];

    // Increment tenant user count — check quota
    const tenantRes = await client.query(
      `SELECT COUNT(*) as user_count, max_users, name FROM users u
       JOIN tenants t ON t.id = u.tenant_id
       WHERE u.tenant_id = $1 AND u.deleted_at IS NULL
       GROUP BY t.max_users, t.name`,
      [tenantId]
    );
    const { user_count, max_users, name: tenantName } = tenantRes.rows[0] || {};
    if (parseInt(user_count) > parseInt(max_users)) {
      throw Object.assign(new Error(`User limit reached (max ${max_users})`), { status: 403, code: 'USER_LIMIT_REACHED' });
    }

    return { user, tenantName };
  });

  await AuditService.log({
    tenantId, userId: result.user.id, type: 'user', severity: 'info',
    action: 'USER_REGISTERED', ipAddress,
    metadata: { email, role }
  });

  // Send welcome email (fire and forget)
  sendEmail(email, 'welcome', {
    firstName, tenantName: result.tenantName, role,
    verifyUrl: `${process.env.APP_URL || 'http://localhost:3000'}/verify-email?token=placeholder`,
  });

  return result.user;
}

module.exports = {
  login, refresh, logout, logoutAll, register,
  hashPassword, verifyPassword, generateAccessToken,
  parseExpiry, hashToken,
};
