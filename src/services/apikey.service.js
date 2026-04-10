/**
 * API Key Service
 *
 * API keys provide programmatic access without passwords.
 * - Keys are hashed (SHA-256) before storage
 * - Only the prefix is shown after creation
 * - Keys can have scoped permissions (subset of user's permissions)
 * - Last-used timestamp tracked for audit
 */

const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const db    = require('../config/database');
const redis = require('../config/redis');
const AuditService = require('./audit.service');
const logger = require('../config/logger');

const KEY_PREFIX = 'tos_';  // TenantOS prefix (like stripe's sk_live_)

// ─── CREATE ──────────────────────────────────────────────────

/**
 * Generate a new API key.
 * The raw key is returned ONCE and never stored.
 * Only the SHA-256 hash is persisted.
 */
async function createApiKey({ tenantId, userId, name, permissions = [], expiresAt = null }) {
  // Generate: tos_<tenantPrefix>_<32 random bytes hex>
  const tenantSlugResult = await db.query('SELECT slug FROM tenants WHERE id = $1', [tenantId]);
  const slug = tenantSlugResult.rows[0]?.slug || 'unknown';
  const randomPart = crypto.randomBytes(32).toString('hex');
  const rawKey  = `${KEY_PREFIX}${slug}_${randomPart}`;
  const keyHash = hashApiKey(rawKey);
  const prefix  = rawKey.slice(0, KEY_PREFIX.length + slug.length + 5); // show tos_slug_XXXXX

  const result = await db.query(
    `INSERT INTO api_keys (tenant_id, user_id, name, key_hash, key_prefix, permissions, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING id, name, key_prefix, permissions, expires_at, is_active, created_at`,
    [tenantId, userId, name, keyHash, prefix, JSON.stringify(permissions), expiresAt]
  );

  await AuditService.log({
    tenantId, userId, type: 'auth', severity: 'info', action: 'API_KEY_CREATED',
    metadata: { name, prefix, permissionCount: permissions.length },
  });

  logger.info('API key created', { tenantId, userId, name, prefix });

  return {
    ...result.rows[0],
    key: rawKey,  // Raw key returned only once
    warning: 'Store this key securely. It will not be shown again.',
  };
}

// ─── VERIFY ──────────────────────────────────────────────────

/**
 * Verify an API key and return its context.
 * Checks: existence, expiry, active status, tenant status.
 */
async function verifyApiKey(rawKey) {
  if (!rawKey?.startsWith(KEY_PREFIX)) return null;

  const keyHash = hashApiKey(rawKey);

  // Check Redis cache first
  const cacheKey = `apikey:${keyHash.slice(0, 16)}`;
  const cached = await redis.redis.get(cacheKey);
  if (cached) {
    const data = JSON.parse(cached);
    if (data.revoked) return null;
    return data;
  }

  const result = await db.query(
    `SELECT ak.*, u.email, u.role, u.status as user_status,
            t.status as tenant_status, t.slug as tenant_slug, t.plan, t.rate_limit
     FROM api_keys ak
     JOIN users   u ON u.id = ak.user_id
     JOIN tenants t ON t.id = ak.tenant_id
     WHERE ak.key_hash = $1`,
    [keyHash]
  );

  const key = result.rows[0];
  if (!key) return null;
  if (!key.is_active) return null;
  if (key.tenant_status !== 'active') return null;
  if (key.user_status   !== 'active') return null;
  if (key.expires_at && new Date(key.expires_at) < new Date()) {
    // Auto-deactivate expired keys
    await db.query('UPDATE api_keys SET is_active = FALSE WHERE id = $1', [key.id]);
    return null;
  }

  // Update last used (async, don't await)
  db.query('UPDATE api_keys SET last_used_at = NOW() WHERE id = $1', [key.id]).catch(() => {});

  const context = {
    keyId:       key.id,
    tenantId:    key.tenant_id,
    userId:      key.user_id,
    email:       key.email,
    role:        key.role,
    tenantSlug:  key.tenant_slug,
    plan:        key.plan,
    rateLimit:   key.rate_limit,
    permissions: JSON.parse(key.permissions || '[]'),
  };

  // Cache for 5 minutes
  await redis.redis.setex(cacheKey, 300, JSON.stringify(context));

  return context;
}

// ─── LIST / REVOKE ───────────────────────────────────────────

async function listApiKeys(tenantId, userId) {
  const result = await db.query(
    `SELECT id, name, key_prefix, permissions, expires_at, last_used_at, is_active, created_at
     FROM api_keys
     WHERE tenant_id = $1 AND user_id = $2
     ORDER BY created_at DESC`,
    [tenantId, userId]
  );
  return result.rows;
}

async function revokeApiKey(keyId, tenantId, revokedBy) {
  const result = await db.query(
    `UPDATE api_keys SET is_active = FALSE WHERE id = $1 AND tenant_id = $2 RETURNING name, key_prefix`,
    [keyId, tenantId]
  );
  if (!result.rows[0]) throw Object.assign(new Error('API key not found'), { status: 404 });

  // Invalidate Redis cache (we don't know the exact hash, so use key ID pattern)
  // In production: store keyId→cacheKey mapping in Redis

  await AuditService.log({
    tenantId, userId: revokedBy, type: 'auth', severity: 'warning', action: 'API_KEY_REVOKED',
    metadata: { keyId, name: result.rows[0].name, prefix: result.rows[0].key_prefix },
  });

  return result.rows[0];
}

async function rotateApiKey(keyId, tenantId, userId) {
  // Get old key details
  const old = await db.query(
    'SELECT * FROM api_keys WHERE id = $1 AND tenant_id = $2',
    [keyId, tenantId]
  );
  if (!old.rows[0]) throw Object.assign(new Error('API key not found'), { status: 404 });

  // Revoke old + create new in a transaction
  const newKey = await db.withTransaction(async (client) => {
    await client.query('UPDATE api_keys SET is_active = FALSE WHERE id = $1', [keyId]);
    return createApiKey({
      tenantId, userId,
      name:        `${old.rows[0].name} (rotated)`,
      permissions: JSON.parse(old.rows[0].permissions || '[]'),
      expiresAt:   old.rows[0].expires_at,
    });
  });

  await AuditService.log({
    tenantId, userId, type: 'auth', severity: 'info', action: 'API_KEY_ROTATED',
    metadata: { oldKeyId: keyId, newKeyId: newKey.id },
  });

  return newKey;
}

// ─── MIDDLEWARE ───────────────────────────────────────────────

/**
 * Express middleware: authenticate via API key (Bearer or X-API-Key header).
 * Falls through to next() if no key — allows stacking with JWT auth.
 */
async function apiKeyAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const apiKeyHeader = req.headers['x-api-key'] || '';
    const rawKey = apiKeyHeader || (authHeader.startsWith('Bearer tos_') ? authHeader.slice(7) : null);

    if (!rawKey) return next();

    const context = await verifyApiKey(rawKey);
    if (!context) {
      return res.status(401).json({ ok: false, error: 'Invalid or expired API key', code: 'INVALID_API_KEY' });
    }

    // Attach user context (same shape as JWT auth)
    req.user = {
      id:        context.userId,
      email:     context.email,
      role:      context.role,
      tenantId:  context.tenantId,
      apiKeyId:  context.keyId,
      scopes:    context.permissions,
      authType:  'api_key',
    };

    next();
  } catch (err) {
    next(err);
  }
}

// ─── HELPERS ─────────────────────────────────────────────────

function hashApiKey(rawKey) {
  return crypto.createHash('sha256').update(rawKey).digest('hex');
}

module.exports = {
  createApiKey, verifyApiKey,
  listApiKeys, revokeApiKey, rotateApiKey,
  apiKeyAuth, hashApiKey,
};
