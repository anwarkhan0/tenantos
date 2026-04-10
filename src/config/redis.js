/**
 * Redis Client — ioredis
 * Handles:
 *  - Refresh token family storage & invalidation
 *  - Access token blacklist (logout/revoke)
 *  - Brute-force login attempt counters
 *  - Session cache
 *  - Distributed rate limiting
 *  - General tenant-namespaced cache
 */

const Redis = require('ioredis');
const logger = require('./logger');

const redisConfig = {
  host:     process.env.REDIS_HOST || 'localhost',
  port:     parseInt(process.env.REDIS_PORT || '6379'),
  password: process.env.REDIS_PASSWORD || undefined,
  db:       parseInt(process.env.REDIS_DB || '0'),
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  lazyConnect: false,
  retryStrategy(times) {
    if (times > 10) {
      logger.error('Redis: max reconnection attempts reached');
      return null;
    }
    return Math.min(times * 200, 3000);
  },
  ...(process.env.REDIS_TLS === 'true' && { tls: {} }),
};

const redis = new Redis(redisConfig);

redis.on('connect',    () => logger.info('Redis: connected'));
redis.on('ready',      () => logger.info('Redis: ready'));
redis.on('error',  (err) => logger.error('Redis error:', { message: err.message }));
redis.on('close',      () => logger.warn('Redis: connection closed'));
redis.on('reconnecting', (ms) => logger.info(`Redis: reconnecting in ${ms}ms`));

// ─── KEY PREFIXES ────────────────────────────────────────────

const KEYS = {
  // Auth
  refreshFamily:  (familyId)     => `rt:family:${familyId}`,          // token family (rotation)
  tokenBlacklist: (jti)          => `bl:${jti}`,                       // blacklisted access tokens
  session:        (sessionId)    => `sess:${sessionId}`,               // session data
  userSessions:   (userId)       => `user_sess:${userId}`,             // set of session IDs per user

  // Brute force
  loginAttempts:  (identifier)   => `bf:login:${identifier}`,          // count per email/IP
  loginLockout:   (identifier)   => `bf:lock:${identifier}`,           // lockout flag
  ipAttempts:     (ip)           => `bf:ip:${ip}`,                     // per-IP attempts
  ipBlock:        (ip)           => `bf:ipblock:${ip}`,                // IP block flag

  // Rate limiting
  rateLimit:      (tenantId, endpoint) => `rl:${tenantId}:${endpoint}`,

  // Cache
  tenantCache:    (tenantId, key) => `cache:${tenantId}:${key}`,
  tenantData:     (tenantId)     => `tenant:${tenantId}`,
  permissions:    (role)         => `perms:${role}`,
};

// ─── TOKEN FAMILY (Refresh Token Rotation) ───────────────────

/**
 * Store refresh token family metadata.
 * When reuse detected, entire family is invalidated.
 */
async function storeTokenFamily(familyId, userId, tenantId, ttlSeconds) {
  await redis.setex(
    KEYS.refreshFamily(familyId),
    ttlSeconds,
    JSON.stringify({ userId, tenantId, createdAt: Date.now(), revoked: false })
  );
}

async function getTokenFamily(familyId) {
  const raw = await redis.get(KEYS.refreshFamily(familyId));
  return raw ? JSON.parse(raw) : null;
}

async function revokeTokenFamily(familyId, reason = 'manual_revoke') {
  const family = await getTokenFamily(familyId);
  if (!family) return false;
  family.revoked = true;
  family.revokedAt = Date.now();
  family.revokeReason = reason;
  // Keep the key alive for audit purposes — but mark revoked
  const ttl = await redis.ttl(KEYS.refreshFamily(familyId));
  await redis.setex(KEYS.refreshFamily(familyId), Math.max(ttl, 3600), JSON.stringify(family));
  return true;
}

// ─── ACCESS TOKEN BLACKLIST ───────────────────────────────────

/**
 * Blacklist a JWT by its jti (JWT ID) until expiry
 */
async function blacklistToken(jti, expiresInSeconds) {
  await redis.setex(KEYS.tokenBlacklist(jti), expiresInSeconds, '1');
}

async function isTokenBlacklisted(jti) {
  return (await redis.exists(KEYS.tokenBlacklist(jti))) === 1;
}

// ─── SESSIONS ────────────────────────────────────────────────

async function setSession(sessionId, data, ttlSeconds) {
  const pipe = redis.pipeline();
  pipe.setex(KEYS.session(sessionId), ttlSeconds, JSON.stringify(data));
  pipe.sadd(KEYS.userSessions(data.userId), sessionId);
  pipe.expire(KEYS.userSessions(data.userId), ttlSeconds + 3600);
  await pipe.exec();
}

async function getSession(sessionId) {
  const raw = await redis.get(KEYS.session(sessionId));
  return raw ? JSON.parse(raw) : null;
}

async function deleteSession(sessionId) {
  const session = await getSession(sessionId);
  const pipe = redis.pipeline();
  pipe.del(KEYS.session(sessionId));
  if (session?.userId) {
    pipe.srem(KEYS.userSessions(session.userId), sessionId);
  }
  await pipe.exec();
}

async function getUserSessions(userId) {
  const sessionIds = await redis.smembers(KEYS.userSessions(userId));
  if (!sessionIds.length) return [];
  const sessions = await redis.mget(sessionIds.map(id => KEYS.session(id)));
  return sessions
    .filter(Boolean)
    .map(s => JSON.parse(s));
}

async function revokeAllUserSessions(userId) {
  const sessionIds = await redis.smembers(KEYS.userSessions(userId));
  if (sessionIds.length) {
    const pipe = redis.pipeline();
    sessionIds.forEach(id => pipe.del(KEYS.session(id)));
    pipe.del(KEYS.userSessions(userId));
    await pipe.exec();
  }
  return sessionIds.length;
}

// ─── BRUTE FORCE PROTECTION ──────────────────────────────────

const MAX_ATTEMPTS = parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5');
const LOCKOUT_SECS = parseInt(process.env.LOCKOUT_DURATION_MINUTES || '15') * 60;
const IP_MAX       = 20;   // max attempts per IP per window
const IP_WINDOW    = 900;  // 15 min

async function recordLoginAttempt(email, ip, success) {
  const pipe = redis.pipeline();

  if (success) {
    // Clear on success
    pipe.del(KEYS.loginAttempts(email));
    pipe.del(KEYS.loginLockout(email));
    pipe.del(KEYS.ipAttempts(ip));
  } else {
    // Increment counters
    const emailKey = KEYS.loginAttempts(email);
    const ipKey    = KEYS.ipAttempts(ip);
    pipe.incr(emailKey);
    pipe.expire(emailKey, LOCKOUT_SECS);
    pipe.incr(ipKey);
    pipe.expire(ipKey, IP_WINDOW);
  }

  await pipe.exec();
}

async function checkBruteForce(email, ip) {
  const [emailCount, ipCount, isLocked, isIpBlocked] = await redis.mget(
    KEYS.loginAttempts(email),
    KEYS.ipAttempts(ip),
    KEYS.loginLockout(email),
    KEYS.ipBlock(ip)
  );

  if (isLocked) {
    const ttl = await redis.ttl(KEYS.loginLockout(email));
    return { blocked: true, reason: 'account_locked', retryAfter: ttl };
  }

  if (isIpBlocked) {
    const ttl = await redis.ttl(KEYS.ipBlock(ip));
    return { blocked: true, reason: 'ip_blocked', retryAfter: ttl };
  }

  const attempts = parseInt(emailCount || '0');
  if (attempts >= MAX_ATTEMPTS) {
    await redis.setex(KEYS.loginLockout(email), LOCKOUT_SECS, '1');
    return { blocked: true, reason: 'too_many_attempts', retryAfter: LOCKOUT_SECS };
  }

  const ipAttempts = parseInt(ipCount || '0');
  if (ipAttempts >= IP_MAX) {
    await redis.setex(KEYS.ipBlock(ip), IP_WINDOW, '1');
    return { blocked: true, reason: 'ip_rate_exceeded', retryAfter: IP_WINDOW };
  }

  return { blocked: false, attempts, remaining: MAX_ATTEMPTS - attempts };
}

async function getLockoutStatus(email) {
  const [count, isLocked] = await redis.mget(
    KEYS.loginAttempts(email),
    KEYS.loginLockout(email)
  );
  if (isLocked) {
    const ttl = await redis.ttl(KEYS.loginLockout(email));
    return { locked: true, retryAfter: ttl };
  }
  return { locked: false, attempts: parseInt(count || '0'), remaining: MAX_ATTEMPTS - parseInt(count || '0') };
}

// ─── PERMISSIONS CACHE ───────────────────────────────────────

async function cachePermissions(role, permissions) {
  await redis.setex(KEYS.permissions(role), 3600, JSON.stringify(permissions));
}

async function getCachedPermissions(role) {
  const raw = await redis.get(KEYS.permissions(role));
  return raw ? JSON.parse(raw) : null;
}

// ─── TENANT CACHE ────────────────────────────────────────────

async function setTenantCache(tenantId, key, value, ttlSeconds = 300) {
  await redis.setex(KEYS.tenantCache(tenantId, key), ttlSeconds, JSON.stringify(value));
}

async function getTenantCache(tenantId, key) {
  const raw = await redis.get(KEYS.tenantCache(tenantId, key));
  return raw ? JSON.parse(raw) : null;
}

async function deleteTenantCache(tenantId, key) {
  return redis.del(KEYS.tenantCache(tenantId, key));
}

async function flushTenantCache(tenantId) {
  const pattern = `cache:${tenantId}:*`;
  let cursor = '0';
  let deleted = 0;
  do {
    const [nextCursor, keys] = await redis.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
    cursor = nextCursor;
    if (keys.length) {
      await redis.del(...keys);
      deleted += keys.length;
    }
  } while (cursor !== '0');
  return deleted;
}

// ─── HEALTH CHECK ────────────────────────────────────────────

async function healthCheck() {
  const start = Date.now();
  await redis.ping();
  const info = await redis.info('server');
  const versionMatch = info.match(/redis_version:(.+)/);
  const memMatch = info.match(/used_memory_human:(.+)/);
  return {
    status:  'healthy',
    version: versionMatch ? versionMatch[1].trim() : 'unknown',
    memory:  memMatch ? memMatch[1].trim() : 'unknown',
    latency: Date.now() - start,
  };
}

module.exports = {
  redis,
  KEYS,
  // Token family
  storeTokenFamily, getTokenFamily, revokeTokenFamily,
  // Blacklist
  blacklistToken, isTokenBlacklisted,
  // Sessions
  setSession, getSession, deleteSession, getUserSessions, revokeAllUserSessions,
  // Brute force
  recordLoginAttempt, checkBruteForce, getLockoutStatus,
  // Permissions cache
  cachePermissions, getCachedPermissions,
  // Tenant cache
  setTenantCache, getTenantCache, deleteTenantCache, flushTenantCache,
  // Health
  healthCheck,
};
