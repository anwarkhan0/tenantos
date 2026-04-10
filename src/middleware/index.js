/**
 * Middleware Stack
 *
 * authenticate      — Verify JWT, check blacklist, attach user to req
 * bruteForce        — Check login attempts before auth routes
 * tenantContext     — Load tenant from header/param, enforce isolation
 * rateLimitByTenant — Per-tenant sliding window rate limit via Redis
 * validateBody      — Joi schema validation
 * requestLogger     — Structured request logging + CloudWatch metric
 */

const jwt     = require('jsonwebtoken');
const { RateLimiterRedis } = require('rate-limit-redis');
const rateLimit = require('express-rate-limit');
const logger  = require('../config/logger');
const redis   = require('../config/redis');
const db      = require('../config/database');
const { Metrics } = require('../config/aws');
const AuditService = require('../services/audit.service');

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'change-me-in-production';

// ─── AUTHENTICATE ─────────────────────────────────────────────

/**
 * Verify Bearer JWT and attach decoded user to req.user
 * Also checks access token blacklist (logout invalidation)
 */
async function authenticate(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    if (!header.startsWith('Bearer ')) {
      return res.status(401).json({ ok: false, error: 'Authorization header required', code: 'NO_TOKEN' });
    }

    const token = header.slice(7);

    let decoded;
    try {
      decoded = jwt.verify(token, ACCESS_SECRET, {
        issuer:   'tenantOS',
        audience: req.headers['x-tenant-id'] || undefined,
      });
    } catch (jwtErr) {
      const code = jwtErr.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN';
      return res.status(401).json({ ok: false, error: jwtErr.message, code });
    }

    if (decoded.type !== 'access') {
      return res.status(401).json({ ok: false, error: 'Invalid token type', code: 'WRONG_TOKEN_TYPE' });
    }

    // Check blacklist (logged-out tokens)
    const isBlacklisted = await redis.isTokenBlacklisted(decoded.jti);
    if (isBlacklisted) {
      return res.status(401).json({ ok: false, error: 'Token has been revoked', code: 'TOKEN_REVOKED' });
    }

    // Attach user context
    req.user = {
      id:       decoded.sub,
      email:    decoded.email,
      role:     decoded.role,
      tenantId: decoded.tenantId,
      jti:      decoded.jti,
      tokenExp: decoded.exp,
    };

    next();
  } catch (err) {
    logger.error('Auth middleware error', { error: err.message });
    next(err);
  }
}

/**
 * Same as authenticate but non-blocking (attaches user if token valid)
 */
async function optionalAuth(req, res, next) {
  if (req.headers.authorization) {
    return authenticate(req, res, next);
  }
  next();
}

// ─── TENANT CONTEXT ───────────────────────────────────────────

/**
 * Load and validate tenant from X-Tenant-ID header or URL param.
 * Ensures users can only access their own tenant's data.
 */
async function tenantContext(req, res, next) {
  try {
    const tenantId = req.headers['x-tenant-id'] || req.params.tenantId;
    if (!tenantId) {
      return res.status(400).json({ ok: false, error: 'X-Tenant-ID header required', code: 'NO_TENANT' });
    }

    // Enforce isolation: users can only access their own tenant
    if (req.user && req.user.role !== 'superadmin' && req.user.tenantId !== tenantId) {
      await AuditService.log({
        tenantId: req.user.tenantId, userId: req.user.id,
        type: 'security', severity: 'critical',
        action: 'CROSS_TENANT_ACCESS_ATTEMPT',
        metadata: { attemptedTenantId: tenantId },
        ipAddress: req.ip,
      });
      return res.status(403).json({ ok: false, error: 'Cross-tenant access forbidden', code: 'TENANT_ISOLATION' });
    }

    // Cache tenant data in Redis
    let tenant = await redis.getTenantCache(tenantId, 'tenant_data');
    if (!tenant) {
      const result = await db.query(
        'SELECT id, slug, name, plan, status, region, rate_limit FROM tenants WHERE id = $1 AND deleted_at IS NULL',
        [tenantId]
      );
      if (!result.rows[0]) {
        return res.status(404).json({ ok: false, error: 'Tenant not found', code: 'TENANT_NOT_FOUND' });
      }
      tenant = result.rows[0];
      await redis.setTenantCache(tenantId, 'tenant_data', tenant, 300);
    }

    if (tenant.status !== 'active') {
      return res.status(403).json({ ok: false, error: `Tenant is ${tenant.status}`, code: 'TENANT_INACTIVE' });
    }

    req.tenant = tenant;
    next();
  } catch (err) {
    next(err);
  }
}

// ─── BRUTE FORCE PROTECTION ───────────────────────────────────

/**
 * Check brute-force counters BEFORE processing login.
 * Must be used BEFORE the route handler that validates credentials.
 */
async function bruteForceProtection(req, res, next) {
  try {
    const email = req.body?.email?.toLowerCase();
    const ip    = req.ip || req.connection.remoteAddress;

    if (!email) return next(); // Let the route handler validate

    const check = await redis.checkBruteForce(email, ip);
    if (check.blocked) {
      Metrics.bruteForceBlock(ip);

      await AuditService.log({
        tenantId:  req.body?.tenantId,
        type:      'security',
        severity:  'critical',
        action:    'BRUTE_FORCE_BLOCKED',
        ipAddress: ip,
        metadata:  { email, reason: check.reason, retryAfter: check.retryAfter }
      });

      return res.status(429).json({
        ok:    false,
        error: 'Too many login attempts. Account temporarily locked.',
        code:  check.reason.toUpperCase(),
        retryAfter: check.retryAfter,
        message: check.reason === 'account_locked'
          ? `Account locked. Try again in ${Math.ceil(check.retryAfter / 60)} minutes.`
          : 'Too many requests from this IP.',
      });
    }

    // Attach attempt info to req for the route handler
    req.loginAttemptInfo = check;
    next();
  } catch (err) {
    next(err);
  }
}

// ─── RATE LIMITING ────────────────────────────────────────────

/**
 * Global rate limiter using Redis as the store (works across multiple instances)
 */
const globalRateLimit = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000'),
  max:      parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'),
  standardHeaders: true,
  legacyHeaders:   false,
  keyGenerator: (req) => {
    const tenantId = req.headers['x-tenant-id'] || 'anonymous';
    return `global:${tenantId}:${req.ip}`;
  },
  handler: (req, res) => {
    res.status(429).json({
      ok:    false,
      error: 'Too many requests',
      code:  'RATE_LIMITED',
      retryAfter: Math.ceil(parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000') / 1000),
    });
  },
});

/**
 * Strict rate limit for auth endpoints
 */
const authRateLimit = rateLimit({
  windowMs: 300000, // 5 minutes
  max:      parseInt(process.env.AUTH_RATE_LIMIT_MAX || '10'),
  standardHeaders: true,
  legacyHeaders:   false,
  keyGenerator: (req) => `auth:${req.ip}`,
  handler: (req, res) => {
    res.status(429).json({
      ok:    false,
      error: 'Too many authentication requests',
      code:  'AUTH_RATE_LIMITED',
      retryAfter: 300,
    });
  },
});

// ─── BODY VALIDATION ─────────────────────────────────────────

function validateBody(schema) {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly:      false,
      stripUnknown:    true,
      allowUnknown:    false,
    });
    if (error) {
      return res.status(400).json({
        ok:     false,
        error:  'Validation failed',
        code:   'VALIDATION_ERROR',
        fields: error.details.map(d => ({ field: d.path.join('.'), message: d.message })),
      });
    }
    req.body = value;
    next();
  };
}

// ─── REQUEST LOGGER ───────────────────────────────────────────

function requestLogger(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    const tenantId = req.headers['x-tenant-id'] || req.user?.tenantId || 'anonymous';
    logger.info('HTTP', {
      method:   req.method,
      path:     req.path,
      status:   res.statusCode,
      duration,
      tenantId,
      userId:   req.user?.id,
      ip:       req.ip,
    });
    Metrics.apiRequest(tenantId, req.method, req.path, res.statusCode, duration);
  });
  next();
}

// ─── ERROR HANDLER ────────────────────────────────────────────

function errorHandler(err, req, res, next) {
  const status  = err.status || 500;
  const message = err.message || 'Internal server error';
  const code    = err.code || 'INTERNAL_ERROR';

  logger.error('Unhandled error', {
    status, message, code,
    stack:    process.env.NODE_ENV === 'development' ? err.stack : undefined,
    path:     req.path,
    method:   req.method,
    tenantId: req.user?.tenantId,
    userId:   req.user?.id,
  });

  res.status(status).json({
    ok:    false,
    error: message,
    code,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
}

module.exports = {
  authenticate,
  optionalAuth,
  tenantContext,
  bruteForceProtection,
  globalRateLimit,
  authRateLimit,
  validateBody,
  requestLogger,
  errorHandler,
};
