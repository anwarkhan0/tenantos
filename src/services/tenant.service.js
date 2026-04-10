/**
 * Tenant Service
 * Handles provisioning, quota tracking, stats aggregation.
 * Each tenant gets an isolated PostgreSQL schema + Redis namespace.
 */

const db     = require('../config/database');
const redis  = require('../config/redis');
const logger = require('../config/logger');
const AuditService = require('./audit.service');
const { sendEmail } = require('../config/aws');

// ─── PLAN LIMITS ─────────────────────────────────────────────
const PLAN_LIMITS = {
  trial:      { rateLimit:   100, maxUsers:   3,  maxStorageMB:  100 },
  pro:        { rateLimit:  1000, maxUsers:  25,  maxStorageMB: 5000 },
  enterprise: { rateLimit:  5000, maxUsers: 500,  maxStorageMB: 50000 },
};

// ─── PROVISION ───────────────────────────────────────────────

async function provision({ slug, name, plan = 'trial', region = 'us-east-1', adminEmail, adminFirstName }) {
  const limits    = PLAN_LIMITS[plan] || PLAN_LIMITS.trial;
  const dbSchema  = `tenant_${slug.replace(/-/g, '_')}`;

  return db.withTransaction(async (client) => {
    // 1. Create tenant row
    const tenantResult = await client.query(
      `INSERT INTO tenants (slug, name, plan, region, db_schema, rate_limit, max_users)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [slug, name, plan, region, dbSchema, limits.rateLimit, limits.maxUsers]
    );
    const tenant = tenantResult.rows[0];

    // 2. Create tenant schema (isolation)
    // In production this would run per-schema migrations
    await client.query(`
      CREATE SCHEMA IF NOT EXISTS "${dbSchema}";
      COMMENT ON SCHEMA "${dbSchema}" IS 'Isolated schema for tenant ${slug}';
    `);

    logger.info('Tenant provisioned', { tenantId: tenant.id, slug, plan, schema: dbSchema });

    await AuditService.log({
      tenantId: tenant.id, type: 'tenant', severity: 'info',
      action: 'TENANT_PROVISIONED',
      afterData: { slug, name, plan, region },
    });

    return tenant;
  });
}

// ─── STATS ───────────────────────────────────────────────────

async function getStats(tenantId) {
  // Try cache first
  const cached = await redis.getTenantCache(tenantId, 'stats');
  if (cached) return cached;

  const [tenantRes, usersRes, sessionsRes, loginRes] = await Promise.all([
    db.query('SELECT * FROM tenants WHERE id = $1', [tenantId]),
    db.query(`SELECT COUNT(*) as total,
               COUNT(*) FILTER (WHERE status = 'active')    as active,
               COUNT(*) FILTER (WHERE status = 'locked')    as locked,
               COUNT(*) FILTER (WHERE role = 'admin')       as admins,
               COUNT(*) FILTER (WHERE email_verified = TRUE) as verified
              FROM users WHERE tenant_id = $1 AND deleted_at IS NULL`, [tenantId]),
    db.query(`SELECT COUNT(*) as active_sessions
              FROM sessions WHERE tenant_id = $1 AND is_active = TRUE AND expires_at > NOW()`, [tenantId]),
    db.query(`SELECT
               COUNT(*) FILTER (WHERE success = TRUE  AND attempted_at > NOW() - INTERVAL '24h') as logins_24h,
               COUNT(*) FILTER (WHERE success = FALSE AND attempted_at > NOW() - INTERVAL '24h') as failures_24h,
               COUNT(*) FILTER (WHERE success = FALSE AND attempted_at > NOW() - INTERVAL '1h')  as failures_1h
              FROM login_attempts WHERE tenant_id = $1`, [tenantId]),
  ]);

  const tenant  = tenantRes.rows[0];
  const users   = usersRes.rows[0];
  const sessions = sessionsRes.rows[0];
  const logins  = loginRes.rows[0];

  const stats = {
    tenant: {
      id:        tenant.id,
      name:      tenant.name,
      slug:      tenant.slug,
      plan:      tenant.plan,
      status:    tenant.status,
      region:    tenant.region,
      rateLimit: tenant.rate_limit,
      maxUsers:  tenant.max_users,
      createdAt: tenant.created_at,
    },
    users: {
      total:    parseInt(users.total),
      active:   parseInt(users.active),
      locked:   parseInt(users.locked),
      admins:   parseInt(users.admins),
      verified: parseInt(users.verified),
      limit:    tenant.max_users,
      utilization: Math.round((parseInt(users.total) / tenant.max_users) * 100),
    },
    sessions: {
      active: parseInt(sessions.active_sessions),
    },
    security: {
      loginsLast24h:   parseInt(logins.logins_24h),
      failuresLast24h: parseInt(logins.failures_24h),
      failuresLastHr:  parseInt(logins.failures_1h),
    },
  };

  // Cache for 60 seconds
  await redis.setTenantCache(tenantId, 'stats', stats, 60);
  return stats;
}

// ─── USAGE TRACKING ──────────────────────────────────────────

async function recordRequest(tenantId) {
  // Increment daily request counter in Redis
  const key  = `usage:${tenantId}:${new Date().toISOString().slice(0, 10)}`;
  const pipe = redis.redis.pipeline();
  pipe.incr(key);
  pipe.expire(key, 90 * 86400); // keep 90 days
  await pipe.exec();
}

async function getUsageHistory(tenantId, days = 30) {
  const dates = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
    dates.push(d);
  }

  const keys = dates.map(d => `usage:${tenantId}:${d}`);
  const values = keys.length ? await redis.redis.mget(...keys) : [];

  return dates.map((date, i) => ({
    date,
    requests: parseInt(values[i] || '0'),
  }));
}

// ─── PLAN UPGRADE ────────────────────────────────────────────

async function upgradePlan(tenantId, newPlan, upgradedBy) {
  const limits = PLAN_LIMITS[newPlan];
  if (!limits) throw Object.assign(new Error(`Invalid plan: ${newPlan}`), { status: 400 });

  const before = await db.query('SELECT * FROM tenants WHERE id = $1', [tenantId]);
  if (!before.rows[0]) throw Object.assign(new Error('Tenant not found'), { status: 404 });

  const result = await db.query(
    `UPDATE tenants SET plan = $1, rate_limit = $2, max_users = $3, updated_at = NOW()
     WHERE id = $4 RETURNING *`,
    [newPlan, limits.rateLimit, limits.maxUsers, tenantId]
  );

  // Invalidate caches
  await Promise.all([
    redis.deleteTenantCache(tenantId, 'tenant_data'),
    redis.deleteTenantCache(tenantId, 'stats'),
  ]);

  await AuditService.log({
    tenantId, userId: upgradedBy, type: 'tenant', severity: 'info',
    action: 'PLAN_UPGRADED',
    beforeData: { plan: before.rows[0].plan },
    afterData:  { plan: newPlan },
  });

  return result.rows[0];
}

// ─── LIST WITH ENRICHMENT ────────────────────────────────────

async function listTenants({ status, plan, search, limit = 20, offset = 0 }) {
  const conditions = ['t.deleted_at IS NULL'];
  const params = [];
  let i = 1;

  if (status) { conditions.push(`t.status = $${i++}`); params.push(status); }
  if (plan)   { conditions.push(`t.plan = $${i++}`);   params.push(plan); }
  if (search) {
    conditions.push(`(t.name ILIKE $${i} OR t.slug ILIKE $${i})`);
    params.push(`%${search}%`); i++;
  }

  const where = conditions.join(' AND ');
  params.push(parseInt(limit));
  params.push(parseInt(offset));

  const [data, count] = await Promise.all([
    db.query(
      `SELECT t.*,
              COUNT(DISTINCT u.id) FILTER (WHERE u.deleted_at IS NULL) as user_count,
              COUNT(DISTINCT s.id) FILTER (WHERE s.is_active = TRUE AND s.expires_at > NOW()) as active_sessions
       FROM tenants t
       LEFT JOIN users u ON u.tenant_id = t.id
       LEFT JOIN sessions s ON s.tenant_id = t.id
       WHERE ${where}
       GROUP BY t.id
       ORDER BY t.created_at DESC
       LIMIT $${i} OFFSET $${i + 1}`,
      params
    ),
    db.query(`SELECT COUNT(*) FROM tenants t WHERE ${where}`, params.slice(0, -2)),
  ]);

  return {
    tenants: data.rows,
    total:   parseInt(count.rows[0].count),
    limit:   parseInt(limit),
    offset:  parseInt(offset),
  };
}

module.exports = {
  provision, getStats, recordRequest, getUsageHistory,
  upgradePlan, listTenants, PLAN_LIMITS,
};
