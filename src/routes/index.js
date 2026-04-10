/**
 * Routes index — mounts all route modules
 */

const express    = require('express');
const Joi        = require('joi');
const router     = express.Router();

const { authenticate, tenantContext, validateBody } = require('../middleware');
const rbac       = require('../services/rbac.service');
const AuditService = require('../services/audit.service');
const db         = require('../config/database');
const redis      = require('../config/redis');
const { uploadAuditExport, sendEmail } = require('../config/aws');
const logger     = require('../config/logger');

// ════════════════════════════════════════════════════════════
// TENANTS
// ════════════════════════════════════════════════════════════

const tenantsRouter = express.Router();

// GET /api/v1/tenants
tenantsRouter.get('/', authenticate, rbac.require('tenants', 'read'), async (req, res, next) => {
  try {
    const { status, plan, limit = 20, offset = 0 } = req.query;
    let q = `SELECT id, slug, name, plan, status, region, db_schema, rate_limit, max_users, created_at, updated_at FROM tenants WHERE deleted_at IS NULL`;
    const params = [];
    if (status) { params.push(status); q += ` AND status = $${params.length}`; }
    if (plan)   { params.push(plan);   q += ` AND plan = $${params.length}`; }
    params.push(parseInt(limit)); q += ` ORDER BY created_at DESC LIMIT $${params.length}`;
    params.push(parseInt(offset)); q += ` OFFSET $${params.length}`;

    const [data, count] = await Promise.all([
      db.query(q, params),
      db.query(`SELECT COUNT(*) FROM tenants WHERE deleted_at IS NULL${status ? ` AND status = '${status}'` : ''}`),
    ]);

    res.json({ ok: true, data: { tenants: data.rows, total: parseInt(count.rows[0].count), limit: parseInt(limit), offset: parseInt(offset) } });
  } catch (err) { next(err); }
});

// GET /api/v1/tenants/:id
tenantsRouter.get('/:id', authenticate, rbac.require('tenants', 'read'), async (req, res, next) => {
  try {
    const result = await db.query(
      `SELECT t.*, COUNT(u.id) as user_count FROM tenants t LEFT JOIN users u ON u.tenant_id = t.id AND u.deleted_at IS NULL WHERE t.id = $1 AND t.deleted_at IS NULL GROUP BY t.id`,
      [req.params.id]
    );
    if (!result.rows[0]) return res.status(404).json({ ok: false, error: 'Tenant not found' });
    res.json({ ok: true, data: { tenant: result.rows[0] } });
  } catch (err) { next(err); }
});

// POST /api/v1/tenants
tenantsRouter.post('/',
  authenticate,
  rbac.require('tenants', 'create'),
  validateBody(Joi.object({
    slug:      Joi.string().alphanum().min(2).max(64).required(),
    name:      Joi.string().min(2).max(255).required(),
    plan:      Joi.string().valid('trial','pro','enterprise').default('trial'),
    region:    Joi.string().default('us-east-1'),
    maxUsers:  Joi.number().integer().min(1).default(5),
  })),
  async (req, res, next) => {
    try {
      const { slug, name, plan, region, maxUsers } = req.body;
      const dbSchema   = `tenant_${slug.replace(/-/g,'_')}`;
      const rateLimit  = plan === 'enterprise' ? 5000 : plan === 'pro' ? 1000 : 100;

      const result = await db.withTransaction(async (client) => {
        const t = await client.query(
          `INSERT INTO tenants (slug, name, plan, region, db_schema, rate_limit, max_users)
           VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
          [slug, name, plan, region, dbSchema, rateLimit, maxUsers]
        );
        return t.rows[0];
      });

      await AuditService.log({
        userId: req.user.id, type: 'tenant', severity: 'info', action: 'TENANT_CREATED',
        resourceId: result.id, afterData: result, ipAddress: req.ip,
        metadata: { slug, name, plan },
      });

      res.status(201).json({ ok: true, data: { tenant: result } });
    } catch (err) {
      if (err.code === '23505') return res.status(409).json({ ok: false, error: 'Tenant slug already exists', code: 'SLUG_TAKEN' });
      next(err);
    }
  }
);

// PATCH /api/v1/tenants/:id
tenantsRouter.patch('/:id',
  authenticate,
  rbac.require('tenants', 'update'),
  validateBody(Joi.object({
    name:      Joi.string().min(2).max(255),
    plan:      Joi.string().valid('trial','pro','enterprise'),
    status:    Joi.string().valid('active','suspended'),
    rateLimit: Joi.number().integer().min(0).max(100000),
    maxUsers:  Joi.number().integer().min(1),
    settings:  Joi.object(),
  }).min(1)),
  async (req, res, next) => {
    try {
      const before = await db.query('SELECT * FROM tenants WHERE id = $1', [req.params.id]);
      if (!before.rows[0]) return res.status(404).json({ ok: false, error: 'Tenant not found' });

      const sets = []; const params = []; let i = 1;
      if (req.body.name)      { sets.push(`name=$${i++}`);       params.push(req.body.name); }
      if (req.body.plan)      { sets.push(`plan=$${i++}`);       params.push(req.body.plan); }
      if (req.body.status)    { sets.push(`status=$${i++}`);     params.push(req.body.status); }
      if (req.body.rateLimit !== undefined) { sets.push(`rate_limit=$${i++}`); params.push(req.body.rateLimit); }
      if (req.body.maxUsers)  { sets.push(`max_users=$${i++}`);  params.push(req.body.maxUsers); }

      params.push(req.params.id);
      const result = await db.query(`UPDATE tenants SET ${sets.join(',')} WHERE id = $${i} RETURNING *`, params);

      // Invalidate tenant cache
      await redis.deleteTenantCache(req.params.id, 'tenant_data');

      await AuditService.log({
        userId: req.user.id, type: 'tenant', severity: 'info', action: 'TENANT_UPDATED',
        resourceId: req.params.id, beforeData: before.rows[0], afterData: result.rows[0], ipAddress: req.ip,
      });

      res.json({ ok: true, data: { tenant: result.rows[0] } });
    } catch (err) { next(err); }
  }
);

// POST /api/v1/tenants/:id/suspend
tenantsRouter.post('/:id/suspend', authenticate, rbac.require('tenants', 'suspend'), async (req, res, next) => {
  try {
    const result = await db.query(`UPDATE tenants SET status = 'suspended' WHERE id = $1 RETURNING *`, [req.params.id]);
    if (!result.rows[0]) return res.status(404).json({ ok: false, error: 'Tenant not found' });
    await redis.deleteTenantCache(req.params.id, 'tenant_data');
    await AuditService.log({ userId: req.user.id, type: 'tenant', severity: 'warning', action: 'TENANT_SUSPENDED', resourceId: req.params.id, ipAddress: req.ip });
    res.json({ ok: true, data: { tenant: result.rows[0] } });
  } catch (err) { next(err); }
});

// POST /api/v1/tenants/:id/reactivate
tenantsRouter.post('/:id/reactivate', authenticate, rbac.require('tenants', 'suspend'), async (req, res, next) => {
  try {
    const result = await db.query(`UPDATE tenants SET status = 'active' WHERE id = $1 RETURNING *`, [req.params.id]);
    if (!result.rows[0]) return res.status(404).json({ ok: false, error: 'Tenant not found' });
    await redis.deleteTenantCache(req.params.id, 'tenant_data');
    await AuditService.log({ userId: req.user.id, type: 'tenant', severity: 'info', action: 'TENANT_REACTIVATED', resourceId: req.params.id, ipAddress: req.ip });
    res.json({ ok: true, data: { tenant: result.rows[0] } });
  } catch (err) { next(err); }
});

// ════════════════════════════════════════════════════════════
// USERS
// ════════════════════════════════════════════════════════════

const usersRouter = express.Router();

// GET /api/v1/users
usersRouter.get('/', authenticate, rbac.require('users', 'read'), async (req, res, next) => {
  try {
    const tenantId = req.user.role === 'superadmin'
      ? req.query.tenantId
      : req.user.tenantId;

    const result = await db.query(
      `SELECT id, email, first_name, last_name, role, status, email_verified, last_login_at, created_at
       FROM users WHERE tenant_id = $1 AND deleted_at IS NULL ORDER BY created_at DESC`,
      [tenantId]
    );
    res.json({ ok: true, data: { users: result.rows, total: result.rows.length } });
  } catch (err) { next(err); }
});

// PATCH /api/v1/users/:id/role
usersRouter.patch('/:id/role', authenticate, rbac.require('users', 'update'),
  validateBody(Joi.object({ role: Joi.string().valid('admin','developer','analyst','viewer').required() })),
  async (req, res, next) => {
    try {
      const user = await rbac.changeUserRole(req.params.id, req.body.role, req.user.id, req.user.tenantId);
      res.json({ ok: true, data: { user } });
    } catch (err) { next(err); }
  }
);

// DELETE /api/v1/users/:id
usersRouter.delete('/:id', authenticate, rbac.require('users', 'delete'), async (req, res, next) => {
  try {
    const result = await db.query(
      `UPDATE users SET deleted_at = NOW(), status = 'inactive' WHERE id = $1 AND tenant_id = $2 RETURNING email`,
      [req.params.id, req.user.tenantId]
    );
    if (!result.rows[0]) return res.status(404).json({ ok: false, error: 'User not found' });

    // Revoke all sessions
    await redis.revokeAllUserSessions(req.params.id);

    await AuditService.log({ tenantId: req.user.tenantId, userId: req.user.id, type: 'user', severity: 'warning', action: 'USER_DELETED', resourceId: req.params.id, ipAddress: req.ip });
    res.json({ ok: true, data: { message: 'User deleted and all sessions revoked' } });
  } catch (err) { next(err); }
});

// ════════════════════════════════════════════════════════════
// AUDIT LOGS
// ════════════════════════════════════════════════════════════

const auditRouter = express.Router();

// GET /api/v1/audit
auditRouter.get('/', authenticate, rbac.require('audit', 'read'), async (req, res, next) => {
  try {
    const tenantId = req.user.role === 'superadmin' ? req.query.tenantId : req.user.tenantId;
    const result = await AuditService.query({
      tenantId,
      userId:   req.query.userId,
      type:     req.query.type,
      severity: req.query.severity,
      action:   req.query.action,
      from:     req.query.from,
      to:       req.query.to,
      limit:    parseInt(req.query.limit || '50'),
      offset:   parseInt(req.query.offset || '0'),
    });
    res.json({ ok: true, data: result });
  } catch (err) { next(err); }
});

// GET /api/v1/audit/summary
auditRouter.get('/summary', authenticate, rbac.require('audit', 'read'), async (req, res, next) => {
  try {
    const summary = await AuditService.getSecuritySummary(req.user.tenantId, parseInt(req.query.days || '7'));
    res.json({ ok: true, data: { summary } });
  } catch (err) { next(err); }
});

// POST /api/v1/audit/export — export to S3
auditRouter.post('/export', authenticate, rbac.require('audit', 'export'), async (req, res, next) => {
  try {
    const csv = await AuditService.exportToCsv(req.user.tenantId, req.body.from, req.body.to);
    const date = new Date().toISOString().slice(0, 10);

    let s3Result = null;
    try {
      s3Result = await uploadAuditExport(req.user.tenantId, csv, date);
    } catch {
      // S3 not configured — return CSV directly
    }

    await AuditService.log({ tenantId: req.user.tenantId, userId: req.user.id, type: 'audit', severity: 'info', action: 'AUDIT_EXPORTED', ipAddress: req.ip });

    if (s3Result) {
      res.json({ ok: true, data: { s3Key: s3Result.key, url: s3Result.url, message: 'Exported to S3' } });
    } else {
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="audit-${date}.csv"`);
      res.send(csv);
    }
  } catch (err) { next(err); }
});

// ════════════════════════════════════════════════════════════
// RBAC
// ════════════════════════════════════════════════════════════

const rbacRouter = express.Router();

// GET /api/v1/rbac/permissions
rbacRouter.get('/permissions', authenticate, async (req, res, next) => {
  try {
    const perms = await rbac.getAllPermissions();
    res.json({ ok: true, data: { permissions: perms } });
  } catch (err) { next(err); }
});

// GET /api/v1/rbac/matrix
rbacRouter.get('/matrix', authenticate, async (req, res, next) => {
  try {
    const matrix = await rbac.getRoleMatrix();
    res.json({ ok: true, data: { matrix } });
  } catch (err) { next(err); }
});

// GET /api/v1/rbac/check?resource=users&action=create
rbacRouter.get('/check', authenticate, async (req, res, next) => {
  try {
    const { resource, action } = req.query;
    if (!resource || !action) return res.status(400).json({ ok: false, error: 'resource and action required' });
    const allowed = await rbac.can(req.user, resource, action);
    res.json({ ok: true, data: { role: req.user.role, resource, action, allowed } });
  } catch (err) { next(err); }
});

// POST /api/v1/rbac/grant — superadmin only
rbacRouter.post('/grant',
  authenticate,
  rbac.require('tenants', 'update'),  // only admins+
  validateBody(Joi.object({ role: Joi.string().required(), resource: Joi.string().required(), action: Joi.string().required() })),
  async (req, res, next) => {
    try {
      await rbac.grantPermission(req.body.role, req.body.resource, req.body.action, req.user.id);
      res.json({ ok: true, data: { message: `Permission ${req.body.resource}:${req.body.action} granted to ${req.body.role}` } });
    } catch (err) { next(err); }
  }
);

// ════════════════════════════════════════════════════════════
// CACHE (ADMIN)
// ════════════════════════════════════════════════════════════

const cacheRouter = express.Router();

cacheRouter.get('/stats', authenticate, rbac.require('cache', 'read'), async (req, res, next) => {
  try {
    const health = await redis.healthCheck();
    res.json({ ok: true, data: { redis: health } });
  } catch (err) { next(err); }
});

cacheRouter.post('/flush', authenticate, rbac.require('cache', 'flush'), async (req, res, next) => {
  try {
    const count = await redis.flushTenantCache(req.user.tenantId);
    await AuditService.log({ tenantId: req.user.tenantId, userId: req.user.id, type: 'system', severity: 'warning', action: 'CACHE_FLUSHED', metadata: { keysDeleted: count }, ipAddress: req.ip });
    res.json({ ok: true, data: { flushedKeys: count } });
  } catch (err) { next(err); }
});

// ════════════════════════════════════════════════════════════
// MOUNT
// ════════════════════════════════════════════════════════════

router.use('/tenants', tenantsRouter);
router.use('/users',   usersRouter);
router.use('/audit',   auditRouter);
router.use('/rbac',    rbacRouter);
router.use('/cache',   cacheRouter);
router.use('/auth',    require('./auth.routes'));

module.exports = router;
