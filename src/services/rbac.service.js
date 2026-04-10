/**
 * RBAC Service — Role-Based Access Control
 *
 * Permission model:
 *   role → role_permissions → permissions (resource + action)
 *
 * Permissions are cached in Redis (TTL 1h) to avoid DB hits on every request.
 * Cache is invalidated when role permissions are updated.
 *
 * Usage:
 *   await rbac.can(user, 'users', 'create')      → true/false
 *   rbac.require('users', 'create')               → Express middleware
 */

const db     = require('../config/database');
const redis  = require('../config/redis');
const logger = require('../config/logger');
const AuditService = require('./audit.service');

// ─── PERMISSION LOADING ───────────────────────────────────────

/**
 * Load all permissions for a role from DB (or Redis cache).
 * Returns Set of "resource:action" strings for O(1) lookup.
 */
async function getPermissionsForRole(role) {
  // 1. Try Redis cache
  const cached = await redis.getCachedPermissions(role);
  if (cached) {
    logger.debug('RBAC: permissions from cache', { role, count: cached.length });
    return new Set(cached);
  }

  // 2. Load from PostgreSQL
  const result = await db.query(
    `SELECT p.resource, p.action
     FROM role_permissions rp
     JOIN permissions p ON p.id = rp.permission_id
     WHERE rp.role = $1`,
    [role]
  );

  const perms = result.rows.map(r => `${r.resource}:${r.action}`);
  logger.debug('RBAC: permissions from DB', { role, count: perms.length });

  // 3. Cache in Redis
  await redis.cachePermissions(role, perms);

  return new Set(perms);
}

// ─── PERMISSION CHECK ─────────────────────────────────────────

/**
 * Check if a user has a specific permission.
 * Superadmin always returns true.
 */
async function can(user, resource, action) {
  if (!user) return false;

  // Superadmin bypass
  if (user.role === 'superadmin') return true;

  const perms = await getPermissionsForRole(user.role);
  return perms.has(`${resource}:${action}`);
}

/**
 * Check multiple permissions at once (AND logic).
 */
async function canAll(user, checks) {
  if (user?.role === 'superadmin') return true;
  const perms = await getPermissionsForRole(user.role);
  return checks.every(({ resource, action }) => perms.has(`${resource}:${action}`));
}

/**
 * Check if user has at least one permission (OR logic).
 */
async function canAny(user, checks) {
  if (user?.role === 'superadmin') return true;
  const perms = await getPermissionsForRole(user.role);
  return checks.some(({ resource, action }) => perms.has(`${resource}:${action}`));
}

// ─── MIDDLEWARE FACTORY ───────────────────────────────────────

/**
 * Express middleware that enforces a permission.
 *
 * Usage:
 *   router.post('/users', rbac.require('users', 'create'), handler)
 *   router.get('/audit',  rbac.require('audit', 'read'),   handler)
 */
function require(resource, action) {
  return async (req, res, next) => {
    try {
      const user = req.user;
      if (!user) {
        return res.status(401).json({ ok: false, error: 'Authentication required' });
      }

      const allowed = await can(user, resource, action);
      if (!allowed) {
        // Audit denied access
        await AuditService.log({
          tenantId:  user.tenantId,
          userId:    user.id,
          type:      'permission',
          severity:  'warning',
          action:    'ACCESS_DENIED',
          resource:  `${resource}:${action}`,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          metadata:  { path: req.path, method: req.method, role: user.role }
        });

        return res.status(403).json({
          ok:    false,
          error: 'Insufficient permissions',
          code:  'FORBIDDEN',
          required: { resource, action },
          yourRole: user.role,
        });
      }

      next();
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Require any one of multiple permissions.
 */
function requireAny(...checks) {
  return async (req, res, next) => {
    try {
      const user = req.user;
      if (!user) return res.status(401).json({ ok: false, error: 'Authentication required' });

      const allowed = await canAny(user, checks.map(c =>
        typeof c === 'string' ? { resource: c.split(':')[0], action: c.split(':')[1] } : c
      ));

      if (!allowed) {
        return res.status(403).json({ ok: false, error: 'Insufficient permissions', code: 'FORBIDDEN' });
      }

      next();
    } catch (err) {
      next(err);
    }
  };
}

// ─── ROLE MANAGEMENT ─────────────────────────────────────────

async function getAllPermissions() {
  const result = await db.query(
    `SELECT p.id, p.resource, p.action, p.description,
            array_agg(rp.role ORDER BY rp.role) FILTER (WHERE rp.role IS NOT NULL) as roles
     FROM permissions p
     LEFT JOIN role_permissions rp ON rp.permission_id = p.id
     GROUP BY p.id, p.resource, p.action, p.description
     ORDER BY p.resource, p.action`
  );
  return result.rows;
}

async function getRoleMatrix() {
  const roles = ['superadmin', 'admin', 'developer', 'analyst', 'viewer'];
  const matrix = {};
  for (const role of roles) {
    const perms = await getPermissionsForRole(role);
    matrix[role] = Array.from(perms);
  }
  return matrix;
}

async function grantPermission(role, resource, action, grantedBy) {
  const permResult = await db.query(
    'SELECT id FROM permissions WHERE resource = $1 AND action = $2',
    [resource, action]
  );
  if (!permResult.rows[0]) throw new Error(`Permission ${resource}:${action} not found`);

  const permId = permResult.rows[0].id;

  await db.query(
    `INSERT INTO role_permissions (role, permission_id, granted_by)
     VALUES ($1, $2, $3)
     ON CONFLICT (role, permission_id) DO NOTHING`,
    [role, permId, grantedBy]
  );

  // Invalidate Redis cache for this role
  await redis.redis.del(redis.KEYS.permissions(role));

  await AuditService.log({
    userId: grantedBy, type: 'permission', severity: 'warning',
    action: 'PERMISSION_GRANTED',
    metadata: { role, resource, action }
  });
}

async function revokePermission(role, resource, action, revokedBy) {
  if (role === 'superadmin') {
    throw new Error('Cannot revoke permissions from superadmin');
  }

  const permResult = await db.query(
    'SELECT id FROM permissions WHERE resource = $1 AND action = $2',
    [resource, action]
  );
  if (!permResult.rows[0]) throw new Error(`Permission ${resource}:${action} not found`);

  await db.query(
    'DELETE FROM role_permissions WHERE role = $1 AND permission_id = $2',
    [role, permResult.rows[0].id]
  );

  await redis.redis.del(redis.KEYS.permissions(role));

  await AuditService.log({
    userId: revokedBy, type: 'permission', severity: 'warning',
    action: 'PERMISSION_REVOKED',
    metadata: { role, resource, action }
  });
}

/**
 * Change a user's role (with audit trail)
 */
async function changeUserRole(targetUserId, newRole, changedBy, tenantId) {
  const validRoles = ['admin', 'developer', 'analyst', 'viewer'];
  if (!validRoles.includes(newRole)) {
    throw Object.assign(new Error(`Invalid role: ${newRole}`), { status: 400 });
  }

  const result = await db.query(
    `UPDATE users SET role = $1, updated_at = NOW()
     WHERE id = $2 AND tenant_id = $3
     RETURNING id, email, role`,
    [newRole, targetUserId, tenantId]
  );

  if (!result.rows[0]) throw Object.assign(new Error('User not found'), { status: 404 });

  await AuditService.log({
    tenantId, userId: changedBy, type: 'user', severity: 'warning',
    action: 'ROLE_CHANGED', resourceId: targetUserId,
    metadata: { targetUserId, newRole, changedBy }
  });

  return result.rows[0];
}

module.exports = {
  can, canAll, canAny,
  require, requireAny,
  getAllPermissions, getRoleMatrix,
  grantPermission, revokePermission, changeUserRole,
  getPermissionsForRole,
};
