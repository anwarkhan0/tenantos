/**
 * Audit Service — Immutable Event Log
 *
 * All auth, security, and data-change events are written here.
 * Stored in PostgreSQL (primary) and shipped to CloudWatch Logs.
 * Events are never updated or deleted.
 */

const db     = require('../config/database');
const logger = require('../config/logger');
const { Metrics } = require('../config/aws');

/**
 * Write an audit event.
 * Non-blocking — failures are logged but not thrown.
 */
async function log({
  tenantId   = null,
  userId     = null,
  type       = 'system',
  severity   = 'info',
  action,
  resource   = null,
  resourceId = null,
  ipAddress  = null,
  userAgent  = null,
  beforeData = null,
  afterData  = null,
  metadata   = {},
}) {
  try {
    const result = await db.query(
      `INSERT INTO audit_logs
        (tenant_id, user_id, type, severity, action, resource, resource_id,
         ip_address, user_agent, before_data, after_data, metadata)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       RETURNING id, created_at`,
      [
        tenantId, userId, type, severity, action, resource, resourceId,
        ipAddress, userAgent,
        beforeData ? JSON.stringify(beforeData) : null,
        afterData  ? JSON.stringify(afterData)  : null,
        JSON.stringify(metadata),
      ]
    );

    const entry = result.rows[0];

    // Structured log → picked up by CloudWatch
    logger[severity === 'critical' ? 'warn' : severity === 'warning' ? 'warn' : 'info']('AUDIT', {
      auditId:   entry.id,
      tenantId, userId, type, severity, action, resource,
      ipAddress, metadata,
    });

    // Emit CloudWatch metric for critical events
    if (severity === 'critical') {
      Metrics.bruteForceBlock(ipAddress || 'unknown');
    }

    return entry;
  } catch (err) {
    // Never let audit failures break the main flow
    logger.error('Audit log write failed', { error: err.message, action });
    return null;
  }
}

/**
 * Query audit logs with filtering and pagination.
 */
async function query({
  tenantId,
  userId,
  type,
  severity,
  action,
  from,
  to,
  limit = 50,
  offset = 0,
}) {
  const conditions = ['1=1'];
  const params = [];
  let i = 1;

  if (tenantId) { conditions.push(`tenant_id = $${i++}`); params.push(tenantId); }
  if (userId)   { conditions.push(`user_id = $${i++}`);   params.push(userId); }
  if (type)     { conditions.push(`type = $${i++}`);      params.push(type); }
  if (severity) { conditions.push(`severity = $${i++}`);  params.push(severity); }
  if (action)   { conditions.push(`action ILIKE $${i++}`);params.push(`%${action}%`); }
  if (from)     { conditions.push(`created_at >= $${i++}`);params.push(from); }
  if (to)       { conditions.push(`created_at <= $${i++}`);params.push(to); }

  params.push(Math.min(limit, 200));
  params.push(offset);

  const whereClause = conditions.join(' AND ');

  const [dataRes, countRes] = await Promise.all([
    db.query(
      `SELECT al.*, u.email as user_email
       FROM audit_logs al
       LEFT JOIN users u ON u.id = al.user_id
       WHERE ${whereClause}
       ORDER BY al.created_at DESC
       LIMIT $${i} OFFSET $${i + 1}`,
      params
    ),
    db.query(`SELECT COUNT(*) FROM audit_logs WHERE ${whereClause}`, params.slice(0, -2)),
  ]);

  return {
    logs:  dataRes.rows,
    total: parseInt(countRes.rows[0].count),
    limit,
    offset,
  };
}

/**
 * Get security summary for a tenant.
 */
async function getSecuritySummary(tenantId, days = 7) {
  const result = await db.query(
    `SELECT
       COUNT(*) FILTER (WHERE type = 'auth' AND action = 'LOGIN_FAILED')    as failed_logins,
       COUNT(*) FILTER (WHERE type = 'auth' AND action = 'LOGIN_SUCCESS')   as successful_logins,
       COUNT(*) FILTER (WHERE type = 'security')                            as security_events,
       COUNT(*) FILTER (WHERE severity = 'critical')                        as critical_events,
       COUNT(*) FILTER (WHERE action = 'REFRESH_TOKEN_REUSE')               as token_reuse_events,
       COUNT(*) FILTER (WHERE action LIKE '%LOCKED%')                       as lockout_events
     FROM audit_logs
     WHERE tenant_id = $1
       AND created_at > NOW() - INTERVAL '${days} days'`,
    [tenantId]
  );
  return result.rows[0];
}

/**
 * Export audit logs as CSV string.
 */
async function exportToCsv(tenantId, from, to) {
  const { logs } = await query({ tenantId, from, to, limit: 10000, offset: 0 });

  const headers = ['ID', 'Type', 'Severity', 'Action', 'User', 'IP', 'Resource', 'Created At'];
  const rows = logs.map(l => [
    l.id, l.type, l.severity, l.action,
    l.user_email || '', l.ip_address || '',
    l.resource || '', l.created_at,
  ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(','));

  return [headers.join(','), ...rows].join('\n');
}

module.exports = { log, query, getSecuritySummary, exportToCsv };
