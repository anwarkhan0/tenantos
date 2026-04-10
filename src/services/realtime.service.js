/**
 * WebSocket Server — Real-Time Event Streaming
 *
 * Streams live events to connected dashboard clients:
 *  - Audit log entries as they're written
 *  - Queue stats every 5 seconds
 *  - Security alerts (brute force, token reuse, lockouts)
 *  - Session activity
 *
 * Auth: JWT Bearer token in query string or Upgrade header.
 * Tenant-isolated: each connection only receives its tenant's events.
 *
 * Uses Node.js built-in net + HTTP upgrade (no ws package needed).
 * In production: add the `ws` package for production-grade WebSocket.
 */

'use strict';

const crypto = require('crypto');
const jwt    = require('jsonwebtoken');
const redis  = require('../config/redis');
const logger = require('../config/logger');

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'change-me-in-production';

// ─── CONNECTION REGISTRY ─────────────────────────────────────

const connections = new Map(); // socketId → { socket, tenantId, userId, role, subscriptions }

function addConnection(socketId, meta) {
  connections.set(socketId, { ...meta, socketId, connectedAt: Date.now() });
}

function removeConnection(socketId) {
  connections.delete(socketId);
}

function getConnectionsByTenant(tenantId) {
  return [...connections.values()].filter(c => c.tenantId === tenantId);
}

function getTotalConnections() {
  return connections.size;
}

// ─── AUTHENTICATION ───────────────────────────────────────────

function authenticateWsToken(token) {
  if (!token) return null;
  try {
    const decoded = jwt.verify(token, ACCESS_SECRET, { issuer: 'tenantOS' });
    return { userId: decoded.sub, tenantId: decoded.tenantId, role: decoded.role, jti: decoded.jti };
  } catch { return null; }
}

// ─── EVENT EMITTER ────────────────────────────────────────────

/**
 * Emit a real-time event to all connections for a specific tenant.
 * Optionally filter by subscription type.
 */
function emitToTenant(tenantId, event) {
  const tenantConnections = getConnectionsByTenant(tenantId);
  const payload = JSON.stringify({ ...event, timestamp: new Date().toISOString() });
  let sent = 0;

  for (const conn of tenantConnections) {
    if (!conn.subscriptions || conn.subscriptions.includes(event.type) || conn.subscriptions.includes('*')) {
      try {
        if (conn.send) {
          conn.send(payload);
          sent++;
        }
      } catch (err) {
        logger.warn('WS send error', { socketId: conn.socketId, error: err.message });
        removeConnection(conn.socketId);
      }
    }
  }

  return sent;
}

/**
 * Emit to a specific user only (e.g., session alert).
 */
function emitToUser(userId, event) {
  const payload = JSON.stringify({ ...event, timestamp: new Date().toISOString() });
  let sent = 0;

  for (const [, conn] of connections) {
    if (conn.userId === userId) {
      try {
        if (conn.send) { conn.send(payload); sent++; }
      } catch { removeConnection(conn.socketId); }
    }
  }

  return sent;
}

/**
 * Emit to all superadmin connections.
 */
function emitToSuperadmins(event) {
  const payload = JSON.stringify({ ...event, timestamp: new Date().toISOString() });
  for (const [, conn] of connections) {
    if (conn.role === 'superadmin' && conn.send) {
      try { conn.send(payload); } catch { removeConnection(conn.socketId); }
    }
  }
}

// ─── MANUAL HTTP SSE FALLBACK ─────────────────────────────────
// Server-Sent Events: works without WebSocket lib, browser-native.

/**
 * SSE endpoint handler.
 * GET /api/v1/events/stream
 * Requires: Authorization: Bearer <token>
 */
function sseHandler(req, res) {
  // Auth
  const token   = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
  const user    = authenticateWsToken(token);

  if (!user) {
    res.status(401).json({ ok: false, error: 'Unauthorized' });
    return;
  }

  // SSE headers
  res.setHeader('Content-Type',  'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection',    'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no'); // disable Nginx buffering
  res.flushHeaders();

  const socketId = crypto.randomUUID();
  const subscriptions = (req.query.subscribe || '*').split(',');

  // Register connection
  addConnection(socketId, {
    send:          (data) => res.write(`data: ${data}\n\n`),
    tenantId:      user.tenantId,
    userId:        user.userId,
    role:          user.role,
    subscriptions,
  });

  // Send welcome event
  res.write(`data: ${JSON.stringify({
    type:     'connected',
    socketId,
    tenantId: user.tenantId,
    subscriptions,
    message:  'Real-time event stream connected',
  })}\n\n`);

  // Heartbeat every 30s to keep connection alive through proxies
  const heartbeat = setInterval(() => {
    try { res.write(': ping\n\n'); }
    catch { clearInterval(heartbeat); removeConnection(socketId); }
  }, 30000);

  // Cleanup on disconnect
  req.on('close', () => {
    clearInterval(heartbeat);
    removeConnection(socketId);
    logger.debug('SSE client disconnected', { socketId, tenantId: user.tenantId });
  });

  logger.info('SSE client connected', {
    socketId, tenantId: user.tenantId,
    userId: user.userId, subscriptions,
  });
}

// ─── EVENT TYPES ─────────────────────────────────────────────

const EventTypes = {
  // Auth events
  LOGIN:              'auth.login',
  LOGOUT:             'auth.logout',
  TOKEN_REUSE:        'security.token_reuse',
  BRUTE_FORCE:        'security.brute_force',
  ACCOUNT_LOCKED:     'security.account_locked',
  MFA_ENABLED:        'auth.mfa_enabled',

  // Queue events
  QUEUE_STATS:        'queue.stats',
  JOB_COMPLETED:      'job.completed',
  JOB_FAILED:         'job.failed',

  // Audit events
  AUDIT_ENTRY:        'audit.entry',

  // Cache events
  CACHE_FLUSHED:      'cache.flushed',

  // System events
  CONNECTED:          'connected',
  STATS_UPDATE:       'stats.update',
};

// ─── PERIODIC STATS BROADCAST ────────────────────────────────

let statsInterval = null;

async function startStatsbroadcast(getQueueStats) {
  if (statsInterval) return;

  statsInterval = setInterval(async () => {
    if (connections.size === 0) return;

    try {
      const queueStats  = await getQueueStats();
      const cacheHealth = await redis.healthCheck().catch(() => ({}));

      // Broadcast to all connected tenants
      const tenantIds = new Set([...connections.values()].map(c => c.tenantId));
      for (const tenantId of tenantIds) {
        emitToTenant(tenantId, {
          type:  EventTypes.QUEUE_STATS,
          queues: queueStats,
          cache:  cacheHealth,
          connections: getConnectionsByTenant(tenantId).length,
        });
      }
    } catch (err) {
      logger.warn('Stats broadcast error', { error: err.message });
    }
  }, 5000);

  logger.info('Real-time stats broadcast started (5s interval)');
}

function stopStatsBroadcast() {
  if (statsInterval) { clearInterval(statsInterval); statsInterval = null; }
}

// ─── AUDIT LOG HOOK ──────────────────────────────────────────

/**
 * Called by AuditService after each log write.
 * Pushes the event to all connected clients in real-time.
 */
function onAuditEvent(entry) {
  if (!entry?.tenantId) return;

  emitToTenant(entry.tenantId, {
    type:      EventTypes.AUDIT_ENTRY,
    entry: {
      id:        entry.id,
      type:      entry.type,
      severity:  entry.severity,
      action:    entry.action,
      tenantId:  entry.tenantId,
      ipAddress: entry.ipAddress,
      createdAt: entry.createdAt,
    },
  });

  // Security events: also notify superadmins
  if (entry.severity === 'critical') {
    emitToSuperadmins({ type: 'security.critical', entry });
  }
}

module.exports = {
  sseHandler,
  emitToTenant, emitToUser, emitToSuperadmins,
  addConnection, removeConnection,
  getTotalConnections, getConnectionsByTenant,
  startStatsbroadcast, stopStatsBroadcast,
  onAuditEvent,
  EventTypes,
};
