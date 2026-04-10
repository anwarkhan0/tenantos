/**
 * Extended Routes: MFA + Webhooks + Real-time SSE
 */

'use strict';

const express = require('express');
const Joi     = require('joi');
const router  = express.Router();

const { authenticate, validateBody, authRateLimit } = require('../middleware');
const rbac    = require('../services/rbac.service');
const MFA     = require('../services/mfa.service');
const Webhook = require('../services/webhook.service');
const RT      = require('../services/realtime.service');
const Queue   = require('../services/queue.service');

// ════════════════════════════════════════════════════════════
// MFA ROUTES  —  /api/v1/auth/mfa/*
// ════════════════════════════════════════════════════════════

const mfaRouter = express.Router();

// POST /api/v1/auth/mfa/setup — initiate setup, get QR code
mfaRouter.post('/setup', authenticate, async (req, res, next) => {
  try {
    const result = await MFA.setupMfa(req.user.id, req.user.tenantId);
    res.json({ ok: true, data: result });
  } catch (err) { next(err); }
});

// POST /api/v1/auth/mfa/confirm — verify first code, activate MFA
mfaRouter.post('/confirm',
  authenticate,
  authRateLimit,
  validateBody(Joi.object({ code: Joi.string().length(6).pattern(/^\d+$/).required() })),
  async (req, res, next) => {
    try {
      const result = await MFA.confirmMfa(req.user.id, req.user.tenantId, req.body.code, req.ip);
      res.json({ ok: true, data: result });
    } catch (err) { next(err); }
  }
);

// POST /api/v1/auth/mfa/verify — verify code during login step 2
mfaRouter.post('/verify',
  authenticate,
  authRateLimit,
  validateBody(Joi.object({ code: Joi.string().min(6).max(10).required() })),
  async (req, res, next) => {
    try {
      await MFA.verifyMfaCode(req.user.id, req.user.tenantId, req.body.code, req.ip);
      res.json({ ok: true, data: { verified: true } });
    } catch (err) { next(err); }
  }
);

// POST /api/v1/auth/mfa/disable
mfaRouter.post('/disable',
  authenticate,
  validateBody(Joi.object({ code: Joi.string().length(6).pattern(/^\d+$/).required() })),
  async (req, res, next) => {
    try {
      const result = await MFA.disableMfa(req.user.id, req.user.tenantId, req.body.code, req.ip);
      res.json({ ok: true, data: result });
    } catch (err) { next(err); }
  }
);

// POST /api/v1/auth/mfa/backup/regenerate
mfaRouter.post('/backup/regenerate',
  authenticate,
  validateBody(Joi.object({ code: Joi.string().min(6).max(10).required() })),
  async (req, res, next) => {
    try {
      const result = await MFA.regenerateBackupCodes(req.user.id, req.user.tenantId, req.body.code, req.ip);
      res.json({ ok: true, data: result });
    } catch (err) { next(err); }
  }
);

// ════════════════════════════════════════════════════════════
// WEBHOOK ROUTES  —  /api/v1/webhooks/*
// ════════════════════════════════════════════════════════════

const webhookRouter = express.Router();

// GET /api/v1/webhooks — list tenant's endpoints
webhookRouter.get('/', authenticate, async (req, res, next) => {
  try {
    const endpoints = await Webhook.listEndpoints(req.user.tenantId);
    res.json({ ok: true, data: { endpoints, total: endpoints.length } });
  } catch (err) { next(err); }
});

// GET /api/v1/webhooks/events — list available event types
webhookRouter.get('/events', authenticate, (req, res) => {
  res.json({ ok: true, data: { events: Webhook.WEBHOOK_EVENTS } });
});

// POST /api/v1/webhooks — register endpoint
webhookRouter.post('/',
  authenticate,
  rbac.require('auth', 'manage_api_keys'),
  validateBody(Joi.object({
    url:    Joi.string().uri({ scheme: ['http', 'https'] }).required(),
    events: Joi.array().items(Joi.string()).min(1).required(),
  })),
  async (req, res, next) => {
    try {
      const endpoint = await Webhook.registerEndpoint({
        tenantId:  req.user.tenantId,
        url:       req.body.url,
        events:    req.body.events,
        createdBy: req.user.id,
      });
      res.status(201).json({ ok: true, data: { endpoint } });
    } catch (err) { next(err); }
  }
);

// DELETE /api/v1/webhooks/:id
webhookRouter.delete('/:id', authenticate, rbac.require('auth', 'manage_api_keys'), async (req, res, next) => {
  try {
    await Webhook.deleteEndpoint(req.params.id, req.user.tenantId, req.user.id);
    res.json({ ok: true, data: { message: 'Webhook endpoint deleted' } });
  } catch (err) { next(err); }
});

// POST /api/v1/webhooks/:id/test — send test payload
webhookRouter.post('/:id/test', authenticate, async (req, res, next) => {
  try {
    await Webhook.dispatch(req.user.tenantId, 'auth.login', {
      test: true,
      message: 'This is a test webhook delivery',
      triggeredBy: req.user.email,
    });
    res.json({ ok: true, data: { message: 'Test webhook dispatched' } });
  } catch (err) { next(err); }
});

// ════════════════════════════════════════════════════════════
// REAL-TIME SSE  —  /api/v1/events/stream
// ════════════════════════════════════════════════════════════

const eventsRouter = express.Router();

// GET /api/v1/events/stream — SSE event stream
eventsRouter.get('/stream', RT.sseHandler);

// GET /api/v1/events/connections — admin view of active connections
eventsRouter.get('/connections', authenticate, rbac.require('audit', 'read'), (req, res) => {
  const tenantConns = RT.getConnectionsByTenant(req.user.tenantId);
  res.json({
    ok:   true,
    data: {
      total:       RT.getTotalConnections(),
      forTenant:   tenantConns.length,
      connections: tenantConns.map(c => ({
        socketId:     c.socketId,
        userId:       c.userId,
        subscriptions: c.subscriptions,
        connectedAt:  c.connectedAt,
      })),
    },
  });
});

// ════════════════════════════════════════════════════════════
// API KEYS  —  /api/v1/api-keys/*
// ════════════════════════════════════════════════════════════

const apiKeyService = require('../services/apikey.service');
const apiKeyRouter  = express.Router();

// GET /api/v1/api-keys
apiKeyRouter.get('/', authenticate, rbac.require('auth', 'manage_api_keys'), async (req, res, next) => {
  try {
    const keys = await apiKeyService.listApiKeys(req.user.tenantId, req.user.id);
    res.json({ ok: true, data: { keys, total: keys.length } });
  } catch (err) { next(err); }
});

// POST /api/v1/api-keys
apiKeyRouter.post('/',
  authenticate,
  rbac.require('auth', 'manage_api_keys'),
  validateBody(Joi.object({
    name:        Joi.string().min(2).max(100).required(),
    permissions: Joi.array().items(Joi.string()).default([]),
    expiresAt:   Joi.date().iso().min('now').optional(),
  })),
  async (req, res, next) => {
    try {
      const key = await apiKeyService.createApiKey({
        tenantId:    req.user.tenantId,
        userId:      req.user.id,
        name:        req.body.name,
        permissions: req.body.permissions,
        expiresAt:   req.body.expiresAt,
      });
      res.status(201).json({ ok: true, data: { key } });
    } catch (err) { next(err); }
  }
);

// DELETE /api/v1/api-keys/:id
apiKeyRouter.delete('/:id', authenticate, rbac.require('auth', 'manage_api_keys'), async (req, res, next) => {
  try {
    await apiKeyService.revokeApiKey(req.params.id, req.user.tenantId, req.user.id);
    res.json({ ok: true, data: { message: 'API key revoked' } });
  } catch (err) { next(err); }
});

// POST /api/v1/api-keys/:id/rotate
apiKeyRouter.post('/:id/rotate', authenticate, rbac.require('auth', 'manage_api_keys'), async (req, res, next) => {
  try {
    const key = await apiKeyService.rotateApiKey(req.params.id, req.user.tenantId, req.user.id);
    res.json({ ok: true, data: { key } });
  } catch (err) { next(err); }
});

// ════════════════════════════════════════════════════════════
// QUEUE ROUTES  —  /api/v1/jobs/*
// ════════════════════════════════════════════════════════════

const jobsRouter = express.Router();

// GET /api/v1/jobs/queues
jobsRouter.get('/queues', authenticate, rbac.require('jobs', 'read'), async (req, res, next) => {
  try {
    const stats = await Queue.getAllQueueStats();
    res.json({ ok: true, data: { queues: stats } });
  } catch (err) { next(err); }
});

// GET /api/v1/jobs/queues/:name
jobsRouter.get('/queues/:name', authenticate, rbac.require('jobs', 'read'), async (req, res, next) => {
  try {
    const stats = await Queue.getQueueStats(req.params.name);
    res.json({ ok: true, data: { queue: stats } });
  } catch (err) { next(err); }
});

// POST /api/v1/jobs/queues/:name — enqueue a job
jobsRouter.post('/queues/:name',
  authenticate,
  rbac.require('jobs', 'manage'),
  validateBody(Joi.object({
    name:     Joi.string().required(),
    data:     Joi.object().default({}),
    priority: Joi.number().integer().min(0).max(10).default(0),
    delay:    Joi.number().integer().min(0).default(0),
    retries:  Joi.number().integer().min(1).max(10).default(3),
  })),
  async (req, res, next) => {
    try {
      const job = await Queue.enqueue(
        req.params.name,
        req.body.name,
        req.body.data,
        { tenantId: req.user.tenantId, priority: req.body.priority, delay: req.body.delay, retries: req.body.retries }
      );
      res.status(201).json({ ok: true, data: { job } });
    } catch (err) { next(err); }
  }
);

// POST /api/v1/jobs/retry-failed
jobsRouter.post('/retry-failed', authenticate, rbac.require('jobs', 'manage'), async (req, res, next) => {
  try {
    const count = await Queue.retryAllFailed();
    res.json({ ok: true, data: { retriedCount: count } });
  } catch (err) { next(err); }
});

// GET /api/v1/jobs — list tenant's jobs
jobsRouter.get('/', authenticate, rbac.require('jobs', 'read'), async (req, res, next) => {
  try {
    const jobs = await Queue.getJobsByTenant(req.user.tenantId, {
      status:    req.query.status,
      queueName: req.query.queue,
      limit:     parseInt(req.query.limit || '20'),
      offset:    parseInt(req.query.offset || '0'),
    });
    res.json({ ok: true, data: { jobs, total: jobs.length } });
  } catch (err) { next(err); }
});

// ════════════════════════════════════════════════════════════
// TENANT STATS + USAGE  —  /api/v1/tenants/:id/stats
// ════════════════════════════════════════════════════════════

const tenantService = require('../services/tenant.service');
const statsRouter   = express.Router({ mergeParams: true });

statsRouter.get('/stats', authenticate, async (req, res, next) => {
  try {
    const tenantId = req.user.role === 'superadmin' ? req.params.tenantId : req.user.tenantId;
    const stats = await tenantService.getStats(tenantId);
    res.json({ ok: true, data: stats });
  } catch (err) { next(err); }
});

statsRouter.get('/usage', authenticate, async (req, res, next) => {
  try {
    const tenantId = req.user.role === 'superadmin' ? req.params.tenantId : req.user.tenantId;
    const days = parseInt(req.query.days || '30');
    const usage = await tenantService.getUsageHistory(tenantId, days);
    res.json({ ok: true, data: { usage, days } });
  } catch (err) { next(err); }
});

statsRouter.patch('/plan', authenticate, rbac.require('billing', 'manage'), async (req, res, next) => {
  try {
    const result = await tenantService.upgradePlan(
      req.user.tenantId, req.body.plan, req.user.id
    );
    res.json({ ok: true, data: { tenant: result } });
  } catch (err) { next(err); }
});

// Export all sub-routers
module.exports = { mfaRouter, webhookRouter, eventsRouter, apiKeyRouter, jobsRouter, statsRouter };
