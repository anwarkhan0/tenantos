/**
 * TenantOS — Main Entry Point
 *
 * Bootstraps in this order:
 *  1. Load secrets (AWS Secrets Manager or .env)
 *  2. Connect PostgreSQL pool
 *  3. Connect Redis
 *  4. Mount Express middleware + routes
 *  5. Start BullMQ-style job workers
 *  6. Start SSE stats broadcaster
 *  7. Serve static dashboard
 *  8. Listen on PORT
 *  9. Register graceful shutdown handlers
 */

'use strict';

require('dotenv').config();
require('express-async-errors');

const path         = require('path');
const express      = require('express');
const cors         = require('cors');
const helmet       = require('helmet');
const cookieParser = require('cookie-parser');

const logger    = require('./config/logger');
const db        = require('./config/database');
const redisClient = require('./config/redis');
const { loadSecretsFromAWS } = require('./config/aws');
const routes    = require('./routes');
const { globalRateLimit, requestLogger, errorHandler } = require('./middleware');

const app  = express();
const PORT = parseInt(process.env.PORT || '3000');
const API  = `/api/${process.env.API_VERSION || 'v1'}`;

// ── Trust proxy (for correct IP behind Nginx/ALB) ─────────────
app.set('trust proxy', 1);

// ── Security headers ──────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // disabled so dashboard loads external fonts
  crossOriginEmbedderPolicy: false,
}));

// ── CORS ──────────────────────────────────────────────────────
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',').map(s => s.trim());
app.use(cors({
  origin: (origin, cb) => {
    // Allow requests with no origin (curl, mobile apps, same-origin)
    if (!origin || allowedOrigins.includes(origin) || allowedOrigins.includes('*')) return cb(null, true);
    cb(new Error(`CORS: origin ${origin} not allowed`));
  },
  credentials:     true,
  methods:         ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders:  ['Content-Type', 'Authorization', 'X-Tenant-ID', 'X-API-Key'],
  exposedHeaders:  ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
}));

// ── Body parsing ──────────────────────────────────────────────
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(cookieParser(process.env.SESSION_SECRET));

// ── Request logging + global rate limit ───────────────────────
app.use(requestLogger);
app.use(globalRateLimit);

// ── Health probes (no auth — used by Docker/K8s) ─────────────
app.get('/health', async (req, res) => {
  try {
    const [dbHealth, redisHealth] = await Promise.all([
      db.healthCheck(),
      redisClient.healthCheck(),
    ]);
    res.json({
      status:    'healthy',
      uptime:    Math.floor(process.uptime()),
      version:   process.env.npm_package_version || '2.0.0',
      env:       process.env.NODE_ENV,
      timestamp: new Date().toISOString(),
      services:  { database: dbHealth, redis: redisHealth },
    });
  } catch (err) {
    res.status(503).json({ status: 'unhealthy', error: err.message });
  }
});

app.get('/ready', async (req, res) => {
  try {
    await db.query('SELECT 1');
    await redisClient.redis.ping();
    res.json({ status: 'ready' });
  } catch (err) {
    res.status(503).json({ status: 'not ready', error: err.message });
  }
});

// ── API routes ────────────────────────────────────────────────
app.use(API, routes);

// ── Serve dashboard (open public/dashboard.html in browser) ───
app.use(express.static(path.join(__dirname, '..', 'public')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'dashboard.html')));

// ── 404 ───────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ ok: false, error: `Cannot ${req.method} ${req.path}`, code: 'NOT_FOUND' });
});

// ── Global error handler ──────────────────────────────────────
app.use(errorHandler);

// ═════════════════════════════════════════════════════════════
// STARTUP
// ═════════════════════════════════════════════════════════════

async function start() {
  try {
    // 1. Load AWS secrets (no-op if ARN not set)
    await loadSecretsFromAWS();

    // 2. Verify PostgreSQL
    const dbStatus = await db.healthCheck();
    logger.info('PostgreSQL connected', { version: dbStatus.version, pool: dbStatus.pool });

    // 3. Verify Redis
    const redisStatus = await redisClient.healthCheck();
    logger.info('Redis connected', { version: redisStatus.version, latency: redisStatus.latency + 'ms' });

    // 4. Start job queue workers
    let QueueService;
    try {
      QueueService = require('./services/queue.service');
      QueueService.startAllWorkers();
      logger.info('Job queue workers started', { queues: Object.keys(QueueService.QUEUES) });
    } catch (err) {
      logger.warn('Queue workers failed to start', { error: err.message });
    }

    // 5. Start SSE stats broadcaster
    let RealtimeService;
    try {
      RealtimeService = require('./services/realtime.service');
      if (QueueService) {
        RealtimeService.startStatsbroadcast(QueueService.getAllQueueStats.bind(QueueService));
        logger.info('Real-time SSE broadcaster started (5s interval)');
      }
    } catch (err) {
      logger.warn('SSE broadcaster failed to start', { error: err.message });
    }

    // 6. HTTP server
    const server = app.listen(PORT, '0.0.0.0', () => {
      const banner = [
        '',
        '╔══════════════════════════════════════════════════════════════╗',
        '║              TenantOS v2.0 — Ready                          ║',
        '╠══════════════════════════════════════════════════════════════╣',
        `║  Dashboard  →  http://localhost:${PORT}${''.padEnd(28)}║`,
        `║  API Base   →  http://localhost:${PORT}${API}${''.padEnd(28 - API.length)}║`,
        `║  Health     →  http://localhost:${PORT}/health${''.padEnd(22)}║`,
        '╠══════════════════════════════════════════════════════════════╣',
        '║  Stack: Node.js · PostgreSQL · Redis · AWS · Docker         ║',
        '║                                                              ║',
        '║  Auth:   JWT (15m) + Refresh Rotation (7d)                  ║',
        '║  RBAC:   5 roles · DB-backed · Redis-cached                 ║',
        '║  MFA:    TOTP (RFC 6238) + backup codes                     ║',
        '║  Guard:  Brute-force · IP block · Token blacklist           ║',
        '║  Queue:  5 BullMQ-style workers with retry/DLQ              ║',
        '║  SSE:    Real-time audit + queue stats streaming             ║',
        '║  Webhooks: HMAC-signed · exponential backoff retry          ║',
        '╚══════════════════════════════════════════════════════════════╝',
        '',
        '  Open your browser → http://localhost:' + PORT,
        '  Login: alice@acme-corp.io  /  AliceAdmin@123',
        '  Tenant: a0000001-0000-0000-0000-000000000001',
        '',
      ].join('\n');

      if (process.env.NODE_ENV !== 'production') console.log(banner);
      logger.info('TenantOS server started', { port: PORT, env: process.env.NODE_ENV, api: API });
    });

    // 7. Graceful shutdown
    const shutdown = async (signal) => {
      logger.info(`${signal} received — shutting down gracefully`);
      server.close(async () => {
        if (QueueService)   QueueService.stopAllWorkers();
        if (RealtimeService) RealtimeService.stopStatsBroadcast();
        await db.pool.end().catch(() => {});
        await redisClient.redis.quit().catch(() => {});
        logger.info('Shutdown complete');
        process.exit(0);
      });
      // Force exit after 15s
      setTimeout(() => { logger.error('Forced shutdown after timeout'); process.exit(1); }, 15000);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT',  () => shutdown('SIGINT'));

    process.on('unhandledRejection', (reason) => {
      logger.error('Unhandled promise rejection', { reason: String(reason) });
    });

    process.on('uncaughtException', (err) => {
      logger.error('Uncaught exception', { error: err.message, stack: err.stack });
      process.exit(1);
    });

    return server;

  } catch (err) {
    logger.error('Startup failed', { error: err.message, stack: err.stack });
    process.exit(1);
  }
}

start();

module.exports = app; // for testing
