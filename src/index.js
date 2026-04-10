/**
 * TenantOS — Multi-Tenant SaaS Backend
 * Entry point: Express app setup + server bootstrap
 */

require('dotenv').config();
require('express-async-errors');

const express = require('express');
const cors    = require('cors');
const helmet  = require('helmet');
const cookieParser = require('cookie-parser');

const logger   = require('./config/logger');
const db       = require('./config/database');
const redis    = require('./config/redis');
const { loadSecretsFromAWS } = require('./config/aws');
const routes   = require('./routes');
const {
  globalRateLimit, requestLogger, errorHandler,
} = require('./middleware');

const app  = express();
const PORT = parseInt(process.env.PORT || '3000');
const API  = `/api/${process.env.API_VERSION || 'v1'}`;

// ─── SECURITY MIDDLEWARE ──────────────────────────────────────

app.set('trust proxy', 1);  // trust first proxy (ALB/NGINX)

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      scriptSrc:  ["'self'"],
      imgSrc:     ["'self'", 'data:', 'https:'],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:5173', 'http://localhost:3001'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID'],
  exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
}));

// ─── BODY PARSING ─────────────────────────────────────────────

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser(process.env.SESSION_SECRET));

// ─── REQUEST LOGGING ─────────────────────────────────────────

app.use(requestLogger);
app.use(globalRateLimit);

// ─── HEALTH ENDPOINTS (no auth) ───────────────────────────────

app.get('/health', async (req, res) => {
  try {
    const [dbHealth, redisHealth] = await Promise.all([
      db.healthCheck(),
      redis.healthCheck(),
    ]);

    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '2.0.0',
      services: { database: dbHealth, redis: redisHealth },
      memory: process.memoryUsage(),
    });
  } catch (err) {
    res.status(503).json({
      status: 'unhealthy',
      error: err.message,
      timestamp: new Date().toISOString(),
    });
  }
});

app.get('/ready', async (req, res) => {
  try {
    await db.query('SELECT 1');
    await redis.redis.ping();
    res.json({ status: 'ready' });
  } catch {
    res.status(503).json({ status: 'not ready' });
  }
});

// ─── API ROUTES ───────────────────────────────────────────────

app.use(API, routes);

// ─── 404 ──────────────────────────────────────────────────────

app.use((req, res) => {
  res.status(404).json({
    ok:    false,
    error: `Cannot ${req.method} ${req.path}`,
    code:  'NOT_FOUND',
  });
});

// ─── ERROR HANDLER ────────────────────────────────────────────

app.use(errorHandler);

// ─── STARTUP ─────────────────────────────────────────────────

async function start() {
  try {
    // 1. Load secrets from AWS Secrets Manager (if configured)
    await loadSecretsFromAWS();

    // 2. Verify database connection
    const dbStatus = await db.healthCheck();
    logger.info('Database connected', {
      version: dbStatus.version,
      pool: dbStatus.pool,
    });

    // 3. Verify Redis connection
    const redisStatus = await redis.healthCheck();
    logger.info('Redis connected', {
      version: redisStatus.version,
      memory:  redisStatus.memory,
      latency: redisStatus.latency + 'ms',
    });

    // 4. Start HTTP server
    const server = app.listen(PORT, '0.0.0.0', () => {
      logger.info(`TenantOS API running`, {
        port:    PORT,
        env:     process.env.NODE_ENV,
        apiBase: API,
      });

      if (process.env.NODE_ENV === 'development') {
        console.log(`
╔══════════════════════════════════════════════════════════╗
║           TenantOS Backend v2.0  —  Node.js              ║
╠══════════════════════════════════════════════════════════╣
║  API     →  http://localhost:${PORT}${API.padEnd(30-API.length)}║
║  Health  →  http://localhost:${PORT}/health${' '.repeat(26)}║
╠══════════════════════════════════════════════════════════╣
║  Stack: Node.js • PostgreSQL • Redis • AWS • Docker      ║
║  Auth:  JWT (15m) + Refresh Rotation (7d)                ║
║  RBAC:  5 roles • DB-backed permissions                  ║
║  Guard: Brute-force • IP blocking • Token blacklist      ║
╚══════════════════════════════════════════════════════════╝`);
      }
    });

    // 5. Graceful shutdown
    const shutdown = async (signal) => {
      logger.info(`${signal} received, shutting down gracefully`);
      server.close(async () => {
        await db.pool.end();
        await redis.redis.quit();
        logger.info('Server shut down cleanly');
        process.exit(0);
      });
      setTimeout(() => process.exit(1), 15000); // force after 15s
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT',  () => shutdown('SIGINT'));

    process.on('unhandledRejection', (reason) => {
      logger.error('Unhandled rejection', { reason });
    });

    return server;

  } catch (err) {
    logger.error('Startup failed', { error: err.message, stack: err.stack });
    process.exit(1);
  }
}

start();

module.exports = app;
