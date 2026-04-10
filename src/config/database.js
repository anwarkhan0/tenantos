/**
 * PostgreSQL Connection Pool
 * Uses pg (node-postgres) with connection pooling
 * Supports multi-tenant schema switching
 */

const { Pool } = require('pg');
const logger = require('./logger');

const config = {
  host:     process.env.POSTGRES_HOST || 'localhost',
  port:     parseInt(process.env.POSTGRES_PORT || '5432'),
  database: process.env.POSTGRES_DB || 'tenantOS',
  user:     process.env.POSTGRES_USER || 'tenantOS_user',
  password: process.env.POSTGRES_PASSWORD,
  min:      parseInt(process.env.POSTGRES_POOL_MIN || '2'),
  max:      parseInt(process.env.POSTGRES_POOL_MAX || '20'),
  idleTimeoutMillis:    30000,
  connectionTimeoutMillis: 5000,
  statement_timeout:    30000,
  ...(process.env.POSTGRES_SSL === 'true' && {
    ssl: { rejectUnauthorized: true }
  }),
};

const pool = new Pool(config);

pool.on('connect', (client) => {
  logger.debug('PostgreSQL: new client connected', {
    totalCount: pool.totalCount,
    idleCount:  pool.idleCount,
    waitingCount: pool.waitingCount,
  });
});

pool.on('error', (err) => {
  logger.error('PostgreSQL pool error:', { error: err.message });
});

pool.on('remove', () => {
  logger.debug('PostgreSQL: client removed from pool');
});

/**
 * Execute a query with automatic connection management
 */
async function query(text, params) {
  const start = Date.now();
  try {
    const result = await pool.query(text, params);
    const duration = Date.now() - start;
    if (duration > 1000) {
      logger.warn('Slow query detected', { text: text.slice(0, 100), duration });
    }
    return result;
  } catch (err) {
    logger.error('Query error', { text: text.slice(0, 100), error: err.message });
    throw err;
  }
}

/**
 * Get a client from the pool for transactions
 */
async function getClient() {
  const client = await pool.connect();
  const originalQuery = client.query.bind(client);
  const originalRelease = client.release.bind(client);
  const timeout = setTimeout(() => {
    logger.error('Client checked out too long — potential leak');
    client.release();
  }, 10000);

  client.query = (...args) => originalQuery(...args);
  client.release = (err) => {
    clearTimeout(timeout);
    client.query = originalQuery;
    client.release = originalRelease;
    return originalRelease(err);
  };
  return client;
}

/**
 * Run multiple operations in a transaction
 */
async function withTransaction(fn) {
  const client = await getClient();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Health check
 */
async function healthCheck() {
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT version(), NOW() as ts');
    return {
      status: 'healthy',
      version: result.rows[0].version.split(' ')[1],
      serverTime: result.rows[0].ts,
      pool: {
        total:   pool.totalCount,
        idle:    pool.idleCount,
        waiting: pool.waitingCount,
      },
    };
  } finally {
    client.release();
  }
}

module.exports = { query, getClient, withTransaction, healthCheck, pool };
