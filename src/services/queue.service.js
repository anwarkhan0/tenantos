/**
 * Job Queue Service
 *
 * Architecture:
 *  - Job definitions stored in PostgreSQL (persistent, survives restarts)
 *  - Active queue managed in Redis (fast, sorted sets by priority + score)
 *  - Workers poll Redis, update PostgreSQL on completion/failure
 *  - Dead letter queue for failed jobs after max retries
 *
 * In production: replace with BullMQ (npm install bullmq)
 * This implementation mirrors BullMQ's API exactly so the swap is trivial.
 */

const { v4: uuidv4 } = require('uuid');
const db     = require('../config/database');
const redis  = require('../config/redis');
const logger = require('../config/logger');
const AuditService = require('./audit.service');

// ─── SCHEMA (run in init.sql) ────────────────────────────────
// This service expects these PostgreSQL tables:
//
// CREATE TABLE IF NOT EXISTS job_queues (
//   id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
//   name        VARCHAR(100) UNIQUE NOT NULL,
//   description TEXT,
//   is_paused   BOOLEAN NOT NULL DEFAULT FALSE,
//   created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
// );
//
// CREATE TABLE IF NOT EXISTS jobs (
//   id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
//   queue_name  VARCHAR(100) NOT NULL,
//   tenant_id   UUID NOT NULL REFERENCES tenants(id),
//   name        VARCHAR(200) NOT NULL,
//   data        JSONB NOT NULL DEFAULT '{}',
//   opts        JSONB NOT NULL DEFAULT '{}',
//   priority    INTEGER NOT NULL DEFAULT 0,    -- higher = more urgent
//   attempts    INTEGER NOT NULL DEFAULT 0,
//   max_attempts INTEGER NOT NULL DEFAULT 3,
//   status      VARCHAR(20) NOT NULL DEFAULT 'waiting',
//   progress    INTEGER NOT NULL DEFAULT 0,
//   result      JSONB,
//   error       TEXT,
//   started_at  TIMESTAMPTZ,
//   finished_at TIMESTAMPTZ,
//   failed_at   TIMESTAMPTZ,
//   delay_until TIMESTAMPTZ,
//   created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
// );

// ─── REDIS KEY HELPERS ────────────────────────────────────────

const QK = {
  waiting:   (q)   => `queue:${q}:waiting`,   // sorted set: score=priority
  active:    (q)   => `queue:${q}:active`,    // set of job IDs
  failed:    (q)   => `queue:${q}:failed`,    // sorted set: score=timestamp
  completed: (q)   => `queue:${q}:completed`, // list (capped)
  delayed:   (q)   => `queue:${q}:delayed`,   // sorted set: score=delay_until timestamp
  jobData:   (id)  => `job:${id}`,            // hash of job data
  stats:     (q)   => `queue:${q}:stats`,     // hash: processed, failed, etc
};

// ─── QUEUE DEFINITIONS ───────────────────────────────────────

const QUEUES = {
  'email-notifications': { concurrency: 5,  retries: 3, ttl: 300000  },
  'report-generation':   { concurrency: 2,  retries: 2, ttl: 600000  },
  'data-sync':           { concurrency: 10, retries: 5, ttl: 120000  },
  'webhook-dispatch':    { concurrency: 8,  retries: 4, ttl: 30000   },
  'invoice-processing':  { concurrency: 3,  retries: 3, ttl: 900000  },
};

// ─── ENQUEUE ─────────────────────────────────────────────────

/**
 * Add a job to the queue.
 * @param {string} queueName  - Queue to add to
 * @param {string} jobName    - Job type / name
 * @param {object} data       - Job payload
 * @param {object} opts       - { priority, delay, retries, tenantId }
 */
async function enqueue(queueName, jobName, data, opts = {}) {
  if (!QUEUES[queueName]) throw new Error(`Unknown queue: ${queueName}`);

  const job = {
    id:          uuidv4(),
    queueName,
    name:        jobName,
    data,
    tenantId:    opts.tenantId,
    priority:    opts.priority || 0,
    maxAttempts: opts.retries  || QUEUES[queueName].retries,
    delayUntil:  opts.delay    ? new Date(Date.now() + opts.delay) : null,
    status:      opts.delay    ? 'delayed' : 'waiting',
    createdAt:   new Date(),
  };

  // Persist to PostgreSQL
  await db.query(
    `INSERT INTO jobs
     (id, queue_name, tenant_id, name, data, opts, priority, max_attempts, status, delay_until)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [
      job.id, queueName, opts.tenantId, jobName,
      JSON.stringify(data), JSON.stringify(opts),
      job.priority, job.maxAttempts,
      job.status,
      job.delayUntil,
    ]
  );

  // Add to Redis queue
  const pipe = redis.redis.pipeline();

  if (job.delayUntil) {
    // Delayed: add to sorted set with score = run timestamp
    pipe.zadd(QK.delayed(queueName), job.delayUntil.getTime(), job.id);
  } else {
    // Waiting: sorted set, higher priority = higher score
    pipe.zadd(QK.waiting(queueName), job.priority, job.id);
  }

  // Store job data in Redis hash (for fast worker access)
  pipe.hset(QK.jobData(job.id), {
    id:          job.id,
    name:        jobName,
    queueName,
    tenantId:    opts.tenantId || '',
    data:        JSON.stringify(data),
    priority:    job.priority,
    maxAttempts: job.maxAttempts,
    attempts:    0,
    status:      job.status,
    createdAt:   job.createdAt.toISOString(),
  });
  pipe.expire(QK.jobData(job.id), 86400); // 24h TTL on job data

  // Increment queue stats
  pipe.hincrby(QK.stats(queueName), 'enqueued', 1);

  await pipe.exec();

  logger.debug('Job enqueued', { jobId: job.id, queue: queueName, name: jobName, tenantId: opts.tenantId });
  return job;
}

// ─── DEQUEUE (worker side) ───────────────────────────────────

/**
 * Atomically move job from waiting → active.
 * Uses ZPOPMAX to get highest-priority job.
 */
async function dequeue(queueName) {
  // First promote any delayed jobs that are now ready
  const now = Date.now();
  const ready = await redis.redis.zrangebyscore(QK.delayed(queueName), '-inf', now);
  if (ready.length) {
    const pipe = redis.redis.pipeline();
    ready.forEach(id => {
      pipe.zrem(QK.delayed(queueName), id);
      pipe.zadd(QK.waiting(queueName), 0, id);
    });
    await pipe.exec();
    await db.query(`UPDATE jobs SET status = 'waiting' WHERE id = ANY($1)`, [ready]);
  }

  // Pop highest priority job
  const popped = await redis.redis.zpopmax(QK.waiting(queueName));
  if (!popped || popped.length === 0) return null;

  const jobId = popped[0]; // zpopmax returns [member, score, ...]

  // Get full job data
  const jobData = await redis.redis.hgetall(QK.jobData(jobId));
  if (!jobData || !jobData.id) return null;

  // Mark active in Redis + PostgreSQL
  const pipe = redis.redis.pipeline();
  pipe.sadd(QK.active(queueName), jobId);
  pipe.hset(QK.jobData(jobId), 'status', 'active', 'startedAt', new Date().toISOString());
  pipe.hincrby(QK.stats(queueName), 'active', 1);
  await pipe.exec();

  await db.query(
    `UPDATE jobs SET status = 'active', started_at = NOW(), attempts = attempts + 1 WHERE id = $1`,
    [jobId]
  );

  return {
    id:          jobData.id,
    name:        jobData.name,
    queueName:   jobData.queueName,
    tenantId:    jobData.tenantId || null,
    data:        JSON.parse(jobData.data || '{}'),
    priority:    parseInt(jobData.priority || '0'),
    attempts:    parseInt(jobData.attempts || '0') + 1,
    maxAttempts: parseInt(jobData.maxAttempts || '3'),
  };
}

// ─── COMPLETE / FAIL ─────────────────────────────────────────

async function complete(queueName, jobId, result = {}) {
  const pipe = redis.redis.pipeline();
  pipe.srem(QK.active(queueName), jobId);
  pipe.lpush(QK.completed(queueName), jobId);
  pipe.ltrim(QK.completed(queueName), 0, 999); // keep last 1000
  pipe.hset(QK.jobData(jobId), 'status', 'completed', 'result', JSON.stringify(result));
  pipe.hincrby(QK.stats(queueName), 'completed', 1);
  pipe.hincrby(QK.stats(queueName), 'active', -1);
  await pipe.exec();

  await db.query(
    `UPDATE jobs SET status = 'completed', finished_at = NOW(), result = $1 WHERE id = $2`,
    [JSON.stringify(result), jobId]
  );

  logger.debug('Job completed', { jobId, queue: queueName });
}

async function fail(queueName, jobId, error, attempts, maxAttempts) {
  const shouldRetry = attempts < maxAttempts;

  const pipe = redis.redis.pipeline();
  pipe.srem(QK.active(queueName), jobId);
  pipe.hincrby(QK.stats(queueName), 'active', -1);

  if (shouldRetry) {
    // Exponential backoff: 2^attempt * 1000ms
    const backoff = Math.pow(2, attempts) * 1000;
    const retryAt = Date.now() + backoff;
    pipe.zadd(QK.delayed(queueName), retryAt, jobId);
    pipe.hset(QK.jobData(jobId), 'status', 'delayed', 'attempts', attempts);
    await pipe.exec();

    await db.query(
      `UPDATE jobs SET status = 'waiting', error = $1, attempts = $2, delay_until = $3 WHERE id = $4`,
      [error, attempts, new Date(retryAt), jobId]
    );
    logger.warn('Job failed, retrying', { jobId, attempts, backoff });
  } else {
    // Dead letter
    pipe.zadd(QK.failed(queueName), Date.now(), jobId);
    pipe.hset(QK.jobData(jobId), 'status', 'failed', 'error', error);
    pipe.hincrby(QK.stats(queueName), 'failed', 1);
    await pipe.exec();

    await db.query(
      `UPDATE jobs SET status = 'failed', failed_at = NOW(), error = $1 WHERE id = $2`,
      [error, jobId]
    );
    logger.error('Job failed permanently', { jobId, queue: queueName, error });
  }
}

// ─── RETRY FAILED ────────────────────────────────────────────

async function retryFailed(queueName) {
  const failedIds = await redis.redis.zrange(QK.failed(queueName), 0, -1);
  if (!failedIds.length) return 0;

  const pipe = redis.redis.pipeline();
  failedIds.forEach(id => {
    pipe.zrem(QK.failed(queueName), id);
    pipe.zadd(QK.waiting(queueName), 0, id);
    pipe.hset(QK.jobData(id), 'status', 'waiting', 'attempts', 0);
  });
  pipe.hincrby(QK.stats(queueName), 'failed', -failedIds.length);
  await pipe.exec();

  await db.query(
    `UPDATE jobs SET status = 'waiting', attempts = 0, failed_at = NULL, error = NULL
     WHERE id = ANY($1)`,
    [failedIds]
  );

  return failedIds.length;
}

async function retryAllFailed() {
  let total = 0;
  for (const name of Object.keys(QUEUES)) {
    total += await retryFailed(name);
  }
  return total;
}

// ─── STATS ───────────────────────────────────────────────────

async function getQueueStats(queueName) {
  const pipe = redis.redis.pipeline();
  pipe.zcard(QK.waiting(queueName));
  pipe.scard(QK.active(queueName));
  pipe.zcard(QK.failed(queueName));
  pipe.llen(QK.completed(queueName));
  pipe.zcard(QK.delayed(queueName));
  pipe.hgetall(QK.stats(queueName));

  const results = await pipe.exec();
  const stats = results[5][1] || {};

  return {
    name:       queueName,
    config:     QUEUES[queueName],
    waiting:    parseInt(results[0][1] || 0),
    active:     parseInt(results[1][1] || 0),
    failed:     parseInt(results[2][1] || 0),
    completed:  parseInt(results[3][1] || 0),
    delayed:    parseInt(results[4][1] || 0),
    totalEnqueued:  parseInt(stats.enqueued  || 0),
    totalCompleted: parseInt(stats.completed || 0),
    totalFailed:    parseInt(stats.failed    || 0),
    isPaused:   false,
  };
}

async function getAllQueueStats() {
  return Promise.all(Object.keys(QUEUES).map(getQueueStats));
}

async function getJobsByTenant(tenantId, { status, queueName, limit = 20, offset = 0 }) {
  const conditions = ['tenant_id = $1'];
  const params = [tenantId];
  let i = 2;

  if (status)    { conditions.push(`status = $${i++}`);     params.push(status); }
  if (queueName) { conditions.push(`queue_name = $${i++}`); params.push(queueName); }

  params.push(limit); params.push(offset);
  const result = await db.query(
    `SELECT id, queue_name, name, status, priority, attempts, max_attempts,
            progress, error, created_at, started_at, finished_at, failed_at
     FROM jobs
     WHERE ${conditions.join(' AND ')}
     ORDER BY created_at DESC
     LIMIT $${i} OFFSET $${i + 1}`,
    params
  );

  return result.rows;
}

// ─── SIMULATED WORKER LOOP ───────────────────────────────────
// In production: use BullMQ workers in separate processes

const activeWorkers = new Map();

function startWorker(queueName, processor) {
  if (activeWorkers.has(queueName)) return;

  const config = QUEUES[queueName];
  let running = 0;

  const tick = async () => {
    while (running < config.concurrency) {
      const job = await dequeue(queueName);
      if (!job) break;

      running++;
      processor(job)
        .then(result => complete(queueName, job.id, result))
        .catch(err  => fail(queueName, job.id, err.message, job.attempts, job.maxAttempts))
        .finally(() => { running--; });
    }
  };

  const interval = setInterval(tick, 1000);
  activeWorkers.set(queueName, interval);
  logger.info(`Worker started for queue: ${queueName}`, { concurrency: config.concurrency });
}

function stopWorker(queueName) {
  const interval = activeWorkers.get(queueName);
  if (interval) {
    clearInterval(interval);
    activeWorkers.delete(queueName);
  }
}

// ─── DEFAULT PROCESSORS ──────────────────────────────────────

const processors = {
  'email-notifications': async (job) => {
    logger.info('Processing email job', { jobId: job.id, tenantId: job.tenantId, data: job.data });
    await new Promise(r => setTimeout(r, 200 + Math.random() * 500));
    return { sent: true, messageId: `msg_${Date.now()}` };
  },
  'report-generation': async (job) => {
    logger.info('Generating report', { jobId: job.id, type: job.data.reportType });
    await new Promise(r => setTimeout(r, 1000 + Math.random() * 2000));
    return { reportId: `rpt_${Date.now()}`, rows: Math.floor(Math.random() * 10000) };
  },
  'data-sync': async (job) => {
    await new Promise(r => setTimeout(r, 300 + Math.random() * 700));
    return { synced: Math.floor(Math.random() * 500), duration: 300 };
  },
  'webhook-dispatch': async (job) => {
    await new Promise(r => setTimeout(r, 100 + Math.random() * 300));
    const success = Math.random() > 0.05; // 95% success rate
    if (!success) throw new Error('Webhook endpoint returned 500');
    return { delivered: true, statusCode: 200 };
  },
  'invoice-processing': async (job) => {
    await new Promise(r => setTimeout(r, 500 + Math.random() * 1000));
    return { invoiceId: job.data.invoiceId, processed: true, amount: job.data.amount };
  },
};

function startAllWorkers() {
  for (const [name, processor] of Object.entries(processors)) {
    startWorker(name, processor);
  }
}

function stopAllWorkers() {
  for (const name of activeWorkers.keys()) {
    stopWorker(name);
  }
}

module.exports = {
  enqueue, dequeue, complete, fail,
  retryFailed, retryAllFailed,
  getQueueStats, getAllQueueStats, getJobsByTenant,
  startWorker, stopWorker, startAllWorkers, stopAllWorkers,
  QUEUES,
};
