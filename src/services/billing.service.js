/**
 * Billing Service
 *
 * Handles:
 *  - Plan quota enforcement (users, API requests, storage)
 *  - Usage metering (per-tenant request counters → Redis → PostgreSQL)
 *  - Invoice generation (monthly, stored in S3)
 *  - Stripe-ready webhook handling stubs
 *  - Overage alerts via SES
 */

'use strict';

const db     = require('../config/database');
const redis  = require('../config/redis');
const { sendEmail, uploadToS3, Metrics } = require('../config/aws');
const AuditService = require('./audit.service');
const logger = require('../config/logger');

// ─── PLAN DEFINITIONS ─────────────────────────────────────────

const PLANS = {
  trial: {
    name:          'Trial',
    price:         0,
    currency:      'USD',
    rateLimit:     100,     // req/min
    maxUsers:      3,
    maxStorageMB:  100,
    maxApiKeys:    2,
    maxWebhooks:   1,
    retentionDays: 7,       // audit log retention
    support:       'community',
    features:      ['basic_auth', 'audit_logs', 'rate_limiting'],
  },
  pro: {
    name:          'Pro',
    price:         49,
    currency:      'USD',
    rateLimit:     1000,
    maxUsers:      25,
    maxStorageMB:  5000,
    maxApiKeys:    10,
    maxWebhooks:   5,
    retentionDays: 90,
    support:       'email',
    features:      ['basic_auth', 'mfa', 'audit_logs', 'rate_limiting', 'webhooks', 'api_keys', 'sso'],
  },
  enterprise: {
    name:          'Enterprise',
    price:         299,
    currency:      'USD',
    rateLimit:     5000,
    maxUsers:      500,
    maxStorageMB:  50000,
    maxApiKeys:    100,
    maxWebhooks:   50,
    retentionDays: 365,
    support:       'dedicated',
    features:      ['basic_auth', 'mfa', 'audit_logs', 'rate_limiting', 'webhooks', 'api_keys', 'sso', 'saml', 'scim', 'custom_domain', 'sla_99_9'],
  },
};

// ─── QUOTA CHECKS ─────────────────────────────────────────────

async function checkUserQuota(tenantId) {
  const result = await db.query(
    `SELECT t.plan, t.max_users,
            COUNT(u.id) FILTER (WHERE u.deleted_at IS NULL) as current_users
     FROM tenants t
     LEFT JOIN users u ON u.tenant_id = t.id
     WHERE t.id = $1
     GROUP BY t.plan, t.max_users`,
    [tenantId]
  );

  const row = result.rows[0];
  if (!row) throw Object.assign(new Error('Tenant not found'), { status: 404 });

  const current = parseInt(row.current_users);
  const max     = row.max_users;
  const plan    = PLANS[row.plan];

  return {
    allowed:     current < max,
    current,
    max,
    plan:        row.plan,
    utilization: Math.round((current / max) * 100),
    overage:     Math.max(0, current - max),
    upgradeRequired: current >= max,
    nextPlan:    row.plan === 'trial' ? 'pro' : row.plan === 'pro' ? 'enterprise' : null,
  };
}

async function checkApiKeyQuota(tenantId) {
  const tenantRes = await db.query('SELECT plan FROM tenants WHERE id = $1', [tenantId]);
  const plan = tenantRes.rows[0]?.plan || 'trial';
  const max  = PLANS[plan]?.maxApiKeys || 2;

  const countRes = await db.query(
    'SELECT COUNT(*) FROM api_keys WHERE tenant_id = $1 AND is_active = TRUE',
    [tenantId]
  );
  const current = parseInt(countRes.rows[0].count);

  return { allowed: current < max, current, max, plan };
}

async function checkWebhookQuota(tenantId) {
  const tenantRes = await db.query('SELECT plan FROM tenants WHERE id = $1', [tenantId]);
  const plan = tenantRes.rows[0]?.plan || 'trial';
  const max  = PLANS[plan]?.maxWebhooks || 1;

  const countRes = await db.query(
    'SELECT COUNT(*) FROM webhooks WHERE tenant_id = $1 AND is_active = TRUE',
    [tenantId]
  );
  const current = parseInt(countRes.rows[0].count);

  return { allowed: current < max, current, max, plan };
}

// ─── USAGE METERING ───────────────────────────────────────────

/**
 * Increment the daily API request counter for a tenant.
 * Called by the rate limiting middleware on every request.
 */
async function recordRequest(tenantId, endpoint = 'api') {
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  const key   = `usage:req:${tenantId}:${today}`;

  // Atomic increment in Redis (fast path)
  const count = await redis.redis.incr(key);
  await redis.redis.expire(key, 92 * 86400); // keep 92 days

  // Flush to PostgreSQL every 100 requests to avoid too many DB writes
  if (count % 100 === 0) {
    await db.query(
      `INSERT INTO usage_metrics (tenant_id, date, requests)
       VALUES ($1, $2, $3)
       ON CONFLICT (tenant_id, date) DO UPDATE
         SET requests = EXCLUDED.requests`,
      [tenantId, today, count]
    ).catch(err => logger.warn('Usage flush failed', { error: err.message }));
  }

  Metrics.apiRequest(tenantId, 'ALL', endpoint, 200, 0);
  return count;
}

async function getUsage(tenantId, days = 30) {
  const dates = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000);
    dates.push(d.toISOString().slice(0, 10));
  }

  // Fetch from Redis first (most recent), fall back to PostgreSQL
  const redisKeys = dates.map(d => `usage:req:${tenantId}:${d}`);
  const redisVals = redisKeys.length ? await redis.redis.mget(...redisKeys) : [];

  // For dates not in Redis, query PostgreSQL
  const dbResult = await db.query(
    `SELECT date::text, requests, api_errors
     FROM usage_metrics
     WHERE tenant_id = $1 AND date >= $2
     ORDER BY date ASC`,
    [tenantId, dates[0]]
  );

  const dbByDate = {};
  dbResult.rows.forEach(r => { dbByDate[r.date] = r; });

  return dates.map((date, i) => {
    const redisCount = redisVals[i] ? parseInt(redisVals[i]) : null;
    const dbRow      = dbByDate[date];
    return {
      date,
      requests:  redisCount !== null ? redisCount : (dbRow?.requests || 0),
      errors:    dbRow?.api_errors || 0,
    };
  });
}

async function getCurrentMonthUsage(tenantId) {
  const now   = new Date();
  const from  = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-01`;
  const days  = now.getDate();
  const usage = await getUsage(tenantId, days);

  const totalRequests = usage.reduce((a, d) => a + d.requests, 0);
  const totalErrors   = usage.reduce((a, d) => a + d.errors, 0);
  const dailyAvg      = Math.round(totalRequests / days);

  return { totalRequests, totalErrors, dailyAvg, days, breakdown: usage };
}

// ─── INVOICE GENERATION ───────────────────────────────────────

async function generateInvoice(tenantId, month) {
  // month = "2026-03"
  const [year, mo] = month.split('-').map(Number);

  const [tenantRes, usageRes] = await Promise.all([
    db.query('SELECT * FROM tenants WHERE id = $1', [tenantId]),
    db.query(
      `SELECT SUM(requests) as total_requests, SUM(api_errors) as total_errors
       FROM usage_metrics
       WHERE tenant_id = $1
         AND EXTRACT(YEAR FROM date) = $2
         AND EXTRACT(MONTH FROM date) = $3`,
      [tenantId, year, mo]
    ),
  ]);

  const tenant = tenantRes.rows[0];
  if (!tenant) throw Object.assign(new Error('Tenant not found'), { status: 404 });

  const plan   = PLANS[tenant.plan];
  const usage  = usageRes.rows[0];

  const invoice = {
    id:           `inv_${tenantId.slice(0, 8)}_${month.replace('-', '')}`,
    tenantId,
    tenantName:   tenant.name,
    tenantSlug:   tenant.slug,
    period:       month,
    plan:         tenant.plan,
    planName:     plan.name,
    currency:     plan.currency,
    baseAmount:   plan.price,
    lineItems:    [
      { description: `${plan.name} Plan — ${month}`, amount: plan.price, quantity: 1 },
    ],
    totalAmount:  plan.price,
    status:       'draft',
    usage: {
      requests:   parseInt(usage.total_requests || 0),
      errors:     parseInt(usage.total_errors || 0),
    },
    generatedAt:  new Date().toISOString(),
  };

  // Add overage if applicable (enterprise customers might have overages)
  const requestOverage = Math.max(0, invoice.usage.requests - plan.rateLimit * 30 * 24 * 60);
  if (requestOverage > 0 && tenant.plan !== 'enterprise') {
    const overageAmount = Math.round(requestOverage / 1000) * 0.01; // $0.01 per 1k overage
    invoice.lineItems.push({
      description: `API Request Overage (${requestOverage.toLocaleString()} requests)`,
      amount: overageAmount,
      quantity: 1,
    });
    invoice.totalAmount += overageAmount;
  }

  // Generate CSV-style invoice and store in S3
  const csvContent = [
    `Invoice ID,${invoice.id}`,
    `Tenant,${invoice.tenantName}`,
    `Period,${invoice.period}`,
    `Plan,${invoice.planName}`,
    '',
    'Item,Amount',
    ...invoice.lineItems.map(li => `"${li.description}",${li.amount.toFixed(2)}`),
    '',
    `Total,${invoice.totalAmount.toFixed(2)} ${invoice.currency}`,
  ].join('\n');

  try {
    const s3Result = await uploadToS3(
      tenantId,
      `invoices/${invoice.id}.csv`,
      csvContent,
      'text/csv',
      { invoiceId: invoice.id, month }
    );
    invoice.s3Key = s3Result.key;
    invoice.downloadUrl = s3Result.url;
  } catch (err) {
    logger.warn('Invoice S3 upload failed', { error: err.message, invoiceId: invoice.id });
  }

  await AuditService.log({
    tenantId, type: 'system', severity: 'info',
    action: 'INVOICE_GENERATED',
    metadata: { invoiceId: invoice.id, amount: invoice.totalAmount, period: month },
  });

  return invoice;
}

// ─── BILLING SUMMARY ──────────────────────────────────────────

async function getBillingSummary(tenantId) {
  const [tenantRes, monthUsage] = await Promise.all([
    db.query('SELECT plan, status, created_at FROM tenants WHERE id = $1', [tenantId]),
    getCurrentMonthUsage(tenantId),
  ]);

  const tenant = tenantRes.rows[0];
  const plan   = PLANS[tenant?.plan || 'trial'];

  return {
    plan:        tenant?.plan,
    planDetails: plan,
    billing: {
      nextInvoiceDate: getNextBillingDate(),
      estimatedAmount: plan.price,
      currency:        plan.currency,
    },
    usage: {
      ...monthUsage,
      requestLimit: plan.rateLimit * 30 * 24 * 60, // per month
      utilizationPct: Math.min(100, Math.round((monthUsage.totalRequests / (plan.rateLimit * 30 * 24 * 60)) * 100)),
    },
    quotas: {
      users:    await checkUserQuota(tenantId),
      apiKeys:  await checkApiKeyQuota(tenantId),
      webhooks: await checkWebhookQuota(tenantId),
    },
  };
}

function getNextBillingDate() {
  const now  = new Date();
  const next = new Date(now.getFullYear(), now.getMonth() + 1, 1);
  return next.toISOString().slice(0, 10);
}

// ─── PLAN FEATURES ────────────────────────────────────────────

function planHasFeature(plan, feature) {
  return PLANS[plan]?.features?.includes(feature) || false;
}

function getAllPlans() {
  return Object.entries(PLANS).map(([id, p]) => ({ id, ...p }));
}

module.exports = {
  PLANS, getAllPlans,
  checkUserQuota, checkApiKeyQuota, checkWebhookQuota,
  recordRequest, getUsage, getCurrentMonthUsage,
  generateInvoice, getBillingSummary,
  planHasFeature,
};
