-- Migration: 001_add_jobs_and_api_keys.sql
-- Adds job queue tables and API keys table referenced by services

-- ─── JOB QUEUES ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS job_queues (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    is_paused   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO job_queues (name, description) VALUES
    ('email-notifications', 'Transactional email delivery'),
    ('report-generation',   'Async report and export generation'),
    ('data-sync',           'Cross-system data synchronization'),
    ('webhook-dispatch',    'Outbound webhook delivery with retry'),
    ('invoice-processing',  'Billing and invoice automation')
ON CONFLICT (name) DO NOTHING;

CREATE TABLE IF NOT EXISTS jobs (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    queue_name   VARCHAR(100) NOT NULL REFERENCES job_queues(name) ON DELETE CASCADE,
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name         VARCHAR(200) NOT NULL,
    data         JSONB NOT NULL DEFAULT '{}',
    opts         JSONB NOT NULL DEFAULT '{}',
    priority     INTEGER NOT NULL DEFAULT 0,
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    status       VARCHAR(20) NOT NULL DEFAULT 'waiting'
                 CHECK (status IN ('waiting','active','completed','failed','delayed','cancelled')),
    progress     INTEGER NOT NULL DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
    result       JSONB,
    error        TEXT,
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ,
    failed_at    TIMESTAMPTZ,
    delay_until  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_jobs_tenant_status  ON jobs(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_jobs_queue_status   ON jobs(queue_name, status);
CREATE INDEX IF NOT EXISTS idx_jobs_delay          ON jobs(delay_until) WHERE status = 'delayed';
CREATE INDEX IF NOT EXISTS idx_jobs_created        ON jobs(created_at DESC);

-- ─── ADDITIONAL PERFORMANCE INDEXES ──────────────────────────

-- Partial index for active sessions (most frequent query)
CREATE INDEX IF NOT EXISTS idx_sessions_active_expires
    ON sessions(tenant_id, expires_at)
    WHERE is_active = TRUE;

-- Partial index for non-expired refresh tokens
CREATE INDEX IF NOT EXISTS idx_rt_valid
    ON refresh_tokens(token_hash)
    WHERE is_used = FALSE AND revoked = FALSE;

-- Composite index for brute force queries
CREATE INDEX IF NOT EXISTS idx_login_attempts_recent
    ON login_attempts(email, ip_address, attempted_at DESC)
    WHERE attempted_at > NOW() - INTERVAL '24 hours';

-- ─── USAGE METRICS TABLE ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS usage_metrics (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    date        DATE NOT NULL,
    requests    BIGINT NOT NULL DEFAULT 0,
    api_errors  INTEGER NOT NULL DEFAULT 0,
    jobs_queued INTEGER NOT NULL DEFAULT 0,

    UNIQUE(tenant_id, date)
);

CREATE INDEX IF NOT EXISTS idx_usage_tenant_date ON usage_metrics(tenant_id, date DESC);

-- ─── WEBHOOK ENDPOINTS ───────────────────────────────────────

CREATE TABLE IF NOT EXISTS webhooks (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    url         TEXT NOT NULL,
    events      TEXT[] NOT NULL DEFAULT '{}',
    secret_hash TEXT NOT NULL,       -- HMAC secret for payload signing
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    failure_count INTEGER NOT NULL DEFAULT 0,
    last_success_at TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhooks_tenant ON webhooks(tenant_id);

COMMIT;
