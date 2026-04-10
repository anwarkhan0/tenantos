-- ============================================================
-- TenantOS Database Schema
-- PostgreSQL 16 — Multi-tenant architecture
-- ============================================================

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- for text search

-- ─── ENUMS ───────────────────────────────────────────────────

CREATE TYPE tenant_plan   AS ENUM ('trial', 'pro', 'enterprise');
CREATE TYPE tenant_status AS ENUM ('active', 'suspended', 'deleted');
CREATE TYPE user_role     AS ENUM ('superadmin', 'admin', 'developer', 'analyst', 'viewer');
CREATE TYPE user_status   AS ENUM ('active', 'inactive', 'locked');
CREATE TYPE audit_type    AS ENUM ('auth', 'tenant', 'user', 'permission', 'security', 'system');
CREATE TYPE audit_severity AS ENUM ('info', 'warning', 'critical');
CREATE TYPE token_type    AS ENUM ('refresh', 'reset_password', 'email_verify', 'api_key');

-- ─── TENANTS ─────────────────────────────────────────────────

CREATE TABLE tenants (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    slug          VARCHAR(64) UNIQUE NOT NULL,
    name          VARCHAR(255) NOT NULL,
    plan          tenant_plan NOT NULL DEFAULT 'trial',
    status        tenant_status NOT NULL DEFAULT 'active',
    region        VARCHAR(32) NOT NULL DEFAULT 'us-east-1',
    db_schema     VARCHAR(64) UNIQUE NOT NULL,    -- isolated schema name
    rate_limit    INTEGER NOT NULL DEFAULT 1000,   -- req/min
    max_users     INTEGER NOT NULL DEFAULT 5,
    settings      JSONB NOT NULL DEFAULT '{}',
    metadata      JSONB NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at    TIMESTAMPTZ
);

CREATE INDEX idx_tenants_slug   ON tenants(slug);
CREATE INDEX idx_tenants_status ON tenants(status);
CREATE INDEX idx_tenants_plan   ON tenants(plan);

-- ─── USERS ───────────────────────────────────────────────────

CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email               VARCHAR(255) NOT NULL,
    password_hash       TEXT NOT NULL,
    role                user_role NOT NULL DEFAULT 'viewer',
    status              user_status NOT NULL DEFAULT 'active',
    first_name          VARCHAR(100),
    last_name           VARCHAR(100),
    email_verified      BOOLEAN NOT NULL DEFAULT FALSE,
    email_verified_at   TIMESTAMPTZ,
    last_login_at       TIMESTAMPTZ,
    last_login_ip       INET,
    failed_attempts     INTEGER NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    mfa_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret          TEXT,
    metadata            JSONB NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at          TIMESTAMPTZ,

    UNIQUE(tenant_id, email)
);

CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_users_email     ON users(email);
CREATE INDEX idx_users_status    ON users(status);
CREATE INDEX idx_users_role      ON users(role);

-- ─── REFRESH TOKENS ──────────────────────────────────────────
-- Implements refresh token rotation: each refresh generates a new pair
-- Old tokens are invalidated (rotation chain)

CREATE TABLE refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash      TEXT UNIQUE NOT NULL,        -- SHA-256 hash of the token
    family_id       UUID NOT NULL,               -- rotation family — all linked tokens
    is_used         BOOLEAN NOT NULL DEFAULT FALSE,
    used_at         TIMESTAMPTZ,
    replaced_by_id  UUID REFERENCES refresh_tokens(id),  -- next token in rotation
    ip_address      INET,
    user_agent      TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ,
    revoke_reason   VARCHAR(100),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rt_user_id    ON refresh_tokens(user_id);
CREATE INDEX idx_rt_token_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_rt_family     ON refresh_tokens(family_id);
CREATE INDEX idx_rt_expires    ON refresh_tokens(expires_at);

-- ─── SESSIONS ────────────────────────────────────────────────

CREATE TABLE sessions (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_family UUID NOT NULL,               -- ties to refresh_tokens.family_id
    ip_address  INET,
    user_agent  TEXT,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    last_active TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_sessions_user   ON sessions(user_id);
CREATE INDEX idx_sessions_family ON sessions(token_family);
CREATE INDEX idx_sessions_active ON sessions(is_active);

-- ─── PERMISSIONS ─────────────────────────────────────────────

CREATE TABLE permissions (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    resource    VARCHAR(100) NOT NULL,   -- e.g. 'users', 'tenants', 'billing'
    action      VARCHAR(50) NOT NULL,    -- e.g. 'create', 'read', 'update', 'delete'
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(resource, action)
);

CREATE TABLE role_permissions (
    role        user_role NOT NULL,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by  UUID REFERENCES users(id),

    PRIMARY KEY (role, permission_id)
);

-- ─── BRUTE FORCE PROTECTION ──────────────────────────────────

CREATE TABLE login_attempts (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID REFERENCES tenants(id) ON DELETE CASCADE,
    email       VARCHAR(255) NOT NULL,
    ip_address  INET NOT NULL,
    user_agent  TEXT,
    success     BOOLEAN NOT NULL DEFAULT FALSE,
    failure_reason VARCHAR(100),
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_login_attempts_email     ON login_attempts(email, attempted_at DESC);
CREATE INDEX idx_login_attempts_ip        ON login_attempts(ip_address, attempted_at DESC);
CREATE INDEX idx_login_attempts_tenant    ON login_attempts(tenant_id, attempted_at DESC);

-- ─── AUDIT LOGS ──────────────────────────────────────────────

CREATE TABLE audit_logs (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID REFERENCES tenants(id) ON DELETE SET NULL,
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    type        audit_type NOT NULL DEFAULT 'system',
    severity    audit_severity NOT NULL DEFAULT 'info',
    action      VARCHAR(200) NOT NULL,
    resource    VARCHAR(200),
    resource_id UUID,
    ip_address  INET,
    user_agent  TEXT,
    before_data JSONB,
    after_data  JSONB,
    metadata    JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_tenant    ON audit_logs(tenant_id, created_at DESC);
CREATE INDEX idx_audit_user      ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_type      ON audit_logs(type, created_at DESC);
CREATE INDEX idx_audit_severity  ON audit_logs(severity, created_at DESC);
CREATE INDEX idx_audit_created   ON audit_logs(created_at DESC);

-- ─── API KEYS ─────────────────────────────────────────────────

CREATE TABLE api_keys (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        VARCHAR(100) NOT NULL,
    key_hash    TEXT UNIQUE NOT NULL,        -- SHA-256 hash
    key_prefix  VARCHAR(12) NOT NULL,        -- first 12 chars shown to user
    permissions JSONB NOT NULL DEFAULT '[]', -- scoped permissions
    expires_at  TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX idx_api_keys_hash   ON api_keys(key_hash);

-- ─── FUNCTIONS & TRIGGERS ────────────────────────────────────

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenants_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Clean up expired tokens (run via pg_cron or scheduled job)
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM refresh_tokens
    WHERE expires_at < NOW() - INTERVAL '1 day'
       OR (is_used = TRUE AND used_at < NOW() - INTERVAL '1 hour');
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- ─── SEED PERMISSIONS ────────────────────────────────────────

INSERT INTO permissions (resource, action, description) VALUES
-- Tenant management
('tenants', 'create',  'Create new tenants'),
('tenants', 'read',    'View tenant information'),
('tenants', 'update',  'Modify tenant settings'),
('tenants', 'delete',  'Delete tenants'),
('tenants', 'suspend', 'Suspend tenant access'),
-- User management
('users', 'create',    'Invite and create users'),
('users', 'read',      'View user information'),
('users', 'update',    'Modify user details and roles'),
('users', 'delete',    'Remove users'),
-- Auth management
('auth', 'manage_sessions', 'View and revoke sessions'),
('auth', 'manage_api_keys', 'Create and revoke API keys'),
-- Audit logs
('audit', 'read',      'View audit logs'),
('audit', 'export',    'Export audit log data'),
-- Billing
('billing', 'read',    'View billing information'),
('billing', 'manage',  'Manage subscription and billing'),
-- Cache
('cache', 'read',      'View cache statistics'),
('cache', 'flush',     'Flush tenant cache'),
-- Jobs
('jobs', 'read',       'View background jobs'),
('jobs', 'manage',     'Enqueue and retry jobs');

-- ─── ROLE PERMISSION MAPPINGS ────────────────────────────────

-- superadmin: everything
INSERT INTO role_permissions (role, permission_id)
SELECT 'superadmin', id FROM permissions;

-- admin: tenant + users + auth + audit + billing + cache + jobs
INSERT INTO role_permissions (role, permission_id)
SELECT 'admin', id FROM permissions
WHERE (resource, action) IN (
    ('tenants','read'), ('tenants','update'), ('tenants','suspend'),
    ('users','create'), ('users','read'), ('users','update'), ('users','delete'),
    ('auth','manage_sessions'), ('auth','manage_api_keys'),
    ('audit','read'), ('audit','export'),
    ('billing','read'), ('billing','manage'),
    ('cache','read'), ('cache','flush'),
    ('jobs','read'), ('jobs','manage')
);

-- developer: users.read + auth + cache + jobs
INSERT INTO role_permissions (role, permission_id)
SELECT 'developer', id FROM permissions
WHERE (resource, action) IN (
    ('users','read'),
    ('auth','manage_api_keys'),
    ('audit','read'),
    ('cache','read'),
    ('jobs','read'), ('jobs','manage')
);

-- analyst: read-only
INSERT INTO role_permissions (role, permission_id)
SELECT 'analyst', id FROM permissions
WHERE (resource, action) IN (
    ('users','read'),
    ('audit','read'), ('audit','export'),
    ('billing','read'),
    ('jobs','read')
);

-- viewer: absolute minimum
INSERT INTO role_permissions (role, permission_id)
SELECT 'viewer', id FROM permissions
WHERE (resource, action) IN (
    ('users','read')
);

COMMIT;
