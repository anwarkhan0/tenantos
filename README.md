# TenantOS — Multi-Tenant SaaS Backend

> Production-grade backend + dashboard · Node.js · PostgreSQL · Redis · AWS · Docker

---

## Quick Start (3 commands)

```bash
# 1. Clone or unzip the project
cd tenantOS

# 2. Auto-setup: installs deps, starts Docker services, runs migrations, seeds data
node scripts/setup.js

# 3. Start the server
npm run dev
```

Open **http://localhost:3000** — the dashboard loads automatically.

**Login:** `alice@acme-corp.io` / `AliceAdmin@123`
**Tenant ID:** `a0000001-0000-0000-0000-000000000001`

---

## Docker (full stack, one command)

```bash
cp .env.example .env          # configure passwords
docker-compose up -d          # starts postgres + redis + app (auto-migrates + seeds)
```

Dev tools (pgAdmin + Redis Commander):
```bash
docker-compose --profile dev up -d
# pgAdmin:          http://localhost:5050  (admin@tenantOS.io / admin)
# Redis Commander:  http://localhost:8081
```

---

## Folder Structure

```
tenantOS/
│
├── public/
│   └── dashboard.html          ← Full dashboard UI (opens at localhost:3000)
│
├── src/
│   ├── index.js                ← App entry: Express + workers + SSE + graceful shutdown
│   │
│   ├── config/
│   │   ├── database.js         ← PostgreSQL pool (pg), transactions, health check
│   │   ├── redis.js            ← ioredis client, token families, sessions, brute-force
│   │   ├── aws.js              ← S3, SES, Secrets Manager, CloudWatch metrics
│   │   └── logger.js           ← Winston structured logs + optional CloudWatch
│   │
│   ├── middleware/
│   │   └── index.js            ← JWT auth, brute-force check, rate limit, RBAC, validation
│   │
│   ├── routes/
│   │   ├── index.js            ← Main router: mounts all 11 sub-routers
│   │   ├── auth.routes.js      ← /auth/* (login, refresh, logout, sessions, me)
│   │   └── extended.routes.js  ← /auth/mfa/*, /webhooks/*, /events/*, /jobs/*, /api-keys/*
│   │
│   └── services/
│       ├── auth.service.js     ← Login, refresh token rotation, session management
│       ├── mfa.service.js      ← TOTP (RFC 6238), backup codes, QR URI
│       ├── rbac.service.js     ← Permission checks, Redis-cached role matrix
│       ├── audit.service.js    ← Immutable event log, CSV export
│       ├── tenant.service.js   ← Provisioning, stats, plan upgrades
│       ├── billing.service.js  ← Quota enforcement, usage metering, invoices
│       ├── queue.service.js    ← BullMQ-style: priority, retry, DLQ, workers
│       ├── webhook.service.js  ← HMAC-signed delivery, exponential backoff
│       ├── realtime.service.js ← SSE event streaming, connection registry
│       └── apikey.service.js   ← SHA-256 hashed keys, scoped permissions
│
├── scripts/
│   ├── setup.js                ← One-command setup (auto-detects, starts services)
│   ├── migrate.js              ← Migration runner (tracks applied migrations)
│   ├── seed.js                 ← Demo tenants, users, audit events
│   ├── init.sql                ← Base schema: 14 tables, enums, triggers, permissions
│   └── migrations/
│       └── 001_add_jobs_and_api_keys.sql
│
├── tests/
│   └── run.js                  ← 140 tests, zero external dependencies
│
├── docker/
│   └── nginx.conf              ← Production reverse proxy + rate limiting
│
├── Dockerfile                  ← Multi-stage: development + production
├── docker-compose.yml          ← Postgres 16 + Redis 7 + App + pgAdmin + Redis-Commander
├── package.json
├── .env.example
├── .gitignore
└── .dockerignore
```

---

## All API Endpoints

**Base URL:** `http://localhost:3000/api/v1`

**Headers required:**
```
Content-Type:  application/json
X-Tenant-ID:   <tenant-uuid>
Authorization: Bearer <access-token>    (all protected routes)
```

### Auth
| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register` | Create user account |
| POST | `/auth/login` | Issue JWT + refresh token |
| POST | `/auth/refresh` | Rotate refresh token |
| POST | `/auth/logout` | Revoke session |
| POST | `/auth/logout-all` | Revoke all sessions |
| GET  | `/auth/sessions` | List active sessions |
| DELETE | `/auth/sessions/:id` | Revoke specific session |
| GET  | `/auth/me` | Current user profile |
| POST | `/auth/change-password` | Change password (revokes all other sessions) |
| GET  | `/auth/lockout-status?email=` | Check brute-force lockout status |

### MFA
| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/mfa/setup` | Start TOTP setup, get QR code |
| POST | `/auth/mfa/confirm` | Activate MFA with first code |
| POST | `/auth/mfa/verify` | Verify code during login |
| POST | `/auth/mfa/disable` | Disable MFA |
| POST | `/auth/mfa/backup/regenerate` | New backup codes |

### Tenants
| Method | Path | Permission |
|--------|------|------------|
| GET | `/tenants` | tenants:read |
| POST | `/tenants` | tenants:create |
| GET | `/tenants/:id` | tenants:read |
| PATCH | `/tenants/:id` | tenants:update |
| POST | `/tenants/:id/suspend` | tenants:suspend |
| POST | `/tenants/:id/reactivate` | tenants:suspend |
| GET | `/tenants/:id/stats` | authenticated |
| GET | `/tenants/:id/usage` | authenticated |
| PATCH | `/tenants/:id/plan` | billing:manage |

### Users
| Method | Path | Permission |
|--------|------|------------|
| GET | `/users` | users:read |
| GET | `/users/:id` | users:read |
| PATCH | `/users/:id/role` | users:update |
| PATCH | `/users/:id/status` | users:update |
| POST | `/users/:id/unlock` | users:update |
| DELETE | `/users/:id` | users:delete |

### RBAC
| Method | Path | Description |
|--------|------|-------------|
| GET | `/rbac/permissions` | All permission definitions |
| GET | `/rbac/matrix` | Role → permission matrix |
| GET | `/rbac/check?resource=&action=` | Check caller's permission |
| POST | `/rbac/grant` | Grant permission to role |

### Jobs
| Method | Path | Permission |
|--------|------|------------|
| GET | `/jobs/queues` | jobs:read |
| GET | `/jobs/queues/:name` | jobs:read |
| POST | `/jobs/queues/:name` | jobs:manage |
| POST | `/jobs/retry-failed` | jobs:manage |
| GET | `/jobs` | jobs:read |

### Audit Logs
| Method | Path | Permission |
|--------|------|------------|
| GET | `/audit` | audit:read |
| GET | `/audit/summary` | audit:read |
| POST | `/audit/export` | audit:export |

### Billing
| Method | Path | Permission |
|--------|------|------------|
| GET | `/billing/plans` | public |
| GET | `/billing/summary` | billing:read |
| GET | `/billing/usage` | billing:read |
| GET | `/billing/quota` | authenticated |
| POST | `/billing/invoice` | billing:manage |

### Cache
| Method | Path | Permission |
|--------|------|------------|
| GET | `/cache/stats` | cache:read |
| POST | `/cache/flush` | cache:flush |

### Webhooks
| Method | Path | Permission |
|--------|------|------------|
| GET | `/webhooks` | authenticated |
| GET | `/webhooks/events` | authenticated |
| POST | `/webhooks` | auth:manage_api_keys |
| DELETE | `/webhooks/:id` | auth:manage_api_keys |
| POST | `/webhooks/:id/test` | authenticated |

### API Keys
| Method | Path | Permission |
|--------|------|------------|
| GET | `/api-keys` | auth:manage_api_keys |
| POST | `/api-keys` | auth:manage_api_keys |
| DELETE | `/api-keys/:id` | auth:manage_api_keys |
| POST | `/api-keys/:id/rotate` | auth:manage_api_keys |

### Real-Time SSE
```
GET /events/stream?token=<jwt>&subscribe=audit.entry,queue.stats
```
Event types: `audit.entry` · `queue.stats` · `security.token_reuse` · `job.completed` · `job.failed`

### System
| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Full health check |
| GET | `/ready` | Liveness probe |
| GET | `/overview` | Platform stats |

---

## Test Accounts (after seed)

| Email | Password | Role | Tenant |
|-------|----------|------|--------|
| `superadmin@tenantOS.io` | `SuperAdmin@123` | superadmin | ACME Corp |
| `alice@acme-corp.io` | `AliceAdmin@123` | admin | ACME Corp |
| `dev@acme-corp.io` | `DevUser@123` | developer | ACME Corp |
| `bob@nova-labs.io` | `BobAdmin@123` | admin | Nova Labs |
| `analyst@nova-labs.io` | `Analyst@123` | analyst | Nova Labs |
| `eve@zeta-systems.io` | `EveViewer@123` | viewer | Zeta Systems |

**Tenant IDs:**
```
ACME Corp     → a0000001-0000-0000-0000-000000000001
Nova Labs     → a0000002-0000-0000-0000-000000000002
Zeta Systems  → a0000003-0000-0000-0000-000000000003
```

---

## Role Permissions

| Permission | superadmin | admin | developer | analyst | viewer |
|-----------|:-:|:-:|:-:|:-:|:-:|
| tenants:read | ✓ | ✓ | — | — | — |
| tenants:create/delete | ✓ | — | — | — | — |
| tenants:update/suspend | ✓ | ✓ | — | — | — |
| users:create | ✓ | ✓ | — | — | — |
| users:read | ✓ | ✓ | ✓ | ✓ | ✓ |
| users:update/delete | ✓ | ✓ | — | — | — |
| audit:read | ✓ | ✓ | ✓ | ✓ | — |
| audit:export | ✓ | ✓ | — | ✓ | — |
| billing:read | ✓ | ✓ | — | ✓ | — |
| billing:manage | ✓ | ✓ | — | — | — |
| cache:read/flush | ✓ | ✓ | ✓ | — | — |
| jobs:read/manage | ✓ | ✓ | ✓ | ✓ | — |
| auth:manage_api_keys | ✓ | ✓ | ✓ | — | — |
| auth:manage_sessions | ✓ | ✓ | — | — | — |

---

## Security Features

**Refresh Token Rotation** — Every refresh issues a new token pair and marks the old one used. Presenting a used token (replay attack) immediately revokes the entire token family and terminates all sessions.

**Brute-Force Protection** — 5 failed logins → 15-minute account lockout. 20 attempts from one IP → IP block. All counters in Redis for instant distributed enforcement.

**TOTP MFA** — Pure RFC 6238 implementation (no library). Compatible with Google Authenticator, Authy, 1Password. Replay protection via Redis. 8 one-time backup codes.

**RBAC** — `role_permissions` table in PostgreSQL, cached in Redis (1h TTL). Middleware on every protected route. Denied access writes an audit event.

**Tenant Isolation** — Separate PostgreSQL schema per tenant. All Redis keys namespaced `tenantId:`. JWT `audience` claim matches tenant ID. Cross-tenant requests return 403.

---

## Production Checklist

```env
# Change these before going live:
JWT_ACCESS_SECRET=<64-char random hex>
JWT_REFRESH_SECRET=<64-char random hex — different from above>
POSTGRES_PASSWORD=<strong password>
REDIS_PASSWORD=<strong password>
SESSION_SECRET=<32+ char random>
BCRYPT_ROUNDS=12
NODE_ENV=production
POSTGRES_SSL=true
REDIS_TLS=true
LOG_TO_CLOUDWATCH=true
```

- Put behind Nginx with TLS (`docker/nginx.conf`)
- Configure `AWS_SECRETS_MANAGER_ARN` for automatic credential rotation
- Set `ALLOWED_ORIGINS` to your frontend domain
- Run `pg_cron` job for `SELECT cleanup_expired_tokens();` daily
