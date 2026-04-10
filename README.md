# TenantOS Backend v2.0

> Production-grade multi-tenant SaaS backend — Node.js · PostgreSQL · Redis · AWS · Docker

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Client (Dashboard / API consumer)                          │
└───────────────┬────────────────────────┬────────────────────┘
                │ HTTPS                  │ SSE (real-time)
┌───────────────▼────────────────────────▼────────────────────┐
│  Nginx  (TLS termination · rate limiting · reverse proxy)   │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│  Node.js / Express  (port 3000)                             │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ Auth Service│  │ RBAC Service│  │  Audit Service      │ │
│  │ JWT · Rot.  │  │ DB-backed   │  │  Immutable log      │ │
│  │ Sessions    │  │ Redis cache │  │  CloudWatch         │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ MFA (TOTP)  │  │ Queue Svc   │  │  Webhook Service    │ │
│  │ Backup codes│  │ Priority +  │  │  HMAC-signed        │ │
│  │             │  │ Retry/DLQ   │  │  Retry backoff      │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└──────┬────────────────┬──────────────────────┬──────────────┘
       │                │                      │
┌──────▼──────┐  ┌──────▼──────┐  ┌───────────▼────────────┐
│ PostgreSQL  │  │   Redis     │  │    AWS Services        │
│ 16-alpine   │  │  7-alpine   │  │  S3 · SES · SM · CW   │
│ Schema/     │  │  Sessions   │  │  (optional in dev)     │
│ tenant      │  │  Cache      │  │                        │
│ isolation   │  │  BF guards  │  │                        │
└─────────────┘  └─────────────┘  └────────────────────────┘
```

---

## Quick Start

### 1. Clone & configure

```bash
cp .env.example .env
# Edit .env — set passwords, JWT secrets (min 32 chars)
```

### 2. Start with Docker

```bash
docker-compose up -d
# Starts: postgres + redis + app + pgAdmin + redis-commander

# View logs
docker-compose logs -f app

# Run migrations + seed
docker-compose exec app node scripts/migrate.js
docker-compose exec app node scripts/seed.js
```

### 3. Without Docker

```bash
npm install
# Ensure PostgreSQL and Redis are running locally
node scripts/migrate.js
node scripts/seed.js
npm run dev
```

### 4. Run tests (no DB needed)

```bash
node tests/run.js
```

---

## Seed Credentials

After `node scripts/seed.js`:

| Email | Password | Role | Tenant |
|---|---|---|---|
| `superadmin@tenantOS.io` | `SuperAdmin@123` | superadmin | ACME Corp |
| `alice@acme-corp.io`     | `AliceAdmin@123` | admin | ACME Corp |
| `dev@acme-corp.io`       | `DevUser@123` | developer | ACME Corp |
| `bob@nova-labs.io`       | `BobAdmin@123` | admin | Nova Labs |
| `eve@zeta-systems.io`    | `EveViewer@123` | viewer | Zeta Systems |

Tenant IDs (use in `X-Tenant-ID` header):
- `a0000001-0000-0000-0000-000000000001` — ACME Corp (enterprise)
- `a0000002-0000-0000-0000-000000000002` — Nova Labs (pro)
- `a0000003-0000-0000-0000-000000000003` — Zeta Systems (trial)

---

## API Reference

**Base URL:** `http://localhost:3000/api/v1`

**Required headers:**
```
Content-Type:  application/json
X-Tenant-ID:   <tenant-uuid>          # required for all endpoints
Authorization: Bearer <access-token>  # required for protected endpoints
```

---

### Authentication

#### `POST /auth/register`
```json
{
  "email":     "alice@acme.com",
  "password":  "StrongPass1",
  "firstName": "Alice",
  "lastName":  "Johnson",
  "role":      "developer"
}
```
**Response:**
```json
{ "ok": true, "data": { "user": { "id": "...", "email": "...", "role": "developer" } } }
```

---

#### `POST /auth/login`
```json
{ "email": "alice@acme.com", "password": "StrongPass1" }
```
**Response:**
```json
{
  "ok": true,
  "data": {
    "accessToken":  "eyJ...",
    "refreshToken": "uuid-...",
    "tokenType":    "Bearer",
    "expiresIn":    900,
    "sessionId":    "...",
    "user": { "id": "...", "email": "...", "role": "admin", "tenantId": "..." }
  }
}
```
**Errors:** `401 INVALID_CREDENTIALS` · `423 ACCOUNT_LOCKED` · `429 TOO_MANY_ATTEMPTS`

---

#### `POST /auth/refresh`
```json
{ "refreshToken": "uuid-..." }
```
**Response:** New `accessToken` + `refreshToken` pair.
> ⚠️ Old refresh token is immediately invalidated. Reuse triggers family revocation.

---

#### `POST /auth/logout`
```json
{ "refreshToken": "uuid-..." }
```

#### `POST /auth/logout-all`
Revokes all active sessions for the current user.

#### `GET /auth/sessions`
Lists all active sessions for current user.

#### `DELETE /auth/sessions/:sessionId`
Revoke a specific session.

#### `GET /auth/me`
Current user profile + tenant info.

#### `POST /auth/change-password`
```json
{ "currentPassword": "old", "newPassword": "New1Pass!" }
```
> Automatically revokes all other sessions after password change.

---

### MFA (TOTP)

#### `POST /auth/mfa/setup`
Returns secret + QR code URI. Scan with Google Authenticator.

#### `POST /auth/mfa/confirm`
```json
{ "code": "123456" }
```
Activates MFA. Returns one-time backup codes.

#### `POST /auth/mfa/verify`
```json
{ "code": "123456" }
```

#### `POST /auth/mfa/disable`
```json
{ "code": "123456" }
```

#### `POST /auth/mfa/backup/regenerate`
```json
{ "code": "123456" }
```
Returns new backup codes (invalidates old ones).

---

### Tenants

| Method | Path | Permission |
|--------|------|-----------|
| `GET` | `/tenants` | `tenants:read` |
| `POST` | `/tenants` | `tenants:create` |
| `GET` | `/tenants/:id` | `tenants:read` |
| `PATCH` | `/tenants/:id` | `tenants:update` |
| `POST` | `/tenants/:id/suspend` | `tenants:suspend` |
| `POST` | `/tenants/:id/reactivate` | `tenants:suspend` |
| `GET` | `/tenants/:id/stats` | authenticated |
| `GET` | `/tenants/:id/usage` | authenticated |
| `PATCH` | `/tenants/:id/plan` | `billing:manage` |

---

### Users

| Method | Path | Permission |
|--------|------|-----------|
| `GET` | `/users` | `users:read` |
| `PATCH` | `/users/:id/role` | `users:update` |
| `DELETE` | `/users/:id` | `users:delete` |

---

### RBAC

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/rbac/permissions` | All permissions |
| `GET` | `/rbac/matrix` | Role → permissions matrix |
| `GET` | `/rbac/check?resource=&action=` | Check your permission |
| `POST` | `/rbac/grant` | Grant permission to role |

---

### Audit Logs

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/audit` | Query logs (filters: tenantId, type, severity, action, from, to) |
| `GET` | `/audit/summary` | Security summary for last N days |
| `POST` | `/audit/export` | Export to CSV / S3 |

---

### Jobs

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/jobs/queues` | All queue stats |
| `GET` | `/jobs/queues/:name` | Single queue stats |
| `POST` | `/jobs/queues/:name` | Enqueue a job |
| `POST` | `/jobs/retry-failed` | Retry all failed jobs |
| `GET` | `/jobs` | Tenant's job history |

---

### Cache

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/cache/stats` | Redis health + stats |
| `POST` | `/cache/flush` | Flush tenant cache |

---

### Webhooks

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/webhooks` | List endpoints |
| `GET` | `/webhooks/events` | Available event types |
| `POST` | `/webhooks` | Register endpoint |
| `DELETE` | `/webhooks/:id` | Remove endpoint |
| `POST` | `/webhooks/:id/test` | Send test payload |

---

### API Keys

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api-keys` | List your API keys |
| `POST` | `/api-keys` | Create new key |
| `DELETE` | `/api-keys/:id` | Revoke key |
| `POST` | `/api-keys/:id/rotate` | Rotate key |

---

### Real-Time Events (SSE)

```
GET /events/stream?token=<access_token>&subscribe=audit.entry,queue.stats
```

Event types: `audit.entry` · `queue.stats` · `security.token_reuse` ·
`security.brute_force` · `job.completed` · `job.failed` · `cache.flushed`

**JavaScript client:**
```javascript
const token  = localStorage.getItem('accessToken');
const events = new EventSource(
  `/api/v1/events/stream?token=${token}&subscribe=audit.entry,queue.stats`
);

events.onmessage = (e) => {
  const event = JSON.parse(e.data);
  console.log(event.type, event);
};
```

---

## Security Model

### Refresh Token Rotation
- Access tokens: 15-minute JWT, signed with `JWT_ACCESS_SECRET`
- Refresh tokens: 7-day, SHA-256 hashed before storage
- Each refresh issues a **new token** and marks old as used
- Reuse detection: presenting a used token → entire token family revoked → all sessions terminated

### Brute Force Protection
- Per-email sliding window: 5 failures → 15-minute lockout
- Per-IP sliding window: 20 failures in 15 min → IP block
- All attempts logged to `login_attempts` table
- Lockout state stored in Redis for instant enforcement

### RBAC
```
superadmin > admin > developer > analyst > viewer
```
Permissions are `resource:action` pairs stored in `role_permissions` table.
Cached in Redis (1h TTL) and invalidated on change.

### Tenant Isolation
- Each tenant gets its own PostgreSQL schema (`tenant_slug_db`)
- All Redis keys are prefixed with `tenantId:`
- JWT audience claim matches tenant ID
- Cross-tenant access blocked at middleware level (HTTP 403)
- Superadmin role can cross tenant boundaries

### MFA
- RFC 6238 TOTP (30-second windows, SHA-1 HMAC, 6 digits)
- Compatible with Google Authenticator, Authy, 1Password
- Replay protection via Redis (code hash stored for 90s)
- 8 single-use backup codes (SHA-256 hashed in DB)

---

## Environment Variables

See `.env.example` for all variables. Critical ones:

```env
JWT_ACCESS_SECRET=<min-32-chars-random>
JWT_REFRESH_SECRET=<min-32-chars-random-different>
POSTGRES_PASSWORD=<strong-password>
REDIS_PASSWORD=<strong-password>
BCRYPT_ROUNDS=12
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=15
```

---

## Docker Services

| Service | Port | URL |
|---------|------|-----|
| API | 3000 | http://localhost:3000 |
| pgAdmin | 5050 | http://localhost:5050 (admin@tenantOS.io / admin) |
| Redis Commander | 8081 | http://localhost:8081 |

Dev services (pgAdmin, Redis Commander) only start with:
```bash
docker-compose --profile dev up -d
```

---

## File Structure

```
tenantOS-v2/
├── Dockerfile                    # Multi-stage: dev + production
├── docker-compose.yml            # Postgres + Redis + App + Dev UIs
├── docker/nginx.conf             # Production reverse proxy
├── package.json
├── .env.example
├── scripts/
│   ├── init.sql                  # Base schema (18 tables)
│   ├── migrate.js                # Migration runner
│   ├── seed.js                   # Dev seed data
│   └── migrations/
│       └── 001_add_jobs_...sql   # Additional indexes + jobs table
├── src/
│   ├── index.js                  # Express app + startup
│   ├── config/
│   │   ├── database.js           # pg pool + transactions
│   │   ├── redis.js              # ioredis + all key operations
│   │   ├── aws.js                # S3, SES, Secrets Manager, CloudWatch
│   │   └── logger.js             # Winston + CloudWatch Logs
│   ├── middleware/
│   │   └── index.js              # Auth, brute-force, rate-limit, RBAC, validation
│   ├── services/
│   │   ├── auth.service.js       # Login, token rotation, logout, register
│   │   ├── mfa.service.js        # TOTP setup, verify, backup codes
│   │   ├── rbac.service.js       # Permission checks + role management
│   │   ├── audit.service.js      # Immutable event log + CSV export
│   │   ├── tenant.service.js     # Provisioning, stats, plan management
│   │   ├── queue.service.js      # Priority queue + retry + dead letter
│   │   ├── webhook.service.js    # HMAC-signed delivery + retry
│   │   ├── apikey.service.js     # API key lifecycle
│   │   └── realtime.service.js   # SSE event streaming
│   └── routes/
│       ├── auth.routes.js        # /auth/* endpoints
│       ├── extended.routes.js    # /auth/mfa, /webhooks, /events, /jobs
│       └── index.js              # All route mounting
└── tests/
    └── run.js                    # 108 tests, zero dependencies
```

---

## Production Checklist

- [ ] Rotate all secrets in `.env` (min 32-char random strings)
- [ ] Set `POSTGRES_SSL=true` + provide valid cert
- [ ] Set `REDIS_TLS=true`
- [ ] Set `LOG_TO_CLOUDWATCH=true` + configure log group
- [ ] Configure `AWS_SECRETS_MANAGER_ARN` for credential rotation
- [ ] Put application behind Nginx with TLS (`docker/nginx.conf`)
- [ ] Set `NODE_ENV=production`
- [ ] Configure `ALLOWED_ORIGINS` to match your frontend domain
- [ ] Set up pg_cron for `cleanup_expired_tokens()` (daily)
- [ ] Enable PostgreSQL connection pooling (PgBouncer in production)
- [ ] Set up Redis Sentinel or Redis Cluster for HA
