/**
 * Database Seed Script
 * Run: node scripts/seed.js
 *
 * Creates demo tenants, users, and sample data for development.
 * Safe to re-run — uses ON CONFLICT DO NOTHING.
 */

require('dotenv').config();
const { Pool } = require('pg');
const bcrypt   = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const pool = new Pool({
  host:     process.env.POSTGRES_HOST || 'localhost',
  port:     parseInt(process.env.POSTGRES_PORT || '5432'),
  database: process.env.POSTGRES_DB   || 'tenantOS',
  user:     process.env.POSTGRES_USER || 'tenantOS_user',
  password: process.env.POSTGRES_PASSWORD,
  ssl: process.env.POSTGRES_SSL === 'true' ? { rejectUnauthorized: true } : false,
});

const BCRYPT_ROUNDS = 10; // lower for seeding speed

// ─── SEED DATA ────────────────────────────────────────────────

const tenants = [
  {
    id:        'a0000001-0000-0000-0000-000000000001',
    slug:      'acme-corp',
    name:      'ACME Corp',
    plan:      'enterprise',
    region:    'us-east-1',
    db_schema: 'tenant_acme_corp',
    rate_limit: 5000,
    max_users:  500,
  },
  {
    id:        'a0000002-0000-0000-0000-000000000002',
    slug:      'nova-labs',
    name:      'Nova Labs',
    plan:      'pro',
    region:    'eu-west-1',
    db_schema: 'tenant_nova_labs',
    rate_limit: 1000,
    max_users:  25,
  },
  {
    id:        'a0000003-0000-0000-0000-000000000003',
    slug:      'zeta-systems',
    name:      'Zeta Systems',
    plan:      'trial',
    region:    'ap-south-1',
    db_schema: 'tenant_zeta_systems',
    rate_limit: 100,
    max_users:  3,
  },
];

const users = [
  // ACME Corp
  {
    id:         'b0000001-0000-0000-0000-000000000001',
    tenant_id:  'a0000001-0000-0000-0000-000000000001',
    email:      'superadmin@tenantOS.io',
    password:   'SuperAdmin@123',
    role:       'superadmin',
    first_name: 'Super',
    last_name:  'Admin',
    email_verified: true,
  },
  {
    id:         'b0000002-0000-0000-0000-000000000002',
    tenant_id:  'a0000001-0000-0000-0000-000000000001',
    email:      'alice@acme-corp.io',
    password:   'AliceAdmin@123',
    role:       'admin',
    first_name: 'Alice',
    last_name:  'Johnson',
    email_verified: true,
  },
  {
    id:         'b0000003-0000-0000-0000-000000000003',
    tenant_id:  'a0000001-0000-0000-0000-000000000001',
    email:      'dev@acme-corp.io',
    password:   'DevUser@123',
    role:       'developer',
    first_name: 'Frank',
    last_name:  'Chen',
    email_verified: true,
  },
  // Nova Labs
  {
    id:         'b0000004-0000-0000-0000-000000000004',
    tenant_id:  'a0000002-0000-0000-0000-000000000002',
    email:      'bob@nova-labs.io',
    password:   'BobAdmin@123',
    role:       'admin',
    first_name: 'Bob',
    last_name:  'Martinez',
    email_verified: true,
  },
  {
    id:         'b0000005-0000-0000-0000-000000000005',
    tenant_id:  'a0000002-0000-0000-0000-000000000002',
    email:      'analyst@nova-labs.io',
    password:   'Analyst@123',
    role:       'analyst',
    first_name: 'Carol',
    last_name:  'Singh',
    email_verified: false,
  },
  // Zeta Systems
  {
    id:         'b0000006-0000-0000-0000-000000000006',
    tenant_id:  'a0000003-0000-0000-0000-000000000003',
    email:      'eve@zeta-systems.io',
    password:   'EveViewer@123',
    role:       'viewer',
    first_name: 'Eve',
    last_name:  'Williams',
    email_verified: true,
  },
];

// ─── HELPERS ─────────────────────────────────────────────────

function log(msg) { process.stdout.write(`  ${msg}\n`); }
function ok(msg)  { process.stdout.write(`  ✓ ${msg}\n`); }
function skip(msg){ process.stdout.write(`  ○ ${msg} (already exists)\n`); }

// ─── SEED FUNCTIONS ───────────────────────────────────────────

async function seedTenants(client) {
  console.log('\n── Tenants ──────────────────────────────────────');
  for (const t of tenants) {
    const result = await client.query(
      `INSERT INTO tenants (id, slug, name, plan, region, db_schema, rate_limit, max_users, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active')
       ON CONFLICT (id) DO NOTHING
       RETURNING id`,
      [t.id, t.slug, t.name, t.plan, t.region, t.db_schema, t.rate_limit, t.max_users]
    );

    if (result.rows.length) ok(`Tenant: ${t.name} (${t.plan})`);
    else skip(`Tenant: ${t.name}`);

    // Create schema
    await client.query(`CREATE SCHEMA IF NOT EXISTS "${t.db_schema}"`);
  }
}

async function seedUsers(client) {
  console.log('\n── Users ────────────────────────────────────────');
  for (const u of users) {
    const hash = await bcrypt.hash(u.password, BCRYPT_ROUNDS);
    const result = await client.query(
      `INSERT INTO users
       (id, tenant_id, email, password_hash, role, first_name, last_name, email_verified, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active')
       ON CONFLICT (id) DO NOTHING
       RETURNING id`,
      [u.id, u.tenant_id, u.email, hash, u.role, u.first_name, u.last_name, u.email_verified]
    );

    if (result.rows.length) ok(`User: ${u.email} [${u.role}] (password: ${u.password})`);
    else skip(`User: ${u.email}`);
  }
}

async function seedAuditLog(client) {
  console.log('\n── Audit Log (sample events) ────────────────────');
  const events = [
    ['a0000001-0000-0000-0000-000000000001', 'b0000002-0000-0000-0000-000000000002', 'auth',     'info',     'LOGIN_SUCCESS',      '192.168.1.1'],
    ['a0000001-0000-0000-0000-000000000001', 'b0000003-0000-0000-0000-000000000003', 'auth',     'warning',  'LOGIN_FAILED',       '10.0.0.5'],
    ['a0000002-0000-0000-0000-000000000002', 'b0000004-0000-0000-0000-000000000004', 'user',     'info',     'USER_INVITED',       '172.16.0.1'],
    ['a0000001-0000-0000-0000-000000000001', 'b0000002-0000-0000-0000-000000000002', 'security', 'critical', 'REFRESH_TOKEN_REUSE','203.0.113.42'],
    ['a0000003-0000-0000-0000-000000000003', 'b0000006-0000-0000-0000-000000000006', 'auth',     'info',     'LOGIN_SUCCESS',      '198.51.100.7'],
    ['a0000001-0000-0000-0000-000000000001', null,                                   'system',   'info',     'SERVER_STARTED',     null],
  ];

  for (const [tid, uid, type, severity, action, ip] of events) {
    await client.query(
      `INSERT INTO audit_logs (tenant_id, user_id, type, severity, action, ip_address)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [tid, uid, type, severity, action, ip]
    );
  }
  ok(`${events.length} audit events inserted`);
}

async function seedLoginAttempts(client) {
  console.log('\n── Login Attempts (history) ─────────────────────');
  const attempts = [
    ['a0000001-0000-0000-0000-000000000001', 'alice@acme-corp.io',    '192.168.1.1',   true,  null],
    ['a0000001-0000-0000-0000-000000000001', 'alice@acme-corp.io',    '10.10.10.1',    false, 'invalid_password'],
    ['a0000001-0000-0000-0000-000000000001', 'hacker@external.com',   '203.0.113.99',  false, 'user_not_found'],
    ['a0000001-0000-0000-0000-000000000001', 'hacker@external.com',   '203.0.113.99',  false, 'user_not_found'],
    ['a0000002-0000-0000-0000-000000000002', 'bob@nova-labs.io',      '172.16.0.10',   true,  null],
  ];

  for (const [tid, email, ip, success, reason] of attempts) {
    await client.query(
      `INSERT INTO login_attempts (tenant_id, email, ip_address, success, failure_reason)
       VALUES ($1,$2,$3,$4,$5)`,
      [tid, email, ip, success, reason]
    );
  }
  ok(`${attempts.length} login attempt records inserted`);
}

// ─── MAIN ────────────────────────────────────────────────────

async function seed() {
  console.log('🌱 Seeding database...');
  const client = await pool.connect();
  try {
    await seedTenants(client);
    await seedUsers(client);
    await seedAuditLog(client);
    await seedLoginAttempts(client);

    console.log('\n' + '═'.repeat(56));
    console.log('✅ Seed complete!\n');
    console.log('Test credentials:');
    users.forEach(u => {
      console.log(`  ${u.email.padEnd(35)} password: ${u.password}`);
    });
    console.log('\nTenant IDs:');
    tenants.forEach(t => {
      console.log(`  ${t.slug.padEnd(20)} → ${t.id}`);
    });
    console.log('═'.repeat(56));
  } catch (err) {
    console.error('\n❌ Seed failed:', err.message);
    throw err;
  } finally {
    client.release();
    await pool.end();
  }
}

seed().catch(() => process.exit(1));
