#!/usr/bin/env node
/**
 * TenantOS Setup Script
 * Run: node scripts/setup.js
 *
 * Does everything in order:
 *  1. Checks Node.js version
 *  2. Copies .env.example → .env (if not exists)
 *  3. Checks PostgreSQL + Redis connectivity
 *  4. Runs database migrations
 *  5. Seeds demo data
 *  6. Prints next steps
 */

'use strict';

const { execSync, spawn } = require('child_process');
const { existsSync, copyFileSync, readFileSync } = require('fs');
const path = require('path');
const net  = require('net');

// ── Colours ───────────────────────────────────────────────────
const C = { r:'\x1b[31m', g:'\x1b[32m', y:'\x1b[33m', b:'\x1b[36m', w:'\x1b[0m', bold:'\x1b[1m' };
const ok   = (m) => console.log(`  ${C.g}✓${C.w}  ${m}`);
const fail = (m) => console.log(`  ${C.r}✗${C.w}  ${m}`);
const info = (m) => console.log(`  ${C.b}→${C.w}  ${m}`);
const warn = (m) => console.log(`  ${C.y}⚠${C.w}  ${m}`);
const head = (m) => console.log(`\n${C.bold}${C.b}── ${m} ${C.w}`);

async function canConnect(host, port, timeout = 3000) {
  return new Promise(resolve => {
    const sock = new net.Socket();
    const done = (v) => { sock.destroy(); resolve(v); };
    sock.setTimeout(timeout);
    sock.on('connect', () => done(true));
    sock.on('error',   () => done(false));
    sock.on('timeout', () => done(false));
    sock.connect(port, host);
  });
}

function run(cmd, opts = {}) {
  return execSync(cmd, { stdio: opts.silent ? 'pipe' : 'inherit', cwd: path.join(__dirname, '..'), ...opts });
}

function runScript(script) {
  return new Promise((resolve, reject) => {
    const child = spawn('node', [path.join(__dirname, script)], {
      stdio: 'inherit', cwd: path.join(__dirname, '..'),
    });
    child.on('close', code => code === 0 ? resolve() : reject(new Error(`Exit code ${code}`)));
  });
}

async function main() {
  console.log(`\n${C.bold}${C.b}TenantOS — Automated Setup${C.w}\n`);

  // ── 1. Node version ──────────────────────────────────────
  head('Node.js Version');
  const nodeVer = parseInt(process.version.slice(1));
  if (nodeVer >= 18) ok(`Node.js ${process.version} (≥ 18 required)`);
  else { fail(`Node.js ${process.version} too old — need ≥ 18`); process.exit(1); }

  // ── 2. .env file ─────────────────────────────────────────
  head('Environment');
  const envPath    = path.join(__dirname, '..', '.env');
  const envExample = path.join(__dirname, '..', '.env.example');

  if (!existsSync(envPath)) {
    if (!existsSync(envExample)) { fail('.env.example not found'); process.exit(1); }
    copyFileSync(envExample, envPath);
    ok('.env created from .env.example');
    warn('Using default credentials — change passwords before production!');
  } else {
    ok('.env already exists');
  }

  require('dotenv').config({ path: envPath });

  // ── 3. Dependencies ───────────────────────────────────────
  head('Dependencies');
  const nodeModules = path.join(__dirname, '..', 'node_modules');
  if (!existsSync(nodeModules)) {
    info('Running npm install...');
    try { run('npm install --prefer-offline'); ok('Dependencies installed'); }
    catch { fail('npm install failed — check your internet connection'); process.exit(1); }
  } else {
    ok('node_modules found');
  }

  // ── 4. PostgreSQL ─────────────────────────────────────────
  head('PostgreSQL');
  const pgHost = process.env.POSTGRES_HOST || 'localhost';
  const pgPort = parseInt(process.env.POSTGRES_PORT || '5432');
  const pgReady = await canConnect(pgHost, pgPort);

  if (!pgReady) {
    fail(`Cannot reach PostgreSQL at ${pgHost}:${pgPort}`);
    info('Start with Docker:  docker-compose up -d postgres');
    info('Or install locally: https://postgresql.org/download');

    // Try Docker as fallback
    info('Attempting to start via Docker Compose...');
    try {
      run('docker-compose up -d postgres', { silent: true });
      info('Waiting 5s for PostgreSQL to initialise...');
      await new Promise(r => setTimeout(r, 5000));
      if (await canConnect(pgHost, pgPort)) ok('PostgreSQL started via Docker');
      else { fail('PostgreSQL still not reachable'); process.exit(1); }
    } catch {
      fail('Docker Compose not available. Start PostgreSQL manually.');
      process.exit(1);
    }
  } else {
    ok(`PostgreSQL reachable at ${pgHost}:${pgPort}`);
  }

  // ── 5. Redis ──────────────────────────────────────────────
  head('Redis');
  const redisHost = process.env.REDIS_HOST || 'localhost';
  const redisPort = parseInt(process.env.REDIS_PORT || '6379');
  const redisReady = await canConnect(redisHost, redisPort);

  if (!redisReady) {
    fail(`Cannot reach Redis at ${redisHost}:${redisPort}`);
    info('Attempting to start via Docker Compose...');
    try {
      run('docker-compose up -d redis', { silent: true });
      await new Promise(r => setTimeout(r, 3000));
      if (await canConnect(redisHost, redisPort)) ok('Redis started via Docker');
      else { fail('Redis still not reachable'); process.exit(1); }
    } catch {
      fail('Docker Compose not available. Start Redis manually.');
      process.exit(1);
    }
  } else {
    ok(`Redis reachable at ${redisHost}:${redisPort}`);
  }

  // ── 6. Migrations ─────────────────────────────────────────
  head('Database Migrations');
  try {
    await runScript('migrate.js');
    ok('Migrations complete');
  } catch (err) {
    fail(`Migration failed: ${err.message}`);
    process.exit(1);
  }

  // ── 7. Seed ───────────────────────────────────────────────
  head('Seed Data');
  try {
    await runScript('seed.js');
    ok('Demo data seeded');
  } catch (err) {
    warn(`Seed skipped or already done: ${err.message}`);
  }

  // ── 8. Summary ────────────────────────────────────────────
  console.log(`
${C.bold}${C.g}════════════════════════════════════════════════${C.w}
${C.bold}  ✓ Setup complete! Start the server:${C.w}

    ${C.b}npm run dev${C.w}        (development, auto-reload)
    ${C.b}npm start${C.w}          (production)
    ${C.b}npm run docker:up${C.w}  (full Docker stack)

${C.bold}  Dashboard:${C.w}  http://localhost:${process.env.PORT || 3000}

${C.bold}  Test accounts:${C.w}
    alice@acme-corp.io   /  AliceAdmin@123   (admin)
    dev@acme-corp.io     /  DevUser@123      (developer)
    bob@nova-labs.io     /  BobAdmin@123     (admin, Nova Labs)

${C.bold}  Tenant ID for login:${C.w}
    a0000001-0000-0000-0000-000000000001

${C.bold}  Run tests:${C.w}  npm test
${C.bold}${C.g}════════════════════════════════════════════════${C.w}
`);
}

main().catch(err => {
  fail(err.message);
  process.exit(1);
});
