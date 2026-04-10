/**
 * Database Migration Runner
 * Run: node scripts/migrate.js
 *
 * Applies SQL migration files in order.
 * Tracks applied migrations in a migrations table.
 */

require('dotenv').config();
const { Pool } = require('pg');
const fs   = require('fs');
const path = require('path');

const pool = new Pool({
  host:     process.env.POSTGRES_HOST || 'localhost',
  port:     parseInt(process.env.POSTGRES_PORT || '5432'),
  database: process.env.POSTGRES_DB   || 'tenantOS',
  user:     process.env.POSTGRES_USER || 'tenantOS_user',
  password: process.env.POSTGRES_PASSWORD,
  ssl: process.env.POSTGRES_SSL === 'true' ? { rejectUnauthorized: true } : false,
});

const MIGRATIONS_DIR = path.join(__dirname, 'migrations');
const MIGRATIONS_TABLE = 'schema_migrations';

async function ensureMigrationsTable(client) {
  await client.query(`
    CREATE TABLE IF NOT EXISTS ${MIGRATIONS_TABLE} (
      id          SERIAL PRIMARY KEY,
      filename    VARCHAR(255) UNIQUE NOT NULL,
      applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      checksum    VARCHAR(64) NOT NULL
    )
  `);
}

function checksum(content) {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(content).digest('hex').slice(0, 16);
}

async function getAppliedMigrations(client) {
  const result = await client.query(
    `SELECT filename, checksum FROM ${MIGRATIONS_TABLE} ORDER BY id`
  );
  return new Map(result.rows.map(r => [r.filename, r.checksum]));
}

async function getMigrationFiles() {
  if (!fs.existsSync(MIGRATIONS_DIR)) {
    fs.mkdirSync(MIGRATIONS_DIR, { recursive: true });
    console.log('Created migrations directory');
  }

  return fs.readdirSync(MIGRATIONS_DIR)
    .filter(f => f.endsWith('.sql'))
    .sort();
}

async function run() {
  console.log('🔄 Running database migrations...\n');
  const client = await pool.connect();

  try {
    await ensureMigrationsTable(client);
    const applied = await getAppliedMigrations(client);
    const files   = await getMigrationFiles();

    if (files.length === 0) {
      // Apply init.sql as the base migration
      const initPath = path.join(__dirname, 'init.sql');
      if (fs.existsSync(initPath)) {
        const content = fs.readFileSync(initPath, 'utf8');
        const cs = checksum(content);

        if (!applied.has('000_init.sql')) {
          console.log('  Applying: 000_init.sql (base schema)');
          await client.query('BEGIN');
          try {
            await client.query(content);
            await client.query(
              `INSERT INTO ${MIGRATIONS_TABLE} (filename, checksum) VALUES ($1, $2)`,
              ['000_init.sql', cs]
            );
            await client.query('COMMIT');
            console.log('  ✓ 000_init.sql applied\n');
          } catch (err) {
            await client.query('ROLLBACK');
            throw err;
          }
        } else {
          console.log('  ✓ Base schema already applied\n');
        }
      }
      console.log('No additional migration files found. Add .sql files to scripts/migrations/');
      return;
    }

    let applied_count = 0;
    let skipped_count = 0;

    for (const file of files) {
      if (applied.has(file)) {
        console.log(`  ○ Skip (already applied): ${file}`);
        skipped_count++;
        continue;
      }

      const filePath = path.join(MIGRATIONS_DIR, file);
      const content  = fs.readFileSync(filePath, 'utf8');
      const cs = checksum(content);

      console.log(`  → Applying: ${file}`);
      await client.query('BEGIN');
      try {
        await client.query(content);
        await client.query(
          `INSERT INTO ${MIGRATIONS_TABLE} (filename, checksum) VALUES ($1, $2)`,
          [file, cs]
        );
        await client.query('COMMIT');
        console.log(`  ✓ Applied: ${file}`);
        applied_count++;
      } catch (err) {
        await client.query('ROLLBACK');
        console.error(`  ✗ Failed: ${file}`);
        console.error(`    Error: ${err.message}`);
        throw err;
      }
    }

    console.log(`\n✅ Migrations complete. Applied: ${applied_count}, Skipped: ${skipped_count}`);
  } finally {
    client.release();
    await pool.end();
  }
}

run().catch(err => {
  console.error('\n❌ Migration failed:', err.message);
  process.exit(1);
});
