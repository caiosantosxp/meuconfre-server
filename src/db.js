const { Pool } = require('pg');

// SSL: managed Postgres geralmente exige. Controle por env PGSSL=true.
const ssl = process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : false;
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl });

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id         BIGSERIAL PRIMARY KEY,
      email      TEXT UNIQUE NOT NULL,
      pass       TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS vaults (
      user_id    BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      blob       JSONB,
      rev        INTEGER NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

module.exports = { pool, migrate };
