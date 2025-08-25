// create_db_safe.js
const fs = require('fs');
const { v4 } = require('uuid');

const DATABASE_URL = process.env.DATABASE_URL;
const DB_PATH = process.env.DB_PATH || './licenses.db';

async function initPostgres() {
  const { Client } = require('pg');
  const client = new Client({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();
  await client.query(`
    CREATE TABLE IF NOT EXISTS licenses (
      key TEXT PRIMARY KEY,
      status TEXT DEFAULT 'active',
      max_devices INTEGER DEFAULT 1,
      devices TEXT DEFAULT '[]',
      created_at BIGINT,
      expires_at BIGINT,
      meta TEXT DEFAULT '{}'
    );
    CREATE TABLE IF NOT EXISTS settings (
      k TEXT PRIMARY KEY,
      v TEXT
    );
  `);

  const res = await client.query('SELECT v FROM settings WHERE k = $1', ['ADMIN_TOKEN']);
  if (res.rowCount === 0) {
    const adminToken = process.env.ADMIN_TOKEN || v4();
    await client.query('INSERT INTO settings(k,v) VALUES($1,$2)', ['ADMIN_TOKEN', adminToken]);
    console.log('Generated ADMIN_TOKEN (save this):', adminToken);
  } else {
    console.log('ADMIN_TOKEN already exists in DB; not overwriting.');
  }
  await client.end();
}

function initSqlite() {
  const Database = require('better-sqlite3');
  const db = new Database(DB_PATH);

  db.exec(`
  CREATE TABLE IF NOT EXISTS licenses (
    key TEXT PRIMARY KEY,
    status TEXT DEFAULT 'active',
    max_devices INTEGER DEFAULT 1,
    devices TEXT DEFAULT '[]',
    created_at INTEGER,
    expires_at INTEGER DEFAULT NULL,
    meta TEXT DEFAULT '{}'
  );
  CREATE TABLE IF NOT EXISTS settings (
    k TEXT PRIMARY KEY,
    v TEXT
  );
  `);

  const row = db.prepare('SELECT v FROM settings WHERE k = ?').get('ADMIN_TOKEN');
  if (!row) {
    const adminToken = process.env.ADMIN_TOKEN || v4();
    db.prepare('INSERT INTO settings (k,v) VALUES (?,?)').run('ADMIN_TOKEN', adminToken);
    console.log('Generated ADMIN_TOKEN (save this):', adminToken);
  } else {
    console.log('ADMIN_TOKEN already exists in DB; not overwriting.');
  }
  db.close();
}

(async () => {
  if (DATABASE_URL) {
    console.log('Initializing Postgres database...');
    await initPostgres();
    console.log('Postgres init complete.');
  } else {
    console.log('Initializing SQLite database at', DB_PATH);
    initSqlite();
    console.log('SQLite init complete.');
  }
})();
