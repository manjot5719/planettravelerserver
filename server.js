// server.js
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { v4 } = require('uuid');

const DATABASE_URL = process.env.DATABASE_URL || null;
const DB_PATH = process.env.DB_PATH || './licenses.db';
const PORT = process.env.PORT || 3000;

// ADMIN_TOKEN may be provided via ENV for convenience; if not present we read from DB settings.
const ENV_ADMIN_TOKEN = process.env.ADMIN_TOKEN || null;

let dbSqlite = null;
let pgPool = null;
let usingPg = false;

if (DATABASE_URL) {
  usingPg = true;
  const { Pool } = require('pg');
  pgPool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
} else {
  const Database = require('better-sqlite3');
  dbSqlite = new Database(DB_PATH);
}

// helper to read setting ADMIN_TOKEN from DB (only if ENV_ADMIN_TOKEN not set)
async function getAdminToken() {
  if (ENV_ADMIN_TOKEN) return ENV_ADMIN_TOKEN;
  if (usingPg) {
    const r = await pgPool.query('SELECT v FROM settings WHERE k = $1', ['ADMIN_TOKEN']);
    return (r.rows[0] && r.rows[0].v) || null;
  } else {
    const row = dbSqlite.prepare('SELECT v FROM settings WHERE k = ?').get('ADMIN_TOKEN');
    return row && row.v;
  }
}

async function getLicenseRow(key) {
  if (usingPg) {
    const r = await pgPool.query('SELECT * FROM licenses WHERE key = $1', [key]);
    return r.rows[0] || null;
  } else {
    return dbSqlite.prepare('SELECT * FROM licenses WHERE key = ?').get(key);
  }
}

async function upsertLicenseDevices(key, devicesJson) {
  if (usingPg) {
    await pgPool.query('UPDATE licenses SET devices = $1 WHERE key = $2', [devicesJson, key]);
  } else {
    dbSqlite.prepare('UPDATE licenses SET devices = ? WHERE key = ?').run(devicesJson, key);
  }
}

const app = express();
app.use(bodyParser.json());
app.use(cors());

app.post('/verify', async (req, res) => {
  const { licenseKey, fingerprint } = req.body || {};
  if (!licenseKey || !fingerprint) return res.status(400).json({ ok:false, error:'missing' });

  try {
    const row = await getLicenseRow(licenseKey);
    if (!row) return res.json({ ok:true, valid:false, reason:'invalid' });
    if (row.status === 'blocked') return res.json({ ok:true, valid:false, reason:'blocked' });
    if (row.expires_at && Date.now() > Number(row.expires_at)) {
      return res.json({ ok:true, valid:false, reason:'expired' });
    }
    let devices = [];
    try { devices = JSON.parse(row.devices || '[]'); } catch (e) { devices = []; }

    if (devices.includes(fingerprint)) {
      return res.json({ ok:true, valid:true, status:'active' });
    }

    const maxDevices = Number(row.max_devices || 1);
    if (devices.length < maxDevices) {
      devices.push(fingerprint);
      await upsertLicenseDevices(licenseKey, JSON.stringify(devices));
      return res.json({ ok:true, valid:true, status:'activated', message:'device_added' });
    }

    return res.json({ ok:true, valid:false, reason:'device_mismatch', devices_count: devices.length });
  } catch (e) {
    console.error('verify error', e);
    return res.status(500).json({ ok:false, error:'server_error' });
  }
});

// Admin endpoints
function adminAuth(req) {
  return (req.headers['x-admin-token'] || req.body.adminToken);
}

app.post('/admin/create-license', async (req, res) => {
  const token = adminAuth(req);
  const ADMIN_TOKEN = await getAdminToken();
  if (!token || token !== ADMIN_TOKEN) return res.status(401).json({ ok:false, error:'unauthorized' });

  const { key, max_devices = 1, expires_at = null } = req.body;
  if (!key) return res.status(400).json({ ok:false, error:'need_key' });

  const now = Date.now();
  try {
    if (usingPg) {
      await pgPool.query('INSERT INTO licenses (key,status,max_devices,devices,created_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (key) DO UPDATE SET status = EXCLUDED.status, max_devices = EXCLUDED.max_devices, expires_at = EXCLUDED.expires_at', [key, 'active', max_devices, '[]', now, expires_at]);
    } else {
      dbSqlite.prepare('INSERT OR REPLACE INTO licenses (key, status, max_devices, devices, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)').run(key, 'active', max_devices, '[]', now, expires_at);
    }
    return res.json({ ok:true, created:key });
  } catch(e) {
    console.error('create-license', e);
    return res.status(500).json({ ok:false, error:'server_err' });
  }
});

app.post('/admin/block-license', async (req, res) => {
  const token = adminAuth(req);
  const ADMIN_TOKEN = await getAdminToken();
  if (!token || token !== ADMIN_TOKEN) return res.status(401).json({ ok:false, error:'unauthorized' });

  const { key } = req.body;
  if (!key) return res.status(400).json({ ok:false, error:'need_key' });

  try {
    if (usingPg) {
      await pgPool.query('UPDATE licenses SET status = $1 WHERE key = $2', ['blocked', key]);
    } else {
      dbSqlite.prepare('UPDATE licenses SET status = ? WHERE key = ?').run('blocked', key);
    }
    return res.json({ ok:true, blocked:key });
  } catch(e) {
    console.error('block-license', e);
    return res.status(500).json({ ok:false, error:'server_err' });
  }
});

app.post('/admin/unblock-license', async (req, res) => {
  const token = adminAuth(req);
  const ADMIN_TOKEN = await getAdminToken();
  if (!token || token !== ADMIN_TOKEN) return res.status(401).json({ ok:false, error:'unauthorized' });

  const { key } = req.body;
  if (!key) return res.status(400).json({ ok:false, error:'need_key' });

  try {
    if (usingPg) {
      await pgPool.query('UPDATE licenses SET status = $1 WHERE key = $2', ['active', key]);
    } else {
      dbSqlite.prepare('UPDATE licenses SET status = ? WHERE key = ?').run('active', key);
    }
    return res.json({ ok:true, unblocked:key });
  } catch(e) {
    console.error('unblock-license', e);
    return res.status(500).json({ ok:false, error:'server_err' });
  }
});

app.post('/admin/block-device', async (req, res) => {
  const token = adminAuth(req);
  const ADMIN_TOKEN = await getAdminToken();
  if (!token || token !== ADMIN_TOKEN) return res.status(401).json({ ok:false, error:'unauthorized' });

  const { key, fingerprint } = req.body;
  if (!key || !fingerprint) return res.status(400).json({ ok:false, error:'need_key_and_fp' });

  try {
    const row = await getLicenseRow(key);
    if (!row) return res.status(404).json({ ok:false, error:'license_not_found' });
    let devices = [];
    try { devices = JSON.parse(row.devices || '[]'); } catch(e){ devices = []; }
    devices = devices.filter(d => d !== fingerprint);
    await upsertLicenseDevices(key, JSON.stringify(devices));
    return res.json({ ok:true, key, devices });
  } catch(e) {
    console.error('block-device', e);
    return res.status(500).json({ ok:false, error:'server_err' });
  }
});

app.get('/', (req,res) => res.json({ok:true, msg:'license server running'}));

app.listen(PORT, () => {
  console.log('License server listening on port', PORT);
});
