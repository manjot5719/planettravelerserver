const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors({
    origin: ['http://localhost', 'http://127.0.0.1', 'file://'], // Allow local file access
    credentials: true
}));
app.use(bodyParser.json());
app.use(express.static('public'));

// Database setup - using persistent file
const db = new sqlite3.Database(path.join(__dirname, 'database.db'));

// Initialize database tables
db.serialize(() => {
  // Licenses table
  db.run(`CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT 1
  )`);
  
  // Devices table
  db.run(`CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT UNIQUE,
    license_key TEXT,
    user_agent TEXT,
    last_seen DATETIME,
    is_blocked BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(license_key) REFERENCES licenses(license_key)
  )`);
  
  // Admin users table
  db.run(`CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  // Check if admin user exists, if not create it
  db.get('SELECT COUNT(*) as count FROM admin_users', (err, row) => {
    if (err) {
      console.error('Error checking admin users:', err);
      return;
    }
    
    if (row.count === 0) {
      const passwordHash = bcrypt.hashSync('admin123', 10);
      db.run(`INSERT INTO admin_users (username, password_hash) VALUES (?, ?)`, ['admin', passwordHash], function(err) {
        if (err) {
          console.error('Error creating admin user:', err);
        } else {
          console.log('Default admin user created');
        }
      });
    }
  });
  
  // Insert some sample licenses if none exist
  db.get('SELECT COUNT(*) as count FROM licenses', (err, row) => {
    if (err) {
      console.error('Error checking licenses:', err);
      return;
    }
    
    if (row.count === 0) {
      db.run(`INSERT INTO licenses (license_key) VALUES (?)`, ['LICENSE-001']);
      db.run(`INSERT INTO licenses (license_key) VALUES (?)`, ['LICENSE-002']);
      console.log('Sample licenses created');
    }
  });
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Admin login endpoint
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  
  db.get('SELECT * FROM admin_users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token });
  });
});

// Verify license endpoint (used by client script)
app.post('/api/verify-license', (req, res) => {
  const { license_key, device_id, user_agent } = req.body;
  
  // Check if license exists and is active
  db.get('SELECT * FROM licenses WHERE license_key = ? AND is_active = 1', [license_key], (err, license) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!license) {
      return res.status(404).json({ error: 'Invalid or inactive license' });
    }
    
    // Check if device is blocked
    db.get('SELECT * FROM devices WHERE device_id = ? AND is_blocked = 1', [device_id], (err, device) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (device) {
        return res.status(403).json({ error: 'Device is blocked' });
      }
      
      // Update or create device record
      db.run(
        `INSERT INTO devices (device_id, license_key, user_agent, last_seen) 
         VALUES (?, ?, ?, datetime('now')) 
         ON CONFLICT(device_id) 
         DO UPDATE SET last_seen = datetime('now')`,
        [device_id, license_key, user_agent],
        function(err) {
          if (err) {
            return res.status(500).json({ error: 'Database error' });
          }
          
          res.json({ valid: true, message: 'License is valid' });
        }
      );
    });
  });
});

// Get all devices (admin only)
app.get('/api/devices', authenticateToken, (req, res) => {
  db.all(`
    SELECT d.*, l.created_at as license_created 
    FROM devices d 
    LEFT JOIN licenses l ON d.license_key = l.license_key 
    ORDER BY d.last_seen DESC
  `, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

// Get all licenses (admin only)
app.get('/api/licenses', authenticateToken, (req, res) => {
  db.all(`
    SELECT l.*, COUNT(d.id) as device_count 
    FROM licenses l 
    LEFT JOIN devices d ON l.license_key = d.license_key 
    GROUP BY l.id
  `, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

// Block a device (admin only)
app.post('/api/block-device', authenticateToken, (req, res) => {
  const { device_id } = req.body;
  
  db.run('UPDATE devices SET is_blocked = 1 WHERE device_id = ?', [device_id], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Device not found' });
    }
    
    res.json({ message: 'Device blocked successfully' });
  });
});

// Unblock a device (admin only)
app.post('/api/unblock-device', authenticateToken, (req, res) => {
  const { device_id } = req.body;
  
  db.run('UPDATE devices SET is_blocked = 0 WHERE device_id = ?', [device_id], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Device not found' });
    }
    
    res.json({ message: 'Device unblocked successfully' });
  });
});

// Create a new license (admin only)
app.post('/api/licenses', authenticateToken, (req, res) => {
  const { license_key } = req.body;
  
  db.run('INSERT INTO licenses (license_key) VALUES (?)', [license_key], function(err) {
    if (err) {
      if (err.message.includes('UNIQUE constraint failed')) {
        return res.status(409).json({ error: 'License key already exists' });
      }
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.json({ message: 'License created successfully', id: this.lastID });
  });
});

// Deactivate a license (admin only)
app.post('/api/deactivate-license', authenticateToken, (req, res) => {
  const { license_key } = req.body;
  
  db.run('UPDATE licenses SET is_active = 0 WHERE license_key = ?', [license_key], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'License not found' });
    }
    
    res.json({ message: 'License deactivated successfully' });
  });
});

// Reactivate a license (admin only)
app.post('/api/reactivate-license', authenticateToken, (req, res) => {
  const { license_key } = req.body;
  
  db.run('UPDATE licenses SET is_active = 1 WHERE license_key = ?', [license_key], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'License not found' });
    }
    
    res.json({ message: 'License reactivated successfully' });
  });
});

// Change admin password endpoint
app.post('/api/admin/change-password', authenticateToken, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const username = req.user.username;

  db.get('SELECT * FROM admin_users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!user || !bcrypt.compareSync(oldPassword, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid old password' });
    }

    const newHash = bcrypt.hashSync(newPassword, 10);
    db.run('UPDATE admin_users SET password_hash = ? WHERE username = ?', [newHash, username], function(err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json({ message: 'Password updated successfully' });
    });
  });
});

// Serve admin panel
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});