const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Low, JSONFile } = require('lowdb');
const crypto = require('crypto'); // Use built-in crypto module instead of uuid

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors({
    origin: '*', // Allow all origins for now
    credentials: true
}));
app.use(bodyParser.json());

// Database setup - using LowDB with in-memory storage
const adapter = new JSONFile('./db.json');
const db = new Low(adapter);

// Generate UUID using crypto module
function generateUUID() {
  return crypto.randomUUID();
}

// Initialize database
async function initializeDB() {
  await db.read();
  
  // Set default data if empty
  db.data ||= { 
    licenses: [],
    devices: [],
    admin_users: []
  };
  
  // Check if admin user exists, if not create it
  if (db.data.admin_users.length === 0) {
    const passwordHash = bcrypt.hashSync('admin123', 10);
    db.data.admin_users.push({
      id: generateUUID(),
      username: 'admin',
      password_hash: passwordHash,
      created_at: new Date().toISOString()
    });
  }
  
  // Check if sample licenses exist
  if (db.data.licenses.length === 0) {
    db.data.licenses.push(
      {
        id: generateUUID(),
        license_key: 'LICENSE-001',
        created_at: new Date().toISOString(),
        is_active: true
      },
      {
        id: generateUUID(),
        license_key: 'LICENSE-002',
        created_at: new Date().toISOString(),
        is_active: true
      }
    );
  }
  
  await db.write();
}

// Initialize database on server start
initializeDB();


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
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  
  await db.read();
  const user = db.data.admin_users.find(u => u.username === username);
  
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token });
});

// Verify license endpoint (used by client script)
app.post('/api/verify-license', async (req, res) => {
  const { license_key, device_id, user_agent } = req.body;
  
  await db.read();
  
  // Check if license exists and is active
  const license = db.data.licenses.find(l => l.license_key === license_key && l.is_active);
  
  if (!license) {
    return res.status(404).json({ error: 'Invalid or inactive license' });
  }
  
  // Check if device is blocked
  const device = db.data.devices.find(d => d.device_id === device_id && d.is_blocked);
  
  if (device) {
    return res.status(403).json({ error: 'Device is blocked' });
  }
  
  // Update or create device record
  const existingDeviceIndex = db.data.devices.findIndex(d => d.device_id === device_id);
  
  if (existingDeviceIndex !== -1) {
    // Update existing device
    db.data.devices[existingDeviceIndex].last_seen = new Date().toISOString();
    db.data.devices[existingDeviceIndex].user_agent = user_agent;
  } else {
    // Create new device
    db.data.devices.push({
      id: generateUUID(),
      device_id,
      license_key,
      user_agent,
      last_seen: new Date().toISOString(),
      is_blocked: false,
      created_at: new Date().toISOString()
    });
  }
  
  await db.write();
  res.json({ valid: true, message: 'License is valid' });
});

// Get all devices (admin only)
app.get('/api/devices', authenticateToken, async (req, res) => {
  await db.read();
  
  // Add license creation date to each device
  const devicesWithLicenseInfo = db.data.devices.map(device => {
    const license = db.data.licenses.find(l => l.license_key === device.license_key);
    return {
      ...device,
      license_created: license ? license.created_at : null
    };
  });
  
  // Sort by last seen (newest first)
  devicesWithLicenseInfo.sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));
  
  res.json(devicesWithLicenseInfo);
});

// Get all licenses (admin only)
app.get('/api/licenses', authenticateToken, async (req, res) => {
  await db.read();
  
  // Add device count to each license
  const licensesWithDeviceCount = db.data.licenses.map(license => {
    const deviceCount = db.data.devices.filter(d => d.license_key === license.license_key).length;
    return {
      ...license,
      device_count: deviceCount
    };
  });
  
  res.json(licensesWithDeviceCount);
});

// Block a device (admin only)
app.post('/api/block-device', authenticateToken, async (req, res) => {
  const { device_id } = req.body;
  
  await db.read();
  const deviceIndex = db.data.devices.findIndex(d => d.device_id === device_id);
  
  if (deviceIndex === -1) {
    return res.status(404).json({ error: 'Device not found' });
  }
  
  db.data.devices[deviceIndex].is_blocked = true;
  await db.write();
  
  res.json({ message: 'Device blocked successfully' });
});

// Unblock a device (admin only)
app.post('/api/unblock-device', authenticateToken, async (req, res) => {
  const { device_id } = req.body;
  
  await db.read();
  const deviceIndex = db.data.devices.findIndex(d => d.device_id === device_id);
  
  if (deviceIndex === -1) {
    return res.status(404).json({ error: 'Device not found' });
  }
  
  db.data.devices[deviceIndex].is_blocked = false;
  await db.write();
  
  res.json({ message: 'Device unblocked successfully' });
});

// Create a new license (admin only)
app.post('/api/licenses', authenticateToken, async (req, res) => {
  const { license_key } = req.body;
  
  await db.read();
  
  // Check if license already exists
  if (db.data.licenses.some(l => l.license_key === license_key)) {
    return res.status(409).json({ error: 'License key already exists' });
  }
  
  // Create new license
  const newLicense = {
    id: generateUUID(),
    license_key,
    created_at: new Date().toISOString(),
    is_active: true
  };
  
  db.data.licenses.push(newLicense);
  await db.write();
  
  res.json({ message: 'License created successfully', id: newLicense.id });
});

// Deactivate a license (admin only)
app.post('/api/deactivate-license', authenticateToken, async (req, res) => {
  const { license_key } = req.body;
  
  await db.read();
  const licenseIndex = db.data.licenses.findIndex(l => l.license_key === license_key);
  
  if (licenseIndex === -1) {
    return res.status(404).json({ error: 'License not found' });
  }
  
  db.data.licenses[licenseIndex].is_active = false;
  await db.write();
  
  res.json({ message: 'License deactivated successfully' });
});

// Reactivate a license (admin only)
app.post('/api/reactivate-license', authenticateToken, async (req, res) => {
  const { license_key } = req.body;
  
  await db.read();
  const licenseIndex = db.data.licenses.findIndex(l => l.license_key === license_key);
  
  if (licenseIndex === -1) {
    return res.status(404).json({ error: 'License not found' });
  }
  
  db.data.licenses[licenseIndex].is_active = true;
  await db.write();
  
  res.json({ message: 'License reactivated successfully' });
});

// Change admin password endpoint
app.post('/api/admin/change-password', authenticateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const username = req.user.username;

  await db.read();
  const userIndex = db.data.admin_users.findIndex(u => u.username === username);
  
  if (userIndex === -1 || !bcrypt.compareSync(oldPassword, db.data.admin_users[userIndex].password_hash)) {
    return res.status(401).json({ error: 'Invalid old password' });
  }

  const newHash = bcrypt.hashSync(newPassword, 10);
  db.data.admin_users[userIndex].password_hash = newHash;
  await db.write();
  
  res.json({ message: 'Password updated successfully' });
});

// Serve admin panel
app.get('/admin', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Planet Traveler - Admin Panel</title>
        <style>
            :root {
                --primary: #2c3e50;
                --secondary: #34495e;
                --accent: #3498db;
                --success: #2ecc71;
                --danger: #e74c3c;
                --warning: #f39c12;
                --light: #ecf0f1;
                --dark: #2c3e50;
            }
            
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            
            body {
                background-color: #f5f7fa;
                color: #333;
                line-height: 1.6;
            }
            
            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }
            
            header {
                background: linear-gradient(to right, var(--primary), var(--secondary));
                color: white;
                padding: 20px 0;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                margin-bottom: 30px;
            }
            
            .header-content {
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            h1 {
                font-size: 28px;
                font-weight: 600;
            }
            
            .auth-section {
                background: white;
                padding: 25px;
                border-radius: 10px;
                box-shadow: 0 4px 10px rgba(0, 0, 0, 0.08);
                margin-bottom: 30px;
            }
            
            .form-group {
                margin-bottom: 20px;
            }
            
            label {
                display: block;
                margin-bottom: 8px;
                font-weight: 500;
                color: var(--dark);
            }
            
            input[type="text"],
            input[type="password"] {
                width: 100%;
                padding: 12px 15px;
                border: 1px solid #ddd;
                border-radius: 6px;
                font-size: 16px;
                transition: border-color 0.3s;
            }
            
            input:focus {
                border-color: var(--accent);
                outline: none;
                box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.2);
            }
            
            button {
                padding: 12px 20px;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-size: 16px;
                font-weight: 500;
                transition: all 0.3s;
            }
            
            .btn-primary {
                background-color: var(--accent);
                color: white;
            }
            
            .btn-primary:hover {
                background-color: #2980b9;
            }
            
            .btn-success {
                background-color: var(--success);
                color: white;
            }
            
            .btn-danger {
                background-color: var(--danger);
                color: white;
            }
            
            .btn-warning {
                background-color: var(--warning);
                color: white;
            }
            
            .dashboard {
                display: none;
            }
            
            .card {
                background: white;
                border-radius: 10px;
                box-shadow: 0 4px 10px rgba(0, 0, 0, 0.08);
                margin-bottom: 30px;
                overflow: hidden;
            }
            
            .card-header {
                background-color: var(--primary);
                color: white;
                padding: 15px 20px;
                font-weight: 500;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            .card-body {
                padding: 20px;
            }
            
            table {
                width: 100%;
                border-collapse: collapse;
            }
            
            th, td {
                padding: 12px 15px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }
            
            th {
                background-color: #f8f9fa;
                font-weight: 600;
            }
            
            tr:hover {
                background-color: #f8f9fa;
            }
            
            .status-active {
                color: var(--success);
                font-weight: 500;
            }
            
            .status-inactive {
                color: var(--danger);
                font-weight: 500;
            }
            
            .status-blocked {
                color: var(--warning);
                font-weight: 500;
            }
            
            .action-buttons {
                display: flex;
                gap: 10px;
            }
            
            .action-btn {
                padding: 6px 12px;
                font-size: 14px;
            }
            
            .stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            
            .stat-card {
                background: white;
                border-radius: 10px;
                box-shadow: 0 4px 10px rgba(0, 0, 0, 0.08);
                padding: 20px;
                text-align: center;
            }
            
            .stat-value {
                font-size: 32px;
                font-weight: 700;
                margin: 10px 0;
                color: var(--primary);
            }
            
            .stat-label {
                color: #7f8c8d;
                font-size: 16px;
            }
            
            .alert {
                padding: 15px;
                border-radius: 6px;
                margin-bottom: 20px;
                display: none;
            }
            
            .alert-success {
                background-color: #d4edda;
                color: #155724;
                border: 1px solid #c3e6cb;
            }
            
            .alert-error {
                background-color: #f8d7da;
                color: #721c24;
                border: 1px solid #f5c6cb;
            }
            
            @media (max-width: 768px) {
                .stats {
                    grid-template-columns: 1fr;
                }
                
                .action-buttons {
                    flex-direction: column;
                }
            }
        </style>
    </head>
    <body>
        <header>
            <div class="container header-content">
                <h1>Planet Traveler Admin Panel</h1>
                <div id="userInfo" style="display: none;">
                    <span id="usernameDisplay"></span>
                    <button id="logoutBtn" class="btn-danger" style="margin-left: 15px;">Logout</button>
                </div>
            </div>
        </header>

        <div class="container">
            <div id="authSection" class="auth-section">
                <h2 style="margin-bottom: 20px;">Admin Login</h2>
                <div id="loginAlert" class="alert"></div>
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" placeholder="Enter username" value="admin">
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" placeholder="Enter password" value="admin123">
                </div>
                <button id="loginBtn" class="btn-primary">Login</button>
            </div>

            <div id="dashboard" class="dashboard">
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-label">Total Licenses</div>
                        <div id="totalLicenses" class="stat-value">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Active Licenses</div>
                        <div id="activeLicenses" class="stat-value">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Registered Devices</div>
                        <div id="totalDevices" class="stat-value">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Blocked Devices</div>
                        <div id="blockedDevices" class="stat-value">0</div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <span>License Management</span>
                        <div>
                            <input type="text" id="newLicenseKey" placeholder="New license key" style="padding: 8px; margin-right: 10px;">
                            <button id="addLicenseBtn" class="btn-success">Add License</button>
                        </div>
                    </div>
                    <div class="card-body">
                        <div id="licenseAlert" class="alert"></div>
                        <table id="licensesTable">
                            <thead>
                                <tr>
                                    <th>License Key</th>
                                    <th>Created At</th>
                                    <th>Status</th>
                                    <th>Device Count</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody></tbody>
                        </table>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">Device Management</div>
                    <div class="card-body">
                        <div id="deviceAlert" class="alert"></div>
                        <table id="devicesTable">
                            <thead>
                                <tr>
                                    <th>Device ID</th>
                                    <th>License Key</th>
                                    <th>User Agent</th>
                                    <th>Last Seen</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <script>
            // UPDATE THIS LINE to use your Render URL
            const API_BASE = 'https://planettravelerlicence.onrender.com';
            
            let authToken = localStorage.getItem('adminToken');
            
            // DOM Elements
            const authSection = document.getElementById('authSection');
            const dashboard = document.getElementById('dashboard');
            const userInfo = document.getElementById('userInfo');
            const usernameDisplay = document.getElementById('usernameDisplay');
            const loginAlert = document.getElementById('loginAlert');
            const licenseAlert = document.getElementById('licenseAlert');
            const deviceAlert = document.getElementById('deviceAlert');
            
            // Check if already logged in
            if (authToken) {
                verifyToken();
            }
            
            // Event Listeners
            document.getElementById('loginBtn').addEventListener('click', login);
            document.getElementById('logoutBtn').addEventListener('click', logout);
            document.getElementById('addLicenseBtn').addEventListener('click', addLicense);
            
            // Login function
            async function login() {
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                
                if (!username || !password) {
                    showAlert(loginAlert, 'Please enter both username and password', 'error');
                    return;
                }
                
                try {
                    const response = await fetch(API_BASE + '/api/admin/login', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ username, password })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        authToken = data.token;
                        localStorage.setItem('adminToken', authToken);
                        showDashboard();
                        loadData();
                    } else {
                        showAlert(loginAlert, data.error, 'error');
                    }
                } catch (error) {
                    showAlert(loginAlert, 'Login failed. Please check your connection.', 'error');
                    console.error('Login error:', error);
                }
            }
            
            // Verify token on page load
            async function verifyToken() {
                try {
                    const response = await fetch(API_BASE + '/api/licenses', {
                        headers: {
                            'Authorization': 'Bearer ' + authToken
                        }
                    });
                    
                    if (response.ok) {
                        showDashboard();
                        loadData();
                    } else {
                        localStorage.removeItem('adminToken');
                        authToken = null;
                    }
                } catch (error) {
                    localStorage.removeItem('adminToken');
                    authToken = null;
                }
            }
            
            // Logout function
            function logout() {
                localStorage.removeItem('adminToken');
                authToken = null;
                dashboard.style.display = 'none';
                userInfo.style.display = 'none';
                authSection.style.display = 'block';
            }
            
            // Show dashboard
            function showDashboard() {
                authSection.style.display = 'none';
                dashboard.style.display = 'block';
                userInfo.style.display = 'block';
                
                // Extract username from token
                const payload = JSON.parse(atob(authToken.split('.')[1]));
                usernameDisplay.textContent = payload.username;
            }
            
            // Load licenses and devices
            async function loadData() {
                await loadLicenses();
                await loadDevices();
                updateStats();
            }
            
            // Load licenses
            async function loadLicenses() {
                try {
                    const response = await fetch(API_BASE + '/api/licenses', {
                        headers: {
                            'Authorization': 'Bearer ' + authToken
                        }
                    });
                    
                    if (response.ok) {
                        const licenses = await response.json();
                        renderLicenses(licenses);
                    } else {
                        if (response.status === 401) {
                            logout();
                        }
                    }
                } catch (error) {
                    showAlert(licenseAlert, 'Failed to load licenses', 'error');
                }
            }
            
            // Load devices
            async function loadDevices() {
                try {
                    const response = await fetch(API_BASE + '/api/devices', {
                        headers: {
                            'Authorization': 'Bearer ' + authToken
                        }
                    });
                    
                    if (response.ok) {
                        const devices = await response.json();
                        renderDevices(devices);
                    } else {
                        if (response.status === 401) {
                            logout();
                        }
                    }
                } catch (error) {
                    showAlert(deviceAlert, 'Failed to load devices', 'error');
                }
            }
            
            // Render licenses table
            function renderLicenses(licenses) {
                const tbody = document.querySelector('#licensesTable tbody');
                tbody.innerHTML = '';
                
                licenses.forEach(license => {
                    const tr = document.createElement('tr');
                    
                    tr.innerHTML = \`
                        <td>\${license.license_key}</td>
                        <td>\${new Date(license.created_at).toLocaleString()}</td>
                        <td class="\${license.is_active ? 'status-active' : 'status-inactive'}">
                            \${license.is_active ? 'Active' : 'Inactive'}
                        </td>
                        <td>\${license.device_count}</td>
                        <td class="action-buttons">
                            \${license.is_active ? 
                                '<button class="btn-warning action-btn" onclick="deactivateLicense(\\'' + license.license_key + '\\')">Deactivate</button>' :
                                '<button class="btn-success action-btn" onclick="activateLicense(\\'' + license.license_key + '\\')">Activate</button>'
                            }
                        </td>
                    \`;
                    
                    tbody.appendChild(tr);
                });
                
                updateStats();
            }
            
            // Render devices table
            function renderDevices(devices) {
                const tbody = document.querySelector('#devicesTable tbody');
                tbody.innerHTML = '';
                
                devices.forEach(device => {
                    const tr = document.createElement('tr');
                    
                    tr.innerHTML = \`
                        <td>\${device.device_id}</td>
                        <td>\${device.license_key}</td>
                        <td title="\${device.user_agent}">\${device.user_agent ? device.user_agent.substring(0, 30) + '...' : 'N/A'}</td>
                        <td>\${device.last_seen ? new Date(device.last_seen).toLocaleString() : 'Never'}</td>
                        <td class="\${device.is_blocked ? 'status-blocked' : 'status-active'}">
                            \${device.is_blocked ? 'Blocked' : 'Active'}
                        </td>
                        <td class="action-buttons">
                            \${device.is_blocked ? 
                                '<button class="btn-success action-btn" onclick="unblockDevice(\\'' + device.device_id + '\\')">Unblock</button>' :
                                '<button class="btn-danger action-btn" onclick="blockDevice(\\'' + device.device_id + '\\')">Block</button>'
                            }
                        </td>
                    \`;
                    
                    tbody.appendChild(tr);
                });
                
                updateStats();
            }
            
            // Update statistics
            function updateStats() {
                const licenses = document.querySelectorAll('#licensesTable tbody tr');
                const devices = document.querySelectorAll('#devicesTable tbody tr');
                
                const activeLicenses = Array.from(licenses).filter(tr => 
                    tr.querySelector('td:nth-child(3)').classList.contains('status-active')
                ).length;
                
                const blockedDevices = Array.from(devices).filter(tr => 
                    tr.querySelector('td:nth-child(5)').classList.contains('status-blocked')
                ).length;
                
                document.getElementById('totalLicenses').textContent = licenses.length;
                document.getElementById('activeLicenses').textContent = activeLicenses;
                document.getElementById('totalDevices').textContent = devices.length;
                document.getElementById('blockedDevices').textContent = blockedDevices;
            }
            
            // Add new license
            async function addLicense() {
                const licenseKey = document.getElementById('newLicenseKey').value;
                
                if (!licenseKey) {
                    showAlert(licenseAlert, 'Please enter a license key', 'error');
                    return;
                }
                
                try {
                    const response = await fetch(API_BASE + '/api/licenses', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + authToken
                        },
                        body: JSON.stringify({ license_key: licenseKey })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        showAlert(licenseAlert, 'License added successfully', 'success');
                        document.getElementById('newLicenseKey').value = '';
                        loadLicenses();
                    } else {
                        showAlert(licenseAlert, data.error, 'error');
                    }
                } catch (error) {
                    showAlert(licenseAlert, 'Failed to add license', 'error');
                }
            }
            
            // Deactivate license
            async function deactivateLicense(licenseKey) {
                try {
                    const response = await fetch(API_BASE + '/api/deactivate-license', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + authToken
                        },
                        body: JSON.stringify({ license_key: licenseKey })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        showAlert(licenseAlert, 'License deactivated successfully', 'success');
                        loadLicenses();
                    } else {
                        showAlert(licenseAlert, data.error, 'error');
                    }
                } catch (error) {
                    showAlert(licenseAlert, 'Failed to deactivate license', 'error');
                }
            }
            
            // Activate license
            async function activateLicense(licenseKey) {
                try {
                    const response = await fetch(API_BASE + '/api/reactivate-license', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + authToken
                        },
                        body: JSON.stringify({ license_key: licenseKey })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        showAlert(licenseAlert, 'License activated successfully', 'success');
                        loadLicenses();
                    } else {
                        showAlert(licenseAlert, data.error, 'error');
                    }
                } catch (error) {
                    showAlert(licenseAlert, 'Failed to activate license', 'error');
                }
            }
            
            // Block device
            async function blockDevice(deviceId) {
                try {
                    const response = await fetch(API_BASE + '/api/block-device', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + authToken
                        },
                        body: JSON.stringify({ device_id: deviceId })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        showAlert(deviceAlert, 'Device blocked successfully', 'success');
                        loadDevices();
                    } else {
                        showAlert(deviceAlert, data.error, 'error');
                    }
                } catch (error) {
                    showAlert(deviceAlert, 'Failed to block device', 'error');
                }
            }
            
            // Unblock device
            async function unblockDevice(deviceId) {
                try {
                    const response = await fetch(API_BASE + '/api/unblock-device', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + authToken
                        },
                        body: JSON.stringify({ device_id: deviceId })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        showAlert(deviceAlert, 'Device unblocked successfully', 'success');
                        loadDevices();
                    } else {
                        showAlert(deviceAlert, data.error, 'error');
                    }
                } catch (error) {
                    showAlert(deviceAlert, 'Failed to unblock device', 'error');
                }
            }
            
            // Show alert message
            function showAlert(element, message, type) {
                element.textContent = message;
                element.className = 'alert alert-' + type;
                element.style.display = 'block';
                
                setTimeout(() => {
                    element.style.display = 'none';
                }, 5000);
            }
            
            // Make functions available globally for onclick handlers
            window.deactivateLicense = deactivateLicense;
            window.activateLicense = activateLicense;
            window.blockDevice = blockDevice;
            window.unblockDevice = unblockDevice;
        </script>
    </body>
    </html>
  `);
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`Admin portal: http://localhost:${PORT}/admin`);
});