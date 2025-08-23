const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const app = express();

// Initialize Firebase using environment variables
// Note: We'll set up the Firebase Admin SDK properly later
// For now, we'll use a simple in-memory database

// Enable CORS for browser requests
app.use(cors());
app.use(express.json());

// Simple in-memory database for licenses (will replace with Firebase later)
let licenses = {};
let users = {};

// Root endpoint
app.get('/', (req, res) => {
  res.send('Planet Traveler License Server is running!');
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date(),
    server: 'Planet Traveler License Server',
    version: '1.0.0'
  });
});

// License validation endpoint
app.post('/validate', async (req, res) => {
  const { licenseKey, deviceId } = req.body;
  
  console.log('License validation request:', { licenseKey, deviceId });
  
  // Check if license exists
  if (!licenses[licenseKey]) {
    return res.json({ 
      valid: false, 
      error: 'Invalid license key',
      code: 'INVALID_LICENSE'
    });
  }
  
  const license = licenses[licenseKey];
  
  // Check if license is expired
  if (new Date(license.validUntil) < new Date()) {
    return res.json({ 
      valid: false, 
      error: 'License expired',
      code: 'LICENSE_EXPIRED'
    });
  }
  
  // Check if device is already registered
  const existingDevice = license.devices.find(d => d.id === deviceId);
  
  if (!existingDevice) {
    // New device - check if we can add it
    if (license.devices.length >= license.maxDevices) {
      return res.json({ 
        valid: false, 
        error: 'Device limit reached',
        code: 'DEVICE_LIMIT'
      });
    }
    
    // Register new device
    license.devices.push({
      id: deviceId,
      firstSeen: new Date(),
      lastSeen: new Date()
    });
  } else {
    // Update existing device
    existingDevice.lastSeen = new Date();
  }
  
  // Update user record
  users[deviceId] = {
    licenseKey: licenseKey,
    lastSeen: new Date()
  };
  
  res.json({
    valid: true,
    validUntil: license.validUntil,
    maxDevices: license.maxDevices,
    usedDevices: license.devices.length
  });
});

// Admin endpoint to add licenses
app.post('/admin/add-license', async (req, res) => {
  const { password, key, maxDevices, validUntil } = req.body;
  
  // Simple password protection
  if (password !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  if (!key) {
    return res.status(400).json({ error: 'License key is required' });
  }
  
  try {
    licenses[key] = {
      maxDevices: parseInt(maxDevices) || 1,
      devices: [],
      validUntil: validUntil || '2024-12-31',
      createdAt: new Date()
    };
    
    res.json({ 
      success: true, 
      message: 'License added',
      license: licenses[key]
    });
    
  } catch (error) {
    console.error('Add license error:', error);
    res.status(500).json({ error: 'Failed to add license' });
  }
});

// Get all licenses (admin)
app.get('/admin/licenses', async (req, res) => {
  const { password } = req.query;
  
  if (password !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  try {
    res.json({
      success: true,
      licenses: licenses,
      users: users,
      serverTime: new Date()
    });
    
  } catch (error) {
    console.error('Get licenses error:', error);
    res.status(500).json({ error: 'Failed to get licenses' });
  }
});

// Reset all data (for testing only)
app.post('/admin/reset', async (req, res) => {
  const { password } = req.body;
  
  if (password !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  try {
    licenses = {};
    users = {};
    
    res.json({ 
      success: true, 
      message: 'All data reset successfully' 
    });
    
  } catch (error) {
    console.error('Reset error:', error);
    res.status(500).json({ error: 'Failed to reset data' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`Admin portal: http://localhost:${PORT}/admin/licenses?password=YOUR_PASSWORD`);
});