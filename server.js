const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const cron = require('node-cron');

const { initDB } = require('./models/db');
const authRoutes = require('./routes/auth');
const targetRoutes = require('./routes/targets');
const scanRoutes = require('./routes/scans');
const reportRoutes = require('./routes/reports');
const dashboardRoutes = require('./routes/dashboard');
const { authenticateToken } = require('./utils/auth');
const ScanEngine = require('./scanner/engine');
const { runScheduledScans } = require('./utils/scheduler');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Global state
const clients = new Map();
const scanEngine = new ScanEngine();

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'", "ws:", "wss:"]
    }
  }
}));
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Static files
app.use(express.static(path.join(__dirname, '../client')));

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/targets', authenticateToken, targetRoutes);
app.use('/api/scans', authenticateToken, scanRoutes);
app.use('/api/reports', authenticateToken, reportRoutes);
app.use('/api/dashboard', authenticateToken, dashboardRoutes);

// WebSocket connection handling
wss.on('connection', (ws, req) => {
  const clientId = req.headers['sec-websocket-key'];
  console.log(`[WS] Client connected: ${clientId}`);
  
  clients.set(clientId, { ws, subscriptions: new Set() });
  
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      handleWebSocketMessage(clientId, data);
    } catch (err) {
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid JSON' }));
    }
  });
  
  ws.on('close', () => {
    console.log(`[WS] Client disconnected: ${clientId}`);
    clients.delete(clientId);
  });
  
  ws.on('error', (err) => {
    console.error(`[WS] Error for ${clientId}:`, err.message);
  });
  
  // Send initial connection ack
  ws.send(JSON.stringify({ type: 'connected', clientId, timestamp: new Date().toISOString() }));
});

function handleWebSocketMessage(clientId, data) {
  const client = clients.get(clientId);
  if (!client) return;
  
  switch (data.type) {
    case 'subscribe':
      if (data.scanId) {
        client.subscriptions.add(data.scanId);
        wsBroadcast(data.scanId, { type: 'subscribed', scanId: data.scanId });
      }
      break;
    case 'unsubscribe':
      if (data.scanId) {
        client.subscriptions.delete(data.scanId);
      }
      break;
    case 'ping':
      client.ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
      break;
  }
}

// Broadcast scan updates to subscribed clients
function broadcastScanUpdate(scanId, update) {
  const message = JSON.stringify({ type: 'scan-update', scanId, ...update });
  clients.forEach((client, id) => {
    if (client.subscriptions.has(scanId) || client.subscriptions.has('all')) {
      if (client.ws.readyState === WebSocket.OPEN) {
        client.ws.send(message);
      }
    }
  });
}

// Make broadcast available globally
global.broadcastScanUpdate = broadcastScanUpdate;

// Scan engine event binding
scanEngine.on('progress', (data) => {
  broadcastScanUpdate(data.scanId, {
    status: 'running',
    progress: data.progress,
    currentModule: data.module,
    findings: data.findings,
    message: data.message
  });
});

scanEngine.on('complete', (data) => {
  broadcastScanUpdate(data.scanId, {
    status: 'completed',
    progress: 100,
    summary: data.summary,
    findings: data.findings
  });
});

scanEngine.on('error', (data) => {
  broadcastScanUpdate(data.scanId, {
    status: 'error',
    error: data.error,
    message: data.message
  });
});

// Make scan engine available to routes
app.set('scanEngine', scanEngine);

// Scheduled scans - every minute check for due scans
cron.schedule('* * * * *', async () => {
  try {
    await runScheduledScans(scanEngine);
  } catch (err) {
    console.error('[Scheduler] Error:', err.message);
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '1.0.0',
    wsClients: clients.size
  });
});

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../client/index.html'));
});

// Error handling
app.use((err, req, res, next) => {
  console.error('[Error]', err);
  res.status(err.status || 500).json({
    error: NODE_ENV === 'production' ? 'Internal server error' : err.message,
    stack: NODE_ENV === 'production' ? undefined : err.stack
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('[Server] SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('[Server] HTTP server closed');
    process.exit(0);
  });
});

// Initialize and start
async function start() {
  try {
    await initDB();
    console.log('[DB] Database initialized');
    
    server.listen(PORT, () => {
      console.log(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   VulnScan-Pro v1.0.0                                        ║
║   Automated Vulnerability Scanning Platform                  ║
║                                                              ║
║   Server: http://localhost:${PORT}                              ║
║   Environment: ${NODE_ENV.padEnd(43)}║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
      `);
    });
  } catch (err) {
    console.error('[Fatal] Failed to start server:', err);
    process.exit(1);
  }
}

start();

module.exports = { app, server, wss };
