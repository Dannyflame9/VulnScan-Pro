const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const DB_PATH = path.join(__dirname, '../../data/vulnscan-db.json');
const DB_LOCK_PATH = path.join(__dirname, '../../data/vulnscan-db.lock');

let dbCache = null;
let writeQueue = Promise.resolve();

const defaultDB = {
  users: [],
  targets: [],
  scans: [],
  findings: [],
  reports: [],
  schedules: [],
  vulnDatabase: [],
  settings: {
    maxConcurrentScans: 3,
    defaultScanTimeout: 300000,
    riskThreshold: {
      critical: 9.0,
      high: 7.0,
      medium: 4.0,
      low: 0.1
    },
    notificationSettings: {
      emailOnCritical: true,
      slackWebhook: null
    }
  },
  initialized: false
};

// Pre-populated vulnerability signatures
const defaultVulnSignatures = [
  {
    id: 'vuln-001',
    name: 'SQL Injection',
    cweId: 'CWE-89',
    description: 'Improper neutralization of special elements used in an SQL command.',
    severity: 'critical',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cvssScore: 9.8,
    remediation: 'Use parameterized queries and prepared statements. Validate all user inputs.',
    references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
    detectionPatterns: ['sql injection', "' OR '1'='1", 'union select', 'error in your SQL syntax'],
    category: 'injection'
  },
  {
    id: 'vuln-002',
    name: 'Cross-Site Scripting (XSS)',
    cweId: 'CWE-79',
    description: 'Improper neutralization of input during web page generation.',
    severity: 'high',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    cvssScore: 6.1,
    remediation: 'Implement Content Security Policy. Encode all output. Use modern frameworks with auto-escaping.',
    references: ['https://owasp.org/www-community/attacks/xss/'],
    detectionPatterns: ['<script>', 'javascript:', 'onerror=', 'onload='],
    category: 'xss'
  },
  {
    id: 'vuln-003',
    name: 'Insecure Direct Object Reference (IDOR)',
    cweId: 'CWE-639',
    description: 'Authorization framework failure to verify user access to objects.',
    severity: 'high',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
    cvssScore: 6.5,
    remediation: 'Implement access control checks for every object access. Use indirect reference maps.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html'],
    detectionPatterns: ['idor', 'direct reference', 'unauthorized access'],
    category: 'access-control'
  },
  {
    id: 'vuln-004',
    name: 'Sensitive Data Exposure',
    cweId: 'CWE-200',
    description: 'Exposure of sensitive information to an actor not explicitly authorized.',
    severity: 'medium',
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
    cvssScore: 5.9,
    remediation: 'Encrypt data at rest and in transit. Minimize data exposure. Use strong cipher suites.',
    references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
    detectionPatterns: ['password', 'secret', 'api_key', 'private_key', 'credit_card'],
    category: 'data-exposure'
  },
  {
    id: 'vuln-005',
    name: 'Security Misconfiguration',
    cweId: 'CWE-16',
    description: 'Improper configuration of security controls.',
    severity: 'medium',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    cvssScore: 5.3,
    remediation: 'Harden all configurations. Remove default accounts. Disable unnecessary features.',
    references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'],
    detectionPatterns: ['default password', 'debug mode', 'stack trace', 'server version'],
    category: 'misconfiguration'
  },
  {
    id: 'vuln-006',
    name: 'Missing Security Headers',
    cweId: 'CWE-693',
    description: 'Missing or improperly configured HTTP security headers.',
    severity: 'low',
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
    cvssScore: 3.7,
    remediation: 'Implement HSTS, X-Frame-Options, X-Content-Type-Options, CSP, and Referrer-Policy headers.',
    references: ['https://owasp.org/www-project-secure-headers/'],
    detectionPatterns: ['missing header', 'x-frame-options', 'content-security-policy', 'strict-transport-security'],
    category: 'misconfiguration'
  },
  {
    id: 'vuln-007',
    name: 'Weak SSL/TLS Configuration',
    cweId: 'CWE-326',
    description: 'Use of weak cryptographic algorithms or protocols.',
    severity: 'high',
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
    cvssScore: 5.9,
    remediation: 'Disable SSLv2/SSLv3/TLS 1.0/TLS 1.1. Use TLS 1.2+ with strong cipher suites.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html'],
    detectionPatterns: ['sslv3', 'tls 1.0', 'rc4', 'des', 'weak cipher'],
    category: 'cryptography'
  },
  {
    id: 'vuln-008',
    name: 'Open Redirect',
    cweId: 'CWE-601',
    description: 'URL redirect to untrusted site.',
    severity: 'medium',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    cvssScore: 6.1,
    remediation: 'Validate redirect URLs against an allowlist. Do not use user input for redirects.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'],
    detectionPatterns: ['redirect=', 'url=', 'return=', 'next='],
    category: 'validation'
  },
  {
    id: 'vuln-009',
    name: 'Command Injection',
    cweId: 'CWE-78',
    description: 'Improper neutralization of OS commands.',
    severity: 'critical',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cvssScore: 9.8,
    remediation: 'Avoid OS commands. If necessary, use parameterized APIs and strict input validation.',
    references: ['https://owasp.org/www-community/attacks/Command_Injection'],
    detectionPatterns: ['; ls', '| cat', '`whoami`', '$(id)', 'command injection'],
    category: 'injection'
  },
  {
    id: 'vuln-010',
    name: 'XML External Entity (XXE)',
    cweId: 'CWE-611',
    description: 'Improper restriction of XML external entity reference.',
    severity: 'critical',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cvssScore: 9.8,
    remediation: 'Disable DTDs. Use less complex data formats. Patch XML processors.',
    references: ['https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing'],
    detectionPatterns: ['<!ENTITY', 'file://', 'xxe', 'xml external entity'],
    category: 'injection'
  }
];

async function ensureDataDir() {
  const dir = path.dirname(DB_PATH);
  try {
    await fs.mkdir(dir, { recursive: true });
  } catch (err) {
    if (err.code !== 'EEXIST') throw err;
  }
}

async function readDB() {
  if (dbCache) return dbCache;
  
  try {
    const data = await fs.readFile(DB_PATH, 'utf8');
    dbCache = JSON.parse(data);
    return dbCache;
  } catch (err) {
    if (err.code === 'ENOENT') {
      dbCache = { ...defaultDB };
      dbCache.vulnDatabase = [...defaultVulnSignatures];
      await writeDB(dbCache);
      return dbCache;
    }
    throw err;
  }
}

async function writeDB(data) {
  dbCache = data;
  writeQueue = writeQueue.then(async () => {
    await ensureDataDir();
    await fs.writeFile(DB_PATH, JSON.stringify(data, null, 2), 'utf8');
  }).catch(err => {
    console.error('[DB] Write error:', err);
    throw err;
  });
  return writeQueue;
}

async function initDB() {
  await ensureDataDir();
  const db = await readDB();
  
  if (!db.initialized) {
    db.initialized = true;
    db.createdAt = new Date().toISOString();
    
    // Create default admin
    const bcrypt = require('bcryptjs');
    const adminExists = db.users.find(u => u.role === 'admin');
    if (!adminExists) {
      db.users.push({
        id: uuidv4(),
        username: 'admin',
        email: 'admin@vulnscan.local',
        password: await bcrypt.hash('admin123', 10),
        role: 'admin',
        createdAt: new Date().toISOString(),
        lastLogin: null,
        preferences: {
          theme: 'dark',
          notifications: true,
          defaultScanProfile: 'full'
        }
      });
    }
    
    await writeDB(db);
  }
  
  return db;
}

// Generic CRUD operations
class Collection {
  constructor(name) {
    this.name = name;
  }
  
  async findAll(query = {}) {
    const db = await readDB();
    let items = db[this.name] || [];
    
    if (Object.keys(query).length > 0) {
      items = items.filter(item => {
        return Object.entries(query).every(([key, value]) => item[key] === value);
      });
    }
    
    return items;
  }
  
  async findOne(query) {
    const items = await this.findAll(query);
    return items[0] || null;
  }
  
  async findById(id) {
    return this.findOne({ id });
  }
  
  async insert(data) {
    const db = await readDB();
    if (!db[this.name]) db[this.name] = [];
    
    const item = {
      id: data.id || uuidv4(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      ...data
    };
    
    db[this.name].push(item);
    await writeDB(db);
    return item;
  }
  
  async update(id, updates) {
    const db = await readDB();
    const idx = (db[this.name] || []).findIndex(item => item.id === id);
    if (idx === -1) return null;
    
    db[this.name][idx] = {
      ...db[this.name][idx],
      ...updates,
      updatedAt: new Date().toISOString()
    };
    
    await writeDB(db);
    return db[this.name][idx];
  }
  
  async delete(id) {
    const db = await readDB();
    const initialLen = (db[this.name] || []).length;
    db[this.name] = (db[this.name] || []).filter(item => item.id !== id);
    await writeDB(db);
    return initialLen !== (db[this.name] || []).length;
  }
  
  async count(query = {}) {
    const items = await this.findAll(query);
    return items.length;
  }
}

const Users = new Collection('users');
const Targets = new Collection('targets');
const Scans = new Collection('scans');
const Findings = new Collection('findings');
const Reports = new Collection('reports');
const Schedules = new Collection('schedules');
const VulnDatabase = new Collection('vulnDatabase');

async function getSettings() {
  const db = await readDB();
  return db.settings;
}

async function updateSettings(updates) {
  const db = await readDB();
  db.settings = { ...db.settings, ...updates };
  await writeDB(db);
  return db.settings;
}

module.exports = {
  initDB,
  readDB,
  writeDB,
  Users,
  Targets,
  Scans,
  Findings,
  Reports,
  Schedules,
  VulnDatabase,
  getSettings,
  updateSettings,
  Collection
};
