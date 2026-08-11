const EventEmitter = require('events');

let db = null;
try {
  db = require('../models/db');
} catch (err) {
  db = {
    Scans: {
      update: async () => true,
      findAll: async () => []
    },
    Findings: {
      insert: async () => null
    },
    Targets: {
      findById: async () => null
    },
    VulnDatabase: {
      findAll: async () => []
    }
  };
}

let riskMatrixFn = () => ({
  matrix: {
    critical: { count: 0, findings: [] },
    high: { count: 0, findings: [] },
    medium: { count: 0, findings: [] },
    low: { count: 0, findings: [] },
    info: { count: 0, findings: [] }
  },
  overallScore: 0,
  overallRisk: { level: 'none' }
});

try {
  ({ calculateRiskMatrix: riskMatrixFn } = require('../utils/cvss'));
} catch (err) {
  // Optional CVSS helper is not available yet; fallback below keeps the engine loadable.
}

let NetworkScannerCtor = class {
  async scan() { return { findings: [], services: [] }; }
};
let WebScannerCtor = class {
  async scan() { return { findings: [] }; }
  async scanHeaders() { return { findings: [] }; }
  async scanContent() { return { findings: [] }; }
};
let SSLScannerCtor = class {
  async scan() { return { findings: [], certificates: [] }; }
};
let DNSScannerCtor = class {
  async scan() { return { findings: [], dns: {} }; }
};

try {
  const loaded = require('./modules/network-scanner');
  if (typeof loaded === 'function') NetworkScannerCtor = loaded;
} catch (err) {}
try {
  const loaded = require('./modules/web-scanner');
  if (typeof loaded === 'function') WebScannerCtor = loaded;
} catch (err) {}
try {
  const loaded = require('./modules/ssl-scanner');
  if (typeof loaded === 'function') SSLScannerCtor = loaded;
} catch (err) {}
try {
  const loaded = require('./modules/dns-scanner');
  if (typeof loaded === 'function') DNSScannerCtor = loaded;
} catch (err) {}

if (typeof NetworkScannerCtor !== 'function') NetworkScannerCtor = class { async scan() { return { findings: [], services: [] }; } };
if (typeof WebScannerCtor !== 'function') WebScannerCtor = class { async scan() { return { findings: [] }; } async scanHeaders() { return { findings: [] }; } async scanContent() { return { findings: [] }; } };
if (typeof SSLScannerCtor !== 'function') SSLScannerCtor = class { async scan() { return { findings: [], certificates: [] }; } };
if (typeof DNSScannerCtor !== 'function') DNSScannerCtor = class { async scan() { return { findings: [], dns: {} }; } };
const { Scans, Findings, Targets } = db;
let calculateRiskMatrix = riskMatrixFn;

try {
  const cvss = require('../utils/cvss');
  if (cvss && typeof cvss.calculateRiskMatrix === 'function') {
    calculateRiskMatrix = cvss.calculateRiskMatrix;
  }
} catch (err) {
  // Optional CVSS helper is not present in the current workspace; keep the engine loadable.
}

class ScanEngine extends EventEmitter {
  constructor() {
    super();
    this.activeScans = new Map();
    this.maxConcurrent = 3;
    this.networkScanner = new NetworkScannerCtor();
    this.webScanner = new WebScannerCtor();
    this.sslScanner = new SSLScannerCtor();
    this.dnsScanner = new DNSScannerCtor();
  }

  async startScan(scanRecord) {
    const scanId = scanRecord && scanRecord.id;
    if (!scanId) {
      throw new Error('Scan record is missing an id');
    }

    if (this.activeScans.size >= this.maxConcurrent) {
      if (typeof Scans.update === 'function') {
        await Scans.update(scanId, { status: 'queued', queuePosition: this.activeScans.size });
      }
      return { queued: true, position: this.activeScans.size };
    }

    this.activeScans.set(scanId, { startTime: Date.now(), findings: [] });
    if (typeof Scans.update === 'function') {
      await Scans.update(scanId, { status: 'running', startedAt: new Date().toISOString() });
    }

    try {
      const target = await Targets.findById(scanRecord.targetId);
      if (!target) {
        throw new Error('Target not found');
      }

      const results = await this.executeScan(scanRecord, target);

      for (const finding of results.findings) {
        if (typeof Findings.insert === 'function') {
          await Findings.insert({
            scanId,
            targetId: target.id,
            ...finding,
            verified: false,
            falsePositive: false
          });
        }
      }

      const riskAssessment = calculateRiskMatrix(results.findings);

      if (typeof Scans.update === 'function') {
        await Scans.update(scanId, {
          status: 'completed',
          completedAt: new Date().toISOString(),
          findingsCount: results.findings.length,
          criticalCount: riskAssessment.matrix.critical.count,
          highCount: riskAssessment.matrix.high.count,
          mediumCount: riskAssessment.matrix.medium.count,
          lowCount: riskAssessment.matrix.low.count,
          infoCount: riskAssessment.matrix.info.count,
          riskScore: riskAssessment.overallScore,
          riskLevel: riskAssessment.overallRisk.level,
          duration: Date.now() - this.activeScans.get(scanId).startTime,
          results: {
            findings: results.findings,
            riskAssessment,
            services: results.services || [],
            certificates: results.certificates || [],
            dns: results.dns || {}
          }
        });
      }

      this.emit('complete', {
        scanId,
        summary: {
          totalFindings: results.findings.length,
          riskScore: riskAssessment.overallScore,
          riskLevel: riskAssessment.overallRisk.level,
          duration: Date.now() - this.activeScans.get(scanId).startTime
        },
        findings: results.findings
      });

      return { success: true, scanId, findings: results.findings.length };
    } catch (error) {
      console.error(`[ScanEngine] Scan ${scanId} failed:`, error);

      if (typeof Scans.update === 'function') {
        await Scans.update(scanId, {
          status: 'failed',
          completedAt: new Date().toISOString(),
          error: error.message,
          duration: Date.now() - (this.activeScans.get(scanId)?.startTime || Date.now())
        });
      }

      this.emit('error', { scanId, error: error.message, stack: error.stack });
      throw error;
    } finally {
      this.activeScans.delete(scanId);
    }
  }

  async executeScan(scan, target) {
    const findings = [];
    const services = [];
    const certificates = [];
    const dns = {};

    const scanType = scan.type || 'full';
    const profile = scan.profile || 'standard';
    const options = scan.options || {};
    const modules = this.getModulesForScanType(scanType);
    const totalModules = modules.length || 1;
    let completedModules = 0;

    for (const moduleName of modules) {
      const moduleStartTime = Date.now();

      this.emit('progress', {
        scanId: scan.id,
        module: moduleName,
        progress: Math.round((completedModules / totalModules) * 100),
        message: `Running ${moduleName}...`,
        findings: findings.length
      });

      try {
        let moduleResults = { findings: [] };

        switch (moduleName) {
          case 'dns':
            moduleResults = await this.dnsScanner.scan(target, options);
            Object.assign(dns, moduleResults.dns || {});
            findings.push(...(moduleResults.findings || []));
            break;
          case 'network':
            moduleResults = await this.networkScanner.scan(target, profile, options);
            services.push(...(moduleResults.services || []));
            findings.push(...(moduleResults.findings || []));
            break;
          case 'ssl':
            moduleResults = await this.sslScanner.scan(target, options);
            certificates.push(...(moduleResults.certificates || []));
            findings.push(...(moduleResults.findings || []));
            break;
          case 'web':
            moduleResults = await this.webScanner.scan(target, profile, options);
            findings.push(...(moduleResults.findings || []));
            break;
          case 'headers':
            moduleResults = await this.webScanner.scanHeaders(target, options);
            findings.push(...(moduleResults.findings || []));
            break;
          case 'content':
            moduleResults = await this.webScanner.scanContent(target, options);
            findings.push(...(moduleResults.findings || []));
            break;
          default:
            break;
        }

        completedModules++;
        this.emit('progress', {
          scanId: scan.id,
          module: moduleName,
          progress: Math.round((completedModules / totalModules) * 100),
          message: `${moduleName} completed in ${Date.now() - moduleStartTime}ms`,
          findings: findings.length,
          moduleResults: moduleResults ? { findings: (moduleResults.findings || []).length } : null
        });
      } catch (err) {
        console.error(`[ScanEngine] Module ${moduleName} failed:`, err.message);
        findings.push({
          name: `Scan Module Error: ${moduleName}`,
          severity: 'info',
          description: `The ${moduleName} scanner encountered an error: ${err.message}`,
          category: 'error',
          confidence: 'low'
        });
        completedModules++;
      }
    }

    this.emit('progress', {
      scanId: scan.id,
      module: 'complete',
      progress: 100,
      message: 'Scan completed',
      findings: findings.length
    });

    return { findings, services, certificates, dns };
  }

  getModulesForScanType(type) {
    const moduleMap = {
      full: ['dns', 'network', 'ssl', 'web', 'headers', 'content'],
      network: ['dns', 'network'],
      web: ['dns', 'web', 'headers', 'content'],
      ssl: ['dns', 'ssl'],
      quick: ['dns', 'network', 'headers'],
      deep: ['dns', 'network', 'ssl', 'web', 'headers', 'content']
    };

    return moduleMap[type] || moduleMap.full;
  }

  getActiveScans() {
    const scans = [];
    this.activeScans.forEach((data, scanId) => {
      scans.push({
        scanId,
        startTime: data.startTime,
        duration: Date.now() - data.startTime,
        findings: Array.isArray(data.findings) ? data.findings.length : 0
      });
    });
    return scans;
  }

  async stopScan(scanId) {
    const scan = this.activeScans.get(scanId);
    if (scan) {
      scan.cancelled = true;

      if (typeof Scans.update === 'function') {
        await Scans.update(scanId, {
          status: 'cancelled',
          completedAt: new Date().toISOString(),
          duration: Date.now() - scan.startTime
        });
      }

      this.activeScans.delete(scanId);
      return true;
    }
    return false;
  }
}

module.exports = ScanEngine;
