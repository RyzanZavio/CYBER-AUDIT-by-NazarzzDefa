import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { DEFAULT_TEMPLATES } from './src/data/defaultTemplates';
import { DEFAULT_EXTENSIONS } from './src/data/defaultExtensions';
import {
  ExtensionManifest,
  ProxyConfig,
  ScanResult,
  VulnerabilityFinding,
  WebhookConfig,
  YamlTemplate,
} from './src/types';
import { executeVulnerabilityScan } from './server/scanner';
import { sendWebhookNotification } from './server/webhook';
import { getScheduleState, initializeScheduler, updateSchedule } from './server/scheduler';
import { generateLinuxWslCliScript } from './server/cli-script';

const PORT = 3000;

// In-memory state
let currentTemplates: YamlTemplate[] = JSON.parse(JSON.stringify(DEFAULT_TEMPLATES));
let currentWebhookConfig: WebhookConfig = {
  type: 'discord',
  url: '',
  enabled: false,
  minSeverity: 'medium',
  channelName: '#security-alerts',
};
let currentProxyConfig: ProxyConfig = {
  enabled: false,
  url: 'http://127.0.0.1:8080',
  insecureSkipVerify: true,
  customUserAgent: 'Mozilla/5.0 (compatible; DevSecOps-Auditor/2.4; +https://owasp.org)',
};
let currentExtensions: ExtensionManifest[] = JSON.parse(JSON.stringify(DEFAULT_EXTENSIONS));
let lastScanResult: ScanResult | null = null;

function syncExtensionTemplates() {
  const baseBuiltins: YamlTemplate[] = JSON.parse(JSON.stringify(DEFAULT_TEMPLATES));
  const activeExtTemplates: YamlTemplate[] = [];

  for (const ext of currentExtensions) {
    if (ext.installed && ext.enabled && Array.isArray(ext.templates)) {
      for (const tpl of ext.templates) {
        activeExtTemplates.push({ ...tpl, isBuiltin: false });
      }
    }
  }

  // Preserve user custom templates
  const userCustom = currentTemplates.filter(
    t =>
      !DEFAULT_TEMPLATES.some(dt => dt.id === t.id) &&
      !currentExtensions.some(ext => ext.templates.some(et => et.id === t.id))
  );

  currentTemplates = [...baseBuiltins, ...activeExtTemplates, ...userCustom];
}

// Initial sync of extension templates
syncExtensionTemplates();

async function startServer() {
  const app = express();

  // Disable x-powered-by banner header
  app.disable('x-powered-by');

  // Defensive HTTP Security Headers Middleware
  app.use((req, res, next) => {
    // Content-Security-Policy (allows safe inline styles/scripts for Vite & frame-ancestors for AI Studio preview)
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data: blob:; frame-ancestors 'self' *;"
    );
    // Prevent MIME-sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // Strict Transport Security (HSTS)
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    // Referrer Policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    // Permissions Policy
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
  });

  app.use(express.json({ limit: '10mb' }));

  // Helper functions for scheduler
  const getTemplates = () => currentTemplates;
  const getWebhookConfig = () => currentWebhookConfig;

  // Initialize background daily scheduler
  initializeScheduler(getTemplates, getWebhookConfig);

  // Health endpoint
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      engine: 'OWASP / Nuclei / Burp Suite Pro Hybrid Scanner',
      version: '2.4.0',
      templatesCount: currentTemplates.length,
      scheduler: getScheduleState().config.status,
    });
  });

  // Templates endpoints
  app.get('/api/templates', (req, res) => {
    res.json(currentTemplates);
  });

  app.post('/api/templates', (req, res) => {
    const template: YamlTemplate = req.body;
    if (!template.id || !template.rawYaml) {
      res.status(400).json({ error: 'Template must contain id and rawYaml' });
      return;
    }
    const existingIndex = currentTemplates.findIndex(t => t.id === template.id);
    if (existingIndex >= 0) {
      currentTemplates[existingIndex] = { ...currentTemplates[existingIndex], ...template };
    } else {
      currentTemplates.push({ ...template, isBuiltin: false });
    }
    res.json({ success: true, template });
  });

  app.delete('/api/templates/:id', (req, res) => {
    const id = req.params.id;
    currentTemplates = currentTemplates.filter(t => t.id !== id);
    res.json({ success: true, message: `Template ${id} removed` });
  });

  app.post('/api/templates/reset', (req, res) => {
    currentTemplates = JSON.parse(JSON.stringify(DEFAULT_TEMPLATES));
    res.json({ success: true, templates: currentTemplates });
  });

  // Scan endpoint
  app.post('/api/scan', async (req, res) => {
    try {
      const { targetUrl, templateIds, timeoutMs, webhook } = req.body;

      if (!targetUrl || typeof targetUrl !== 'string') {
        res.status(400).json({ error: 'Valid targetUrl is required' });
        return;
      }

      // Filter templates
      let templatesToRun = currentTemplates.filter(t => t.enabled);
      if (Array.isArray(templateIds) && templateIds.length > 0) {
        templatesToRun = templatesToRun.filter(t => templateIds.includes(t.id));
      }

      const effectiveProxy = req.body.proxy || (currentProxyConfig.enabled ? currentProxyConfig : undefined);

      console.log(`[Scan] Starting scan on target: ${targetUrl} with ${templatesToRun.length} templates (Proxy: ${effectiveProxy?.enabled ? effectiveProxy.url : 'Direct'})`);

      const isStreaming = req.headers.accept?.includes('text/event-stream') || req.query.stream === 'true' || req.path.endsWith('/stream');

      if (isStreaming) {
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache, no-transform');
        res.setHeader('Connection', 'keep-alive');
        res.flushHeaders?.();

        const result = await executeVulnerabilityScan(targetUrl, templatesToRun, {
          timeoutMs: timeoutMs || 8000,
          userAgent: 'DevSecOps-Auditor/2.4 (OWASP-ZAP/Nuclei/BurpSuite)',
          proxy: effectiveProxy,
          onProgressLog: (log) => {
            res.write(`data: ${JSON.stringify({ type: 'log', log })}\n\n`);
          },
        });

        lastScanResult = result;

        // Handle webhook notification if configured
        const effectiveWebhook: WebhookConfig = webhook || currentWebhookConfig;
        if (effectiveWebhook && effectiveWebhook.enabled && effectiveWebhook.url) {
          const severityOrder = ['info', 'low', 'medium', 'high', 'critical'];
          const thresholdIndex = severityOrder.indexOf(effectiveWebhook.minSeverity || 'medium');
          const hasRelevantFindings = result.findings.some(
            f => severityOrder.indexOf(f.severity) >= thresholdIndex
          );
          if (hasRelevantFindings || result.findings.length === 0) {
            sendWebhookNotification(effectiveWebhook, result).catch(err => {
              console.error('[Webhook] Scan dispatch error:', err);
            });
          }
        }

        res.write(`data: ${JSON.stringify({ type: 'complete', result })}\n\n`);
        res.end();
        return;
      }

      const result = await executeVulnerabilityScan(targetUrl, templatesToRun, {
        timeoutMs: timeoutMs || 8000,
        userAgent: 'DevSecOps-Auditor/2.4 (OWASP-ZAP/Nuclei/BurpSuite)',
        proxy: effectiveProxy,
      });

      lastScanResult = result;

      // Handle webhook notification if configured
      const effectiveWebhook: WebhookConfig = webhook || currentWebhookConfig;
      if (effectiveWebhook && effectiveWebhook.enabled && effectiveWebhook.url) {
        // Check minSeverity threshold
        const severityOrder = ['info', 'low', 'medium', 'high', 'critical'];
        const thresholdIndex = severityOrder.indexOf(effectiveWebhook.minSeverity || 'medium');

        const hasRelevantFindings = result.findings.some(
          f => severityOrder.indexOf(f.severity) >= thresholdIndex
        );

        if (hasRelevantFindings || result.findings.length === 0) {
          sendWebhookNotification(effectiveWebhook, result).then(webhookRes => {
            console.log(`[Webhook] Scan dispatch result:`, webhookRes.message);
          }).catch(err => {
            console.error('[Webhook] Scan dispatch error:', err);
          });
        }
      }

      res.json(result);
    } catch (err: any) {
      console.error('[Scan] Error executing scan:', err);
      res.status(500).json({ error: err.message || 'Scan execution failed' });
    }
  });

  // Last scan result
  app.get('/api/scan/last', (req, res) => {
    res.json(lastScanResult || { status: 'none', findings: [] });
  });

  // Batch Multi-Target Scan endpoint (for subfinder/file drag/drop lists)
  app.post('/api/scan/batch', async (req, res) => {
    try {
      const { targets, templateIds, timeoutMs, proxy, webhook } = req.body;

      if (!Array.isArray(targets) || targets.length === 0) {
        res.status(400).json({ error: 'Array of target hosts is required' });
        return;
      }

      const effectiveProxy = proxy || (currentProxyConfig.enabled ? currentProxyConfig : undefined);
      let templatesToRun = currentTemplates.filter(t => t.enabled);
      if (Array.isArray(templateIds) && templateIds.length > 0) {
        templatesToRun = templatesToRun.filter(t => templateIds.includes(t.id));
      }

      console.log(`[Batch Scan] Commencing batch scan on ${targets.length} targets (Proxy: ${effectiveProxy?.enabled ? effectiveProxy.url : 'Direct'})`);

      const resultsByTarget: Record<string, ScanResult> = {};
      const allFindings: VulnerabilityFinding[] = [];
      let completedCount = 0;
      let failedCount = 0;

      for (const target of targets) {
        try {
          const scanRes = await executeVulnerabilityScan(target, templatesToRun, {
            timeoutMs: timeoutMs || 6000,
            proxy: effectiveProxy,
          });
          resultsByTarget[target] = scanRes;
          allFindings.push(...scanRes.findings);
          completedCount++;
        } catch (err: any) {
          failedCount++;
          resultsByTarget[target] = {
            id: `err-${Date.now()}-${Math.random().toString(36).substring(7)}`,
            targetUrl: target,
            startTime: new Date().toISOString(),
            status: 'failed',
            findings: [],
            templatesExecuted: 0,
            requestsSent: 0,
            logs: [
              {
                timestamp: new Date().toLocaleTimeString(),
                level: 'crit',
                message: `Batch target execution failed: ${err.message}`,
              },
            ],
          };
        }
      }

      const summary = {
        id: `batch-${Date.now()}`,
        totalTargets: targets.length,
        completedTargets: completedCount,
        failedTargets: failedCount,
        totalFindings: allFindings.length,
        criticalCount: allFindings.filter(f => f.severity === 'critical').length,
        highCount: allFindings.filter(f => f.severity === 'high').length,
        resultsByTarget,
        findings: allFindings,
        timestamp: new Date().toISOString(),
      };

      // Optional webhook notification for batch completion
      const effectiveWebhook: WebhookConfig = webhook || currentWebhookConfig;
      if (effectiveWebhook && effectiveWebhook.enabled && effectiveWebhook.url) {
        const dummyResult: ScanResult = {
          id: summary.id,
          targetUrl: `Batch Scan (${targets.length} subdomains/hosts)`,
          startTime: summary.timestamp,
          durationMs: 0,
          status: 'completed',
          findings: allFindings,
          templatesExecuted: templatesToRun.length,
          requestsSent: targets.length * templatesToRun.length,
          logs: [],
        };
        sendWebhookNotification(effectiveWebhook, dummyResult).catch(err =>
          console.error('[Webhook] Batch scan notification error:', err)
        );
      }

      res.json(summary);
    } catch (err: any) {
      console.error('[Batch Scan] Error executing batch scan:', err);
      res.status(500).json({ error: err.message || 'Batch scan execution failed' });
    }
  });

  // Proxy Configuration & Testing Endpoints
  app.get('/api/proxy', (req, res) => {
    res.json(currentProxyConfig);
  });

  app.post('/api/proxy', (req, res) => {
    const config: Partial<ProxyConfig> = req.body;
    currentProxyConfig = { ...currentProxyConfig, ...config };
    console.log(`[Proxy] Configuration updated: enabled=${currentProxyConfig.enabled}, url=${currentProxyConfig.url}`);
    res.json({ success: true, config: currentProxyConfig });
  });

  app.post('/api/proxy/test', async (req, res) => {
    try {
      const proxyToTest: ProxyConfig = req.body.url ? req.body : currentProxyConfig;
      if (!proxyToTest.url) {
        res.status(400).json({ success: false, message: 'Proxy URL cannot be empty (e.g. http://127.0.0.1:8080)' });
        return;
      }

      const { ProxyAgent, fetch: undiciFetch } = await import('undici');
      const dispatcher = new ProxyAgent({
        uri: proxyToTest.url,
        requestTls: {
          rejectUnauthorized: !proxyToTest.insecureSkipVerify,
        },
      });

      const start = Date.now();
      const headers: Record<string, string> = {
        'User-Agent': proxyToTest.customUserAgent || 'DevSecOps-Proxy-Probe/1.0',
      };

      if (proxyToTest.username) {
        const credentials = Buffer.from(`${proxyToTest.username}:${proxyToTest.password || ''}`).toString('base64');
        headers['Proxy-Authorization'] = `Basic ${credentials}`;
      }

      // Test against public IP reflection service through the proxy
      const testRes = await undiciFetch('https://icanhazip.com', {
        dispatcher,
        headers,
        signal: AbortSignal.timeout(6000),
      });

      const duration = Date.now() - start;
      if (testRes.ok) {
        const ip = (await testRes.text()).trim();
        res.json({
          success: true,
          message: `Proxy connection verified! Outgoing Egress IP: ${ip} (${duration}ms)`,
          outgoingIp: ip,
          latencyMs: duration,
        });
      } else {
        res.json({
          success: false,
          message: `Upstream proxy reached, but target returned HTTP status ${testRes.status}`,
        });
      }
    } catch (err: any) {
      res.json({
        success: false,
        message: `Upstream proxy connection failed: ${err.message}`,
      });
    }
  });

  // Extensions Management Endpoints
  app.get('/api/extensions', (req, res) => {
    res.json(currentExtensions);
  });

  app.post('/api/extensions/toggle', (req, res) => {
    const { id, enabled } = req.body;
    const ext = currentExtensions.find(e => e.id === id);
    if (!ext) {
      res.status(404).json({ error: `Extension with id ${id} not found` });
      return;
    }
    ext.enabled = !!enabled;
    if (ext.enabled) {
      ext.installed = true;
    }
    syncExtensionTemplates();
    res.json({ success: true, extension: ext, totalTemplates: currentTemplates.length });
  });

  app.post('/api/extensions/install', (req, res) => {
    try {
      const manifest: Partial<ExtensionManifest> = req.body;
      if (!manifest.id || !manifest.name) {
        res.status(400).json({ error: 'Extension manifest must specify id and name' });
        return;
      }

      const existingIndex = currentExtensions.findIndex(e => e.id === manifest.id);
      const newExt: ExtensionManifest = {
        id: manifest.id,
        name: manifest.name,
        version: manifest.version || '1.0.0',
        author: manifest.author || 'Community Contributor',
        description: manifest.description || 'Custom DevSecOps Security Extension',
        category: manifest.category || 'custom',
        installed: true,
        enabled: manifest.enabled !== undefined ? manifest.enabled : true,
        templatesCount: Array.isArray(manifest.templates) ? manifest.templates.length : 0,
        templates: manifest.templates || [],
        repositoryUrl: manifest.repositoryUrl,
        downloadUrl: manifest.downloadUrl,
      };

      if (existingIndex >= 0) {
        currentExtensions[existingIndex] = newExt;
      } else {
        currentExtensions.push(newExt);
      }

      syncExtensionTemplates();
      res.json({ success: true, extension: newExt, totalTemplates: currentTemplates.length });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.delete('/api/extensions/:id', (req, res) => {
    const { id } = req.params;
    currentExtensions = currentExtensions.filter(e => e.id !== id);
    syncExtensionTemplates();
    res.json({ success: true, message: `Extension ${id} uninstalled`, totalTemplates: currentTemplates.length });
  });

  // Webhook settings & test
  app.get('/api/webhook', (req, res) => {
    res.json(currentWebhookConfig);
  });

  app.post('/api/webhook', (req, res) => {
    const config: Partial<WebhookConfig> = req.body;
    currentWebhookConfig = { ...currentWebhookConfig, ...config };
    res.json({ success: true, config: currentWebhookConfig });
  });

  app.post('/api/webhook/test', async (req, res) => {
    try {
      const config: WebhookConfig = req.body.url ? req.body : currentWebhookConfig;
      if (!config.url) {
        res.status(400).json({ success: false, message: 'Webhook URL cannot be blank' });
        return;
      }

      // Generate a mock test scan result
      const testScan: ScanResult = {
        id: `test-scan-${Date.now()}`,
        targetUrl: 'https://demo-audit.internal',
        startTime: new Date().toISOString(),
        durationMs: 2450,
        status: 'completed',
        templatesExecuted: 10,
        requestsSent: 28,
        logs: [],
        findings: [
          {
            id: 'test-1',
            templateId: 'owasp-security-headers',
            name: 'OWASP Missing Security Headers (CSP / HSTS)',
            severity: 'medium',
            cvssScore: 5.3,
            cweId: 'CWE-693',
            owaspCategory: 'A05:2021-Security Misconfiguration',
            description: 'Strict-Transport-Security and Content-Security-Policy were not detected on response.',
            url: 'https://demo-audit.internal/',
            matchedAt: 'https://demo-audit.internal/',
            evidence: 'Missing header: strict-transport-security',
            remediation: 'Add HSTS and CSP in web server configuration.',
            references: ['https://owasp.org/www-project-secure-headers/'],
            timestamp: new Date().toISOString(),
          },
          {
            id: 'test-2',
            templateId: 'exposed-env-credentials',
            name: 'Exposed Environment (.env) Secrets Test Probe',
            severity: 'critical',
            cvssScore: 9.8,
            cweId: 'CWE-200',
            owaspCategory: 'A01:2021-Broken Access Control',
            description: 'Simulated high-risk credential disclosure probe test for webhook verification.',
            url: 'https://demo-audit.internal/.env',
            matchedAt: 'https://demo-audit.internal/.env',
            evidence: 'Status 200 with DB_PASSWORD token',
            remediation: 'Restrict web access to dotfiles in Nginx / Apache.',
            references: ['https://owasp.org/'],
            timestamp: new Date().toISOString(),
          },
        ],
      };

      const webhookResponse = await sendWebhookNotification(config, testScan);
      res.json(webhookResponse);
    } catch (err: any) {
      res.status(500).json({ success: false, message: err.message });
    }
  });

  // Schedule endpoints
  app.get('/api/schedule', (req, res) => {
    res.json(getScheduleState());
  });

  app.post('/api/schedule', (req, res) => {
    try {
      const newConfig = req.body;
      const state = updateSchedule(newConfig, getTemplates, getWebhookConfig);
      res.json(state);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Linux & WSL CLI Downloadable Script and Installer (wget, curl, git support)
  const sendCliScript = (req: express.Request, res: express.Response, filename = 'cyber-audit') => {
    const hostHeader = req.get('host') || 'localhost:3000';
    const proto = req.get('x-forwarded-proto') || 'http';
    const appUrl = `${proto}://${hostHeader}`;
    const script = generateLinuxWslCliScript(appUrl);

    res.setHeader('Content-Type', 'text/x-shellscript; charset=utf-8');
    res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
    res.send(script);
  };

  app.get('/install.sh', (req, res) => sendCliScript(req, res, 'install.sh'));
  app.get('/cyber-audit', (req, res) => sendCliScript(req, res, 'cyber-audit'));
  app.get('/git-audit', (req, res) => sendCliScript(req, res, 'git-audit'));
  app.get('/api/cli/script', (req, res) => sendCliScript(req, res, 'cyber-audit'));
  app.get('/api/cli/git-audit', (req, res) => sendCliScript(req, res, 'git-audit'));

  // Setup Vite or static serving
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[DevSecOps Server] Running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch(err => {
  console.error('[DevSecOps Server] Failed to start:', err);
});
