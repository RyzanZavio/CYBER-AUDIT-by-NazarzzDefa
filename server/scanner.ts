import * as yaml from 'js-yaml';
import { ProxyAgent } from 'undici';
import {
  ProxyConfig,
  ScanLog,
  ScanResult,
  SubFindingItem,
  VulnerabilityFinding,
  VulnerabilitySeverity,
  YamlTemplate,
} from '../src/types';

interface ParsedYamlInfo {
  name?: string;
  author?: string;
  severity?: VulnerabilitySeverity;
  description?: string;
  reference?: string[];
  tags?: string;
  classification?: {
    'cvss-score'?: number;
    'cvss-vector'?: string;
    'cwe-id'?: string;
    'owasp-category'?: string;
  };
}

interface ParsedMatcher {
  type: 'word' | 'regex' | 'status' | 'header' | 'content-type' | 'size';
  part?: 'body' | 'header' | 'all';
  words?: string[];
  regex?: string[];
  status?: number[];
  'content-type'?: string[];
  'min-size'?: number;
  'max-size'?: number;
  negative?: boolean;
  condition?: 'and' | 'or';
}

interface ParsedRequest {
  method?: string;
  path?: string[];
  headers?: Record<string, string>;
  body?: string;
  'matchers-condition'?: 'and' | 'or';
  matchers?: ParsedMatcher[];
}

interface ParsedTemplate {
  id: string;
  info: ParsedYamlInfo;
  requests?: ParsedRequest[];
}

// Check for Soft-404 error page disguised with HTTP 200
function isSoft404ErrorPage(body: string, path: string): boolean {
  if (path === '/' || path === '' || path === '{{BaseURL}}/') return false;
  const lower = body.toLowerCase();
  
  // HTML page title / heading indicators of 404
  if (
    lower.includes('<title>404') ||
    lower.includes('<title>page not found') ||
    lower.includes('<title>not found') ||
    lower.includes('<title>halaman tidak ditemukan') ||
    lower.includes('<h1>404') ||
    lower.includes('<h1>page not found') ||
    lower.includes('<h1>not found') ||
    lower.includes('<h1>halaman tidak ditemukan')
  ) {
    return true;
  }

  // JSON error responses
  if (
    lower.includes('"status":404') ||
    lower.includes('"status": 404') ||
    lower.includes('"error":"not found"') ||
    lower.includes('"error": "not found"') ||
    lower.includes('"message":"not found"') ||
    lower.includes('"message": "not found"')
  ) {
    return true;
  }

  return false;
}

export async function executeVulnerabilityScan(
  targetUrl: string,
  templates: YamlTemplate[],
  options: {
    timeoutMs?: number;
    userAgent?: string;
    proxy?: ProxyConfig;
    onProgressLog?: (log: ScanLog) => void;
  } = {}
): Promise<ScanResult> {
  const startTime = new Date().toISOString();
  const startTimestamp = Date.now();
  const timeoutMs = options.timeoutMs || 8000;
  const userAgent =
    options.proxy?.customUserAgent ||
    options.userAgent ||
    'Mozilla/5.0 (compatible; DevSecOps-Auditor/2.4; +https://owasp.org)';

  // Setup Upstream Security Proxy Dispatcher (Burp Suite, OWASP ZAP, Tor)
  let dispatcher: any = undefined;
  if (options.proxy?.enabled && options.proxy?.url) {
    try {
      dispatcher = new ProxyAgent({
        uri: options.proxy.url,
        requestTls: {
          rejectUnauthorized: !options.proxy.insecureSkipVerify,
        },
      });
    } catch (proxyErr: any) {
      console.warn(`[Proxy] Failed to initialize proxy agent for ${options.proxy.url}:`, proxyErr.message);
    }
  }

  // Normalize target URL
  let normalizedUrl = targetUrl.trim();
  if (!/^https?:\/\//i.test(normalizedUrl)) {
    normalizedUrl = `http://${normalizedUrl}`;
  }
  normalizedUrl = normalizedUrl.replace(/\/+$/, '');

  const logs: ScanLog[] = [];
  const rawFindings: VulnerabilityFinding[] = [];
  let requestsSent = 0;
  let templatesExecuted = 0;

  const emitLog = (
    level: 'info' | 'warn' | 'crit' | 'pass',
    message: string,
    templateId?: string,
    severity?: VulnerabilitySeverity,
    templateName?: string,
    payload?: import('../src/types').ScanPayloadInfo
  ) => {
    const entry: ScanLog = {
      id: `log-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      timestamp: new Date().toLocaleTimeString(),
      level,
      message,
      templateId,
      templateName,
      severity,
      payload,
    };
    logs.push(entry);
    if (options.onProgressLog) {
      options.onProgressLog(entry);
    }
  };

  emitLog('info', `Initializing scan session on target: ${normalizedUrl}`);
  if (options.proxy?.enabled && options.proxy?.url) {
    emitLog('info', `[Proxy Active] Upstream security proxy engaged: ${options.proxy.url} (SSL Validation: ${options.proxy.insecureSkipVerify ? 'Disabled/Burp-Bypass' : 'Strict'})`);
  }
  emitLog('info', `Loaded ${templates.length} active YAML automation templates (OWASP/Nuclei/Burp Suite engine)`);

  for (const tpl of templates) {
    if (!tpl.enabled) continue;
    templatesExecuted++;

    let parsed: ParsedTemplate;
    try {
      parsed = yaml.load(tpl.rawYaml) as ParsedTemplate;
    } catch (err: any) {
      emitLog('warn', `Failed to parse YAML template [${tpl.id}]: ${err.message}`, tpl.id);
      continue;
    }

    const tplName = parsed?.info?.name || tpl.name;
    const tplSeverity = (parsed?.info?.severity || tpl.severity || 'medium') as VulnerabilitySeverity;
    const defaultCvss = tplSeverity === 'critical' ? 9.1 : tplSeverity === 'high' ? 7.5 : tplSeverity === 'medium' ? 5.3 : tplSeverity === 'low' ? 3.1 : 0.0;
    const cvssScore = parsed?.info?.classification?.['cvss-score'] ?? defaultCvss;
    const cvssVector = parsed?.info?.classification?.['cvss-vector'] || 
      (tplSeverity === 'critical' ? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' :
       tplSeverity === 'high' ? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' :
       tplSeverity === 'medium' ? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N' :
       tplSeverity === 'low' ? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N' :
       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N');

    const cweId = parsed?.info?.classification?.['cwe-id'] || 'CWE-693';
    const owaspCategory = parsed?.info?.classification?.['owasp-category'] || 'A05:2021-Security Misconfiguration';
    const description = parsed?.info?.description || tpl.description;
    const references = parsed?.info?.reference || [];

    emitLog('info', `[${tpl.id}] Executing audit: "${tplName}"`, tpl.id, undefined, tplName);

    const requests = parsed.requests || [];
    for (const reqConfig of requests) {
      const method = (reqConfig.method || 'GET').toUpperCase();
      const paths = reqConfig.path && reqConfig.path.length > 0 ? reqConfig.path : ['{{BaseURL}}/'];

      for (const rawPath of paths) {
        const fullUrl = rawPath.replace(/\{\{BaseURL\}\}/g, normalizedUrl);
        requestsSent++;

        const requestHeaders: Record<string, string> = {
          'User-Agent': userAgent,
          'Accept': '*/*',
          ...(reqConfig.headers || {}),
        };

        if (options.proxy?.enabled && options.proxy?.username) {
          const authString = `${options.proxy.username}:${options.proxy.password || ''}`;
          requestHeaders['Proxy-Authorization'] = `Basic ${Buffer.from(authString).toString('base64')}`;
        }

        emitLog(
          'info',
          `[PROBE] Transmitting ${method} ${fullUrl}`,
          tpl.id,
          undefined,
          tplName,
          {
            method,
            url: fullUrl,
            headers: requestHeaders,
            body: reqConfig.body,
          }
        );

        let responseStatusCode = 0;
        let responseHeaders: Record<string, string> = {};
        let responseBody = '';
        let responseTimeMs = 0;

        try {
          const reqStart = Date.now();
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeoutMs);

          const res = await fetch(fullUrl, {
            method,
            headers: requestHeaders,
            body: method !== 'GET' && method !== 'HEAD' && reqConfig.body ? reqConfig.body : undefined,
            signal: controller.signal,
            redirect: 'follow',
            dispatcher,
          } as any);

          clearTimeout(timer);
          responseTimeMs = Date.now() - reqStart;
          responseStatusCode = res.status;

          // Extract response headers
          res.headers.forEach((val, key) => {
            responseHeaders[key.toLowerCase()] = val;
          });

          // Read response text (capped at 100KB)
          const text = await res.text();
          responseBody = text.slice(0, 100000);
        } catch (fetchErr: any) {
          emitLog('warn', `[${tpl.id}] Request error to ${fullUrl}: ${fetchErr.name === 'AbortError' ? 'Connection timeout' : fetchErr.message}`, tpl.id);
        }

        // Multi-Condition Matcher Engine
        const matchers = reqConfig.matchers || [];
        const matchersCondition = reqConfig['matchers-condition'] || 'and';
        const matcherResults: boolean[] = [];
        let matchedEvidence = '';

        // Anti-False-Positive: Check for Soft-404 if status is 200 on deep probes
        const isSoft404 = responseStatusCode === 200 && isSoft404ErrorPage(responseBody, rawPath);
        if (isSoft404 && tpl.id !== 'owasp-security-headers') {
          emitLog('pass', `[ANTI-FP] Suppressed Soft-404 false positive for ${fullUrl} (Returned 200 with error page text).`, tpl.id);
          continue;
        }

        for (const matcher of matchers) {
          let matcherSatisfied = false;
          const isNegative = matcher.negative === true;
          const condition = matcher.condition || 'or';

          if (matcher.type === 'status') {
            const expectedStatuses = matcher.status || [200];
            const matchStatus = expectedStatuses.includes(responseStatusCode);
            matcherSatisfied = isNegative ? !matchStatus : matchStatus;
            if (matcherSatisfied) {
              matchedEvidence += `HTTP Status ${responseStatusCode} matched [${expectedStatuses.join(', ')}]. `;
            }
          } else if (matcher.type === 'content-type') {
            const expectedTypes = matcher['content-type'] || [];
            const actualContentType = (responseHeaders['content-type'] || '').toLowerCase();
            const typeMatch = expectedTypes.some(t => actualContentType.includes(t.toLowerCase()));
            matcherSatisfied = isNegative ? !typeMatch : typeMatch;
            if (matcherSatisfied) {
              matchedEvidence += `Content-Type matched "${actualContentType}". `;
            }
          } else if (matcher.type === 'size') {
            const bodyLen = responseBody.length;
            const minSize = matcher['min-size'] ?? 0;
            const maxSize = matcher['max-size'] ?? Infinity;
            const sizeMatch = bodyLen >= minSize && bodyLen <= maxSize;
            matcherSatisfied = isNegative ? !sizeMatch : sizeMatch;
            if (matcherSatisfied) {
              matchedEvidence += `Body length (${bodyLen} bytes) within expected range. `;
            }
          } else if (matcher.type === 'header') {
            const words = matcher.words || [];
            const headerString = Object.entries(responseHeaders)
              .map(([k, v]) => `${k}: ${v}`)
              .join('\n');

            let wordMatches: boolean[] = [];
            for (const word of words) {
              const lowerWord = word.toLowerCase();
              const hasWord = headerString.toLowerCase().includes(lowerWord);
              wordMatches.push(hasWord);
              if (!isNegative && hasWord) {
                matchedEvidence += `Header matched "${word}". `;
              } else if (isNegative && !hasWord) {
                matchedEvidence += `Missing security header "${word}". `;
              }
            }

            if (condition === 'and') {
              matcherSatisfied = wordMatches.length > 0 && wordMatches.every(m => m === true);
            } else {
              matcherSatisfied = wordMatches.some(m => m === true);
            }

            if (isNegative) {
              matcherSatisfied = !matcherSatisfied;
            }
          } else if (matcher.type === 'word') {
            const part = matcher.part || 'body';
            const targetText =
              part === 'header'
                ? Object.entries(responseHeaders).map(([k, v]) => `${k}: ${v}`).join('\n')
                : part === 'all'
                ? `${Object.entries(responseHeaders).map(([k, v]) => `${k}: ${v}`).join('\n')}\n\n${responseBody}`
                : responseBody;

            const words = matcher.words || [];
            let wordMatches: boolean[] = [];

            for (const word of words) {
              const hasWord = targetText.toLowerCase().includes(word.toLowerCase());
              wordMatches.push(hasWord);
              if (!isNegative && hasWord) {
                matchedEvidence += `Found signature token "${word}". `;
              } else if (isNegative && !hasWord) {
                matchedEvidence += `Did not find expected token "${word}". `;
              }
            }

            if (condition === 'and') {
              matcherSatisfied = wordMatches.length > 0 && wordMatches.every(m => m === true);
            } else {
              matcherSatisfied = wordMatches.some(m => m === true);
            }

            if (isNegative) {
              matcherSatisfied = !matcherSatisfied;
            }
          }

          matcherResults.push(matcherSatisfied);
        }

        // Combine all matchers with matchers-condition
        const overallMatched =
          matchers.length > 0 &&
          (matchersCondition === 'and'
            ? matcherResults.every(r => r === true)
            : matcherResults.some(r => r === true));

        if (overallMatched) {
          const findingId = `${tpl.id}-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
          
          let remediation = 'Inspect and update server configuration according to security standards.';
          let subFindings: SubFindingItem[] = [];

          if (tpl.id === 'owasp-security-headers') {
            const missingList: { name: string; key: string }[] = [];
            if (!responseHeaders['content-security-policy']) {
              missingList.push({ name: 'Content-Security-Policy', key: 'csp' });
              subFindings.push({
                id: 'sub-csp',
                name: 'Missing Content-Security-Policy (CSP)',
                severity: 'low',
                evidence: 'No "Content-Security-Policy" header detected in HTTP response.',
                remediation: 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\' https:;" always;',
              });
            }
            if (!responseHeaders['x-frame-options']) {
              missingList.push({ name: 'X-Frame-Options', key: 'frame' });
              subFindings.push({
                id: 'sub-xfo',
                name: 'Missing X-Frame-Options (Clickjacking Protection)',
                severity: 'low',
                evidence: 'No "X-Frame-Options" or CSP "frame-ancestors" directive present.',
                remediation: 'add_header X-Frame-Options "SAMEORIGIN" always;',
              });
            }
            if (!responseHeaders['x-content-type-options']) {
              missingList.push({ name: 'X-Content-Type-Options: nosniff', key: 'sniff' });
              subFindings.push({
                id: 'sub-sniff',
                name: 'Missing X-Content-Type-Options (MIME-Sniffing Defense)',
                severity: 'low',
                evidence: 'Header "X-Content-Type-Options: nosniff" is absent.',
                remediation: 'add_header X-Content-Type-Options "nosniff" always;',
              });
            }
            if (!responseHeaders['strict-transport-security']) {
              missingList.push({ name: 'Strict-Transport-Security (HSTS)', key: 'hsts' });
              subFindings.push({
                id: 'sub-hsts',
                name: 'Missing Strict-Transport-Security (HSTS)',
                severity: 'low',
                evidence: 'No "Strict-Transport-Security" header present to enforce TLS.',
                remediation: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
              });
            }

            matchedEvidence = `HTTP GET ${responseStatusCode} (${responseTimeMs}ms) — Missing defensive headers:\n` +
              missingList.map(h => `• [MISSING] ${h.name}`).join('\n');

            remediation = 'Add defensive HTTP security headers to your web server / reverse proxy (Nginx, Apache, Express, LiteSpeed, Cloudflare):\n\n' +
              'Recommended headers:\n' +
              '• Content-Security-Policy: default-src \'self\'; script-src \'self\' https:; object-src \'none\';\n' +
              '• X-Frame-Options: SAMEORIGIN\n' +
              '• X-Content-Type-Options: nosniff\n' +
              '• Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n' +
              '• Referrer-Policy: strict-origin-when-cross-origin\n\n' +
              'Nginx Configuration (nginx.conf / sites-available):\n' +
              'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\' https:;" always;\n' +
              'add_header X-Frame-Options "SAMEORIGIN" always;\n' +
              'add_header X-Content-Type-Options "nosniff" always;\n' +
              'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\n' +
              'add_header Referrer-Policy "strict-origin-when-cross-origin" always;\n' +
              'server_tokens off;';
          } else if (tpl.id === 'exposed-env-credentials') {
            remediation = 'Immediately block public HTTP access to .env* files in web server rules and invalidate/rotate any database credentials or API keys exposed.';
          } else if (tpl.id === 'exposed-git-repository') {
            remediation = 'Deny web access to /.git/ directory and all subfiles via web server rules (e.g., in Nginx: location ~ /\\.git { deny all; }).';
          } else if (tpl.id === 'cors-misconfiguration') {
            remediation = 'Avoid wildcards (*) in Access-Control-Allow-Origin when authentication is enabled. Maintain a strict whitelist of trusted origins.';
          } else if (tpl.id === 'cookie-security-flags') {
            remediation = 'Enforce HttpOnly, Secure, and SameSite=Lax/Strict flags on all session cookies to mitigate XSS session hijacking.';
          } else if (tpl.id === 'server-version-disclosure') {
            remediation = 'Disable verbose server banner and framework fingerprint tokens (e.g., in Express: app.disable("x-powered-by"); in Nginx: server_tokens off;).';
          } else if (tpl.id === 'sqli-error-signatures') {
            remediation = 'Use parameterized queries / prepared statements exclusively. Disable verbose database error reporting in client responses.';
          } else if (tpl.id === 'xss-reflection-passive') {
            remediation = 'Apply context-aware output encoding (HTML entity escaping) and enforce Content-Security-Policy (CSP).';
          } else if (tpl.id === 'api-debug-endpoints') {
            remediation = 'Restrict public access to Swagger UI, OpenAPI JSON documentation, and Actuator health/metric debug endpoints using authentication or network firewall rules.';
          }

          const isAggregated = tpl.id === 'owasp-security-headers' || tpl.id === 'cookie-security-flags' || tpl.id === 'server-version-disclosure';

          const finding: VulnerabilityFinding = {
            id: findingId,
            templateId: tpl.id,
            name: tplName,
            severity: tplSeverity,
            cvssScore,
            cvssVector,
            cvssVersion: '3.1',
            cweId,
            owaspCategory,
            description,
            url: fullUrl,
            matchedAt: fullUrl,
            evidence: matchedEvidence.trim() || 'Triggered matching conditions defined in YAML template.',
            findingType: isAggregated ? 'aggregated' : 'atomic',
            subFindings: subFindings.length > 0 ? subFindings : undefined,
            request: {
              method,
              url: fullUrl,
              headers: requestHeaders,
            },
            response: {
              statusCode: responseStatusCode,
              headers: responseHeaders,
              bodySnippet: responseBody.slice(0, 500),
              responseTimeMs,
            },
            remediation,
            references,
            timestamp: new Date().toISOString(),
          };

          rawFindings.push(finding);

          const logSeverityLevel = tplSeverity === 'critical' || tplSeverity === 'high' ? 'crit' : 'warn';
          emitLog(
            logSeverityLevel,
            `[${tplSeverity.toUpperCase()}] [${tpl.id}] Identified: "${tplName}" at ${fullUrl}`,
            tpl.id,
            tplSeverity,
            tplName,
            {
              method,
              url: fullUrl,
              headers: requestHeaders,
              body: reqConfig.body,
              statusCode: responseStatusCode,
              responseTimeMs,
              matched: true,
              evidence: matchedEvidence.trim() || 'Triggered matching conditions',
              matchersCondition,
            }
          );
        } else {
          emitLog(
            'pass',
            `[PASS] [${tpl.id}] Passed on ${fullUrl} (HTTP ${responseStatusCode}, ${responseTimeMs}ms)`,
            tpl.id,
            undefined,
            tplName,
            {
              method,
              url: fullUrl,
              headers: requestHeaders,
              body: reqConfig.body,
              statusCode: responseStatusCode,
              responseTimeMs,
              matched: false,
              evidence: 'No vulnerable signature or misconfiguration detected.',
              matchersCondition,
            }
          );
        }
      }
    }
  }

  // POST-PROCESSING PIPELINE: Deduplication, Aggregation & Contextual CVSS Scoring
  const postProcessedFindings: VulnerabilityFinding[] = [];
  const seenTemplateTarget = new Set<string>();

  for (const raw of rawFindings) {
    const key = `${raw.templateId}::${raw.matchedAt}`;
    if (seenTemplateTarget.has(key)) continue;
    seenTemplateTarget.add(key);
    postProcessedFindings.push(raw);
  }

  // Contextual Risk Evaluation:
  // If active reflected input (XSS canary) exists alongside missing CSP, dynamically elevate header severity
  const hasXssCanary = postProcessedFindings.some(f => f.templateId === 'xss-reflection-passive');
  if (hasXssCanary) {
    for (const f of postProcessedFindings) {
      if (f.templateId === 'owasp-security-headers') {
        f.severity = 'medium';
        f.cvssScore = 5.3;
        f.cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N';
        f.contextualNotes = 'Contextual Severity Elevation: Baseline Low (3.1) escalated to Medium (5.3) because active reflected parameter canary was also detected, creating an exploitable vector in the absence of Content-Security-Policy (CSP).';
      }
    }
  }

  const endTime = new Date().toISOString();
  const durationMs = Date.now() - startTimestamp;

  emitLog(
    'info',
    `Audit completed in ${(durationMs / 1000).toFixed(1)}s. Executed ${templatesExecuted} templates, sent ${requestsSent} requests. Consolidated ${postProcessedFindings.length} root finding(s).`
  );

  return {
    id: `scan-${Date.now()}`,
    targetUrl: normalizedUrl,
    startTime,
    endTime,
    durationMs,
    status: 'completed',
    findings: postProcessedFindings,
    templatesExecuted,
    requestsSent,
    logs,
  };
}

