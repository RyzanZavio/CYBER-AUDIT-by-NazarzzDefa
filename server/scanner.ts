import * as yaml from 'js-yaml';
import { ProxyAgent } from 'undici';
import {
  ProxyConfig,
  ScanLog,
  ScanResult,
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
    'cwe-id'?: string;
    'owasp-category'?: string;
  };
}

interface ParsedMatcher {
  type: 'word' | 'regex' | 'status' | 'header';
  part?: 'body' | 'header' | 'all';
  words?: string[];
  regex?: string[];
  status?: number[];
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

  // Setup Upstream Proxy Dispatcher (Burp Suite, OWASP ZAP, Tor, Corporate Gateway)
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
  // Strip trailing slash for template {{BaseURL}} substitution
  normalizedUrl = normalizedUrl.replace(/\/+$/, '');

  const logs: ScanLog[] = [];
  const findings: VulnerabilityFinding[] = [];
  let requestsSent = 0;
  let templatesExecuted = 0;

  const emitLog = (level: 'info' | 'warn' | 'crit' | 'pass', message: string, templateId?: string, severity?: VulnerabilitySeverity) => {
    const entry: ScanLog = {
      timestamp: new Date().toLocaleTimeString(),
      level,
      message,
      templateId,
      severity,
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
    const cvssScore = parsed?.info?.classification?.['cvss-score'] ?? (tplSeverity === 'critical' ? 9.5 : tplSeverity === 'high' ? 7.8 : tplSeverity === 'medium' ? 5.2 : 3.0);
    const cweId = parsed?.info?.classification?.['cwe-id'] || 'CWE-693';
    const owaspCategory = parsed?.info?.classification?.['owasp-category'] || 'A05:2021-Security Misconfiguration';
    const description = parsed?.info?.description || tpl.description;
    const references = parsed?.info?.reference || [];

    emitLog('info', `[${tpl.id}] Executing audit: "${tplName}"`, tpl.id);

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

          // Read response text (limit to 100KB to avoid excessive memory)
          const text = await res.text();
          responseBody = text.slice(0, 100000);
        } catch (fetchErr: any) {
          emitLog('warn', `[${tpl.id}] Request error to ${fullUrl}: ${fetchErr.name === 'AbortError' ? 'Connection timeout' : fetchErr.message}`, tpl.id);
          // Still allow evaluating negative header matchers (e.g. if host is HTTPS check)
        }

        // Evaluate Matchers
        const matchers = reqConfig.matchers || [];
        const matchersCondition = reqConfig['matchers-condition'] || 'and';
        const matcherResults: boolean[] = [];
        let matchedEvidence = '';

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
          if (tpl.id === 'owasp-security-headers') {
            remediation = 'Configure defensive HTTP response headers in your web server/reverse proxy (Nginx, Cloudflare, Apache, or Express): Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options: nosniff, and X-Frame-Options: DENY.';
          } else if (tpl.id === 'exposed-env-credentials') {
            remediation = 'Immediately block public HTTP access to .env* files in web server rules and invalidate/rotate any secrets, database credentials, or API keys exposed.';
          } else if (tpl.id === 'exposed-git-repository') {
            remediation = 'Deny web access to /.git/ directory and all subfiles via web server rules (e.g. nginx location ~ /\\.git { deny all; }).';
          } else if (tpl.id === 'cors-misconfiguration') {
            remediation = 'Avoid wildcards (*) in Access-Control-Allow-Origin when authentication is enabled. Maintain a strict whitelist of trusted partner origins.';
          } else if (tpl.id === 'cookie-security-flags') {
            remediation = 'Enforce HttpOnly, Secure, and SameSite=Lax/Strict flags on all session cookies to mitigate XSS-based session hijacking and CSRF attacks.';
          } else if (tpl.id === 'server-version-disclosure') {
            remediation = 'Disable server banner and framework fingerprint tokens (e.g., in Express: app.disable("x-powered-by"); in Nginx: server_tokens off;).';
          } else if (tpl.id === 'sqli-error-signatures') {
            remediation = 'Use parameterized queries / prepared statements exclusively. Disable verbose database error reporting to client responses.';
          } else if (tpl.id === 'xss-reflection-passive') {
            remediation = 'Apply context-aware output encoding (HTML escaping) and enforce Content-Security-Policy (CSP) with script-src nonces.';
          }

          const finding: VulnerabilityFinding = {
            id: findingId,
            templateId: tpl.id,
            name: tplName,
            severity: tplSeverity,
            cvssScore,
            cweId,
            owaspCategory,
            description,
            url: fullUrl,
            matchedAt: fullUrl,
            evidence: matchedEvidence.trim() || 'Triggered matching conditions defined in YAML template.',
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

          findings.push(finding);

          const logSeverityLevel = tplSeverity === 'critical' || tplSeverity === 'high' ? 'crit' : 'warn';
          emitLog(
            logSeverityLevel,
            `[${tplSeverity.toUpperCase()}] [${tpl.id}] Found: "${tplName}" at ${fullUrl}`,
            tpl.id,
            tplSeverity
          );
        } else {
          emitLog('pass', `[PASS] [${tpl.id}] No vulnerabilities detected on ${fullUrl}`, tpl.id);
        }
      }
    }
  }

  const endTime = new Date().toISOString();
  const durationMs = Date.now() - startTimestamp;

  emitLog(
    'info',
    `Audit completed in ${(durationMs / 1000).toFixed(1)}s. Executed ${templatesExecuted} templates, sent ${requestsSent} requests. Identified ${findings.length} finding(s).`
  );

  return {
    id: `scan-${Date.now()}`,
    targetUrl: normalizedUrl,
    startTime,
    endTime,
    durationMs,
    status: 'completed',
    findings,
    templatesExecuted,
    requestsSent,
    logs,
  };
}
