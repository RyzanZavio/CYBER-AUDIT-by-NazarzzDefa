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
  reference?: string[] | string;
  tags?: string[] | string;
  remediation?: string;
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
    scanId?: string;
    timeoutMs?: number;
    userAgent?: string;
    proxy?: ProxyConfig;
    threads?: number;
    abortSignal?: AbortSignal;
    onProgressLog?: (log: ScanLog) => void;
  } = {}
): Promise<ScanResult> {
  const startTime = new Date().toISOString();
  const startTimestamp = Date.now();
  const timeoutMs = options.timeoutMs || 8000;
  const threads = Math.max(1, Math.min(25, Number(options.threads) || 5));
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
  let isCancelled = false;

  if (options.abortSignal?.aborted) {
    isCancelled = true;
  }
  options.abortSignal?.addEventListener('abort', () => {
    isCancelled = true;
  });

  const emitLog = (
    level: 'info' | 'warn' | 'crit' | 'pass',
    message: string,
    templateId?: string,
    severity?: VulnerabilitySeverity,
    templateName?: string,
    payload?: any
  ) => {
    const log: ScanLog = {
      id: `log-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      level,
      message,
      templateId,
      severity,
      templateName,
      payload,
    };
    logs.push(log);
    if (options.onProgressLog) {
      options.onProgressLog(log);
    }
  };

  emitLog('info', `Initializing DevSecOps Vulnerability Scan targeting: ${normalizedUrl} (Concurrency: ${threads} threads)`);
  if (options.proxy?.enabled && options.proxy?.url) {
    emitLog('info', `[Proxy Active] Upstream security proxy engaged: ${options.proxy.url} (SSL Validation: ${options.proxy.insecureSkipVerify ? 'Disabled/Burp-Bypass' : 'Strict'})`);
  }
  emitLog('info', `Loaded ${templates.length} active YAML automation templates (Threads: ${threads}, OWASP/Nuclei/Burp Suite engine)`);

  const executeTemplate = async (tpl: YamlTemplate) => {
    if (isCancelled || options.abortSignal?.aborted) {
      isCancelled = true;
      return;
    }

    let parsed: ParsedTemplate;
    try {
      parsed = yaml.load(tpl.rawYaml) as ParsedTemplate;
    } catch (err: any) {
      emitLog('warn', `Failed to parse YAML template [${tpl.id}]: ${err.message}`, tpl.id);
      return;
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
    const rawRefs = parsed?.info?.reference;
    const references = Array.isArray(rawRefs) ? rawRefs : typeof rawRefs === 'string' ? [rawRefs] : [];

    emitLog('info', `[${tpl.id}] Executing audit: "${tplName}"`, tpl.id, undefined, tplName);

    const requests = parsed.requests || [];
    for (const reqConfig of requests) {
      if (isCancelled || options.abortSignal?.aborted) {
        isCancelled = true;
        return;
      }

      const method = (reqConfig.method || 'GET').toUpperCase();
      const paths = reqConfig.path && reqConfig.path.length > 0 ? reqConfig.path : ['{{BaseURL}}/'];

      for (const rawPath of paths) {
        if (isCancelled || options.abortSignal?.aborted) {
          isCancelled = true;
          return;
        }

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

        // Redact sensitive headers from log output to prevent credential disclosure
        const sanitizedHeadersForLog: Record<string, string> = {};
        for (const [k, v] of Object.entries(requestHeaders)) {
          if (/^(authorization|proxy-authorization|cookie|x-api-key|apikey|token|set-cookie)$/i.test(k)) {
            sanitizedHeadersForLog[k] = '[REDACTED]';
          } else {
            sanitizedHeadersForLog[k] = v;
          }
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
            headers: sanitizedHeadersForLog,
            body: reqConfig.body,
          }
        );

        let responseStatusCode = 0;
        let responseHeaders: Record<string, string> = {};
        let responseBody = '';
        let responseTimeMs = 0;

        try {
          const reqStart = Date.now();
          const fetchSignal = options.abortSignal
            ? AbortSignal.any([AbortSignal.timeout(timeoutMs), options.abortSignal])
            : AbortSignal.timeout(timeoutMs);

          const res = await fetch(fullUrl, {
            method,
            headers: requestHeaders,
            body: method !== 'GET' && method !== 'HEAD' && reqConfig.body ? reqConfig.body : undefined,
            signal: fetchSignal,
            redirect: 'follow',
            dispatcher,
          } as any);

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
          if (isCancelled || options.abortSignal?.aborted || (fetchErr.name === 'AbortError' && options.abortSignal?.aborted)) {
            isCancelled = true;
            return;
          }
          emitLog('warn', `[${tpl.id}] Request error to ${fullUrl}: ${fetchErr.name === 'AbortError' ? 'Connection timeout' : fetchErr.message}`, tpl.id);
        }

        if (isCancelled || options.abortSignal?.aborted) {
          isCancelled = true;
          return;
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
          } else if (matcher.type === 'regex') {
            const part = matcher.part || 'body';
            const targetText =
              part === 'header'
                ? Object.entries(responseHeaders).map(([k, v]) => `${k}: ${v}`).join('\n')
                : part === 'all'
                ? `${Object.entries(responseHeaders).map(([k, v]) => `${k}: ${v}`).join('\n')}\n\n${responseBody}`
                : responseBody;

            const patterns = matcher.regex || [];
            let regexMatches: boolean[] = [];

            for (const pat of patterns) {
              try {
                let flags = 'm';
                let cleanPat = pat;
                if (cleanPat.startsWith('(?i)')) {
                  flags += 'i';
                  cleanPat = cleanPat.substring(4);
                }
                const re = new RegExp(cleanPat, flags);
                const isMatch = re.test(targetText);
                regexMatches.push(isMatch);
                if (!isNegative && isMatch) {
                  matchedEvidence += `Matched pattern "${pat}". `;
                } else if (isNegative && !isMatch) {
                  matchedEvidence += `Did not match pattern "${pat}". `;
                }
              } catch {
                regexMatches.push(false);
              }
            }

            if (condition === 'and') {
              matcherSatisfied = regexMatches.length > 0 && regexMatches.every(m => m === true);
            } else {
              matcherSatisfied = regexMatches.some(m => m === true);
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
          
          // Extensible Remediation Engine:
          // 1. Prefer explicit info.remediation defined in the YAML schema
          // 2. Fallback dynamically based on CWE / OWASP classification
          let remediation = parsed?.info?.remediation?.trim() || '';
          if (!remediation) {
            if (cweId === 'CWE-693' || tpl.id === 'owasp-security-headers') {
              remediation = 'Add defensive HTTP security headers to your web server (CSP, X-Frame-Options, X-Content-Type-Options, HSTS).';
            } else if (cweId === 'CWE-200' || cweId === 'CWE-538' || cweId === 'CWE-530') {
              remediation = 'Restrict public web server access to sensitive files and directories using authentication or rewrite rules.';
            } else if (cweId === 'CWE-89') {
              remediation = 'Use parameterized queries / prepared statements exclusively. Disable verbose database error reporting.';
            } else if (cweId === 'CWE-79') {
              remediation = 'Apply context-aware output encoding (HTML entity escaping) and enforce Content-Security-Policy (CSP).';
            } else if (cweId === 'CWE-346') {
              remediation = 'Maintain a strict whitelist of trusted origins and avoid reflecting untrusted Origin headers with credentials.';
            } else if (cweId === 'CWE-918') {
              remediation = 'Validate and whitelist all outbound URLs; block access to private RFC1918 and cloud metadata (169.254.169.254) addresses.';
            } else if (cweId === 'CWE-22') {
              remediation = 'Validate and sanitize file path parameters. Use path normalization to prevent directory traversal outside webroot.';
            } else if (cweId === 'CWE-287' || cweId === 'CWE-306') {
              remediation = 'Enforce robust authentication and authorization checks on all sensitive administrative endpoints.';
            } else {
              remediation = 'Inspect and update server configuration and application code according to OWASP / NIST security standards.';
            }
          }

          let subFindings: SubFindingItem[] = [];

          // Dynamic sub-findings evaluation
          if (tpl.id === 'owasp-security-headers' || (cweId === 'CWE-693' && matchers.some(m => m.negative && m.type === 'header'))) {
            const missingList: { name: string; key: string }[] = [];
            if (!responseHeaders['content-security-policy']) {
              missingList.push({ name: 'Content-Security-Policy', key: 'csp' });
              subFindings.push({
                id: 'sub-csp',
                name: 'Missing Content-Security-Policy (CSP)',
                severity: 'low',
                evidence: 'No "Content-Security-Policy" header detected in HTTP response.',
                remediation: "add_header Content-Security-Policy \"default-src 'self'; script-src 'self' https:;\" always;",
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

            if (missingList.length > 0) {
              matchedEvidence = `HTTP GET ${responseStatusCode} (${responseTimeMs}ms) — Missing defensive headers:\n` +
                missingList.map(h => `• [MISSING] ${h.name}`).join('\n');
            }
          } else if (tpl.id === 'cookie-security-flags' || cweId === 'CWE-614') {
            const setCookie = responseHeaders['set-cookie'] || '';
            if (setCookie) {
              if (!setCookie.toLowerCase().includes('httponly')) {
                subFindings.push({
                  id: 'sub-httponly',
                  name: 'Missing HttpOnly Flag on Cookie',
                  severity: 'low',
                  evidence: 'Cookie set without "HttpOnly" attribute, leaving it accessible to client-side scripts.',
                  remediation: 'Append "HttpOnly" flag in Set-Cookie header.',
                });
              }
              if (!setCookie.toLowerCase().includes('secure')) {
                subFindings.push({
                  id: 'sub-secure',
                  name: 'Missing Secure Flag on Cookie',
                  severity: 'low',
                  evidence: 'Cookie set without "Secure" attribute, allowing transmission over cleartext HTTP.',
                  remediation: 'Append "Secure" flag in Set-Cookie header.',
                });
              }
              if (!setCookie.toLowerCase().includes('samesite')) {
                subFindings.push({
                  id: 'sub-samesite',
                  name: 'Missing SameSite Flag on Cookie',
                  severity: 'low',
                  evidence: 'Cookie set without "SameSite" attribute (Lax/Strict), increasing CSRF risk.',
                  remediation: 'Append "SameSite=Lax" or "SameSite=Strict" in Set-Cookie header.',
                });
              }
            }
          }

          const isAggregated = subFindings.length > 0;

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
  };

  // Multi-threaded worker queue: execute enabled templates with configured concurrency
  const enabledTemplates = templates.filter(t => t.enabled);
  let templateCursor = 0;
  const workerCount = Math.min(threads, Math.max(1, enabledTemplates.length));

  const workers = Array.from({ length: workerCount }, async () => {
    while (templateCursor < enabledTemplates.length) {
      if (isCancelled || options.abortSignal?.aborted) {
        isCancelled = true;
        break;
      }
      const currentIndex = templateCursor++;
      const tpl = enabledTemplates[currentIndex];
      if (!tpl) break;
      templatesExecuted++;
      await executeTemplate(tpl);
    }
  });

  await Promise.all(workers);

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

  if (isCancelled) {
    emitLog(
      'warn',
      `[CANCELLED] Scan was cancelled by user after ${(durationMs / 1000).toFixed(1)}s. Executed ${templatesExecuted} templates, sent ${requestsSent} requests before termination.`
    );
  } else {
    emitLog(
      'info',
      `Audit completed in ${(durationMs / 1000).toFixed(1)}s. Executed ${templatesExecuted} templates with ${threads} concurrent threads, sent ${requestsSent} requests. Consolidated ${postProcessedFindings.length} root finding(s).`
    );
  }

  return {
    id: options.scanId || `scan-${Date.now()}`,
    targetUrl: normalizedUrl,
    startTime,
    endTime,
    durationMs,
    status: isCancelled ? 'cancelled' : 'completed',
    findings: postProcessedFindings,
    templatesExecuted,
    requestsSent,
    logs,
    threads,
  };
}
