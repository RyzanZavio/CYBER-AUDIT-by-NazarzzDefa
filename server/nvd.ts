import { CveDatabaseItem, RAW_CVE_DATABASE } from '../src/data/cveDatabase';
import { VulnerabilitySeverity, YamlTemplate } from '../src/types';
import { syncTemplateWithYaml } from '../src/utils/templateParser';

export const NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

// Optional NVD API Key (configured securely via environment variable NVD_API_KEY)
export const NVD_API_KEY = process.env.NVD_API_KEY || '';

// Known CISA KEV (Known Exploited Vulnerabilities) set curated from verified intelligence
const KNOWN_CISA_KEV_IDS = new Set<string>(
  RAW_CVE_DATABASE.filter(c => c.isKev).map(c => c.cveId.toUpperCase())
);

/**
 * Checks whether a CVE is genuinely documented in the CISA KEV catalog,
 * using official NIST NVD 2.0 metadata fields, explicit tags, or the curated catalog.
 * NEVER guesses based on CVSS score alone!
 */
export function isCisaKev(cveObj: any): boolean {
  if (!cveObj || !cveObj.id) return false;
  const idUpper = cveObj.id.toUpperCase();

  // 1. Official CISA KEV fields present in NIST NVD 2.0 API schema
  if (
    cveObj.cisaExploitAdd ||
    cveObj.cisaActionDue ||
    cveObj.cisaRequiredAction ||
    cveObj.cisaVulnerabilityName
  ) {
    return true;
  }

  // 2. Tagged explicitly in NVD metadata as knownExploited
  if (Array.isArray(cveObj.cveTags)) {
    const hasKevTag = cveObj.cveTags.some((t: any) => {
      if (typeof t === 'string') {
        const lower = t.toLowerCase();
        return lower.includes('knownexploited') || lower === 'kev';
      }
      if (Array.isArray(t?.tags)) {
        return t.tags.some((sub: string) => typeof sub === 'string' && sub.toLowerCase().includes('knownexploited'));
      }
      return false;
    });
    if (hasKevTag) return true;
  }

  // 3. Known verified CISA KEV intelligence catalog
  if (KNOWN_CISA_KEV_IDS.has(idUpper)) {
    return true;
  }

  return false;
}

export interface NvdCvssMetrics {
  version: string;
  baseScore: number;
  severity: VulnerabilitySeverity;
  vectorString: string;
  exploitabilityScore?: number;
  impactScore?: number;
  attackVector?: string;
  attackComplexity?: string;
  privilegesRequired?: string;
  userInteraction?: string;
  scope?: string;
  confidentialityImpact?: string;
  integrityImpact?: string;
  availabilityImpact?: string;
}

export interface NvdCveDetail {
  cveId: string;
  name: string;
  description: string;
  publishedDate: string;
  lastModifiedDate: string;
  vulnStatus: string;
  sourceIdentifier: string;
  cvss: NvdCvssMetrics;
  cweId: string;
  cweName?: string;
  owaspCategory: string;
  affectedTech: string;
  cpeConfigurations: string[];
  references: { url: string; source: string; tags?: string[] }[];
  isKev: boolean;
  generatedYamlTemplate?: YamlTemplate;
}

/**
 * Parses CVSS metrics from NIST NVD 2.0 response format (CVSS v3.1, v3.0, or v2.0)
 */
export function extractCvssMetrics(metrics: any): NvdCvssMetrics {
  // 1. Prefer CVSS v3.1
  if (metrics?.cvssMetricV31 && metrics.cvssMetricV31.length > 0) {
    const primary = metrics.cvssMetricV31.find((m: any) => m.type === 'Primary') || metrics.cvssMetricV31[0];
    const data = primary.cvssData || {};
    const baseSeverity = (data.baseSeverity || 'MEDIUM').toLowerCase() as VulnerabilitySeverity;

    return {
      version: '3.1',
      baseScore: data.baseScore || 0,
      severity: baseSeverity,
      vectorString: data.vectorString || '',
      exploitabilityScore: primary.exploitabilityScore,
      impactScore: primary.impactScore,
      attackVector: data.attackVector,
      attackComplexity: data.attackComplexity,
      privilegesRequired: data.privilegesRequired,
      userInteraction: data.userInteraction,
      scope: data.scope,
      confidentialityImpact: data.confidentialityImpact,
      integrityImpact: data.integrityImpact,
      availabilityImpact: data.availabilityImpact,
    };
  }

  // 2. Fallback to CVSS v3.0
  if (metrics?.cvssMetricV30 && metrics.cvssMetricV30.length > 0) {
    const primary = metrics.cvssMetricV30.find((m: any) => m.type === 'Primary') || metrics.cvssMetricV30[0];
    const data = primary.cvssData || {};
    const baseSeverity = (data.baseSeverity || 'MEDIUM').toLowerCase() as VulnerabilitySeverity;

    return {
      version: '3.0',
      baseScore: data.baseScore || 0,
      severity: baseSeverity,
      vectorString: data.vectorString || '',
      exploitabilityScore: primary.exploitabilityScore,
      impactScore: primary.impactScore,
      attackVector: data.attackVector,
      attackComplexity: data.attackComplexity,
      privilegesRequired: data.privilegesRequired,
      userInteraction: data.userInteraction,
      scope: data.scope,
      confidentialityImpact: data.confidentialityImpact,
      integrityImpact: data.integrityImpact,
      availabilityImpact: data.availabilityImpact,
    };
  }

  // 3. Fallback to CVSS v2.0
  if (metrics?.cvssMetricV2 && metrics.cvssMetricV2.length > 0) {
    const primary = metrics.cvssMetricV2.find((m: any) => m.type === 'Primary') || metrics.cvssMetricV2[0];
    const data = primary.cvssData || {};
    const score = data.baseScore || 0;
    let severity: VulnerabilitySeverity = 'medium';
    if (score >= 7.0) severity = 'high';
    else if (score < 4.0) severity = 'low';

    return {
      version: '2.0',
      baseScore: score,
      severity,
      vectorString: data.vectorString || '',
      exploitabilityScore: primary.exploitabilityScore,
      impactScore: primary.impactScore,
      attackVector: data.accessVector,
      attackComplexity: data.accessComplexity,
    };
  }

  // Default fallback
  return {
    version: '3.1',
    baseScore: 5.0,
    severity: 'medium',
    vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
  };
}

/**
 * Maps CWE to OWASP Top 10 Category (2021 edition)
 */
export function mapCweToOwasp(cweId: string): string {
  const cwe = cweId.toUpperCase();

  // A01:2021 - Broken Access Control
  if (
    ['CWE-22', 'CWE-23', 'CWE-352', 'CWE-284', 'CWE-285', 'CWE-639', 'CWE-862', 'CWE-863', 'CWE-200', 'CWE-913'].some(
      c => cwe.includes(c)
    )
  ) {
    return 'A01:2021-Broken Access Control';
  }

  // A02:2021 - Cryptographic Failures
  if (
    ['CWE-327', 'CWE-326', 'CWE-328', 'CWE-330', 'CWE-310', 'CWE-311', 'CWE-312', 'CWE-319', 'CWE-347'].some(c =>
      cwe.includes(c)
    )
  ) {
    return 'A02:2021-Cryptographic Failures';
  }

  // A03:2021 - Injection
  if (
    ['CWE-89', 'CWE-77', 'CWE-78', 'CWE-94', 'CWE-502', 'CWE-917', 'CWE-79', 'CWE-116'].some(c => cwe.includes(c))
  ) {
    return 'A03:2021-Injection';
  }

  // A04:2021 - Insecure Design
  if (['CWE-400', 'CWE-770', 'CWE-209', 'CWE-256'].some(c => cwe.includes(c))) {
    return 'A04:2021-Insecure Design';
  }

  // A05:2021 - Security Misconfiguration
  if (['CWE-16', 'CWE-693', 'CWE-1004', 'CWE-614', 'CWE-548'].some(c => cwe.includes(c))) {
    return 'A05:2021-Security Misconfiguration';
  }

  // A06:2021 - Vulnerable and Outdated Components
  if (['CWE-1104', 'CWE-1395', 'CWE-119', 'CWE-120', 'CWE-125', 'CWE-416', 'CWE-787'].some(c => cwe.includes(c))) {
    return 'A06:2021-Vulnerable and Outdated Components';
  }

  // A07:2021 - Identification and Authentication Failures
  if (
    ['CWE-287', 'CWE-384', 'CWE-288', 'CWE-306', 'CWE-798', 'CWE-640', 'CWE-522', 'CWE-307'].some(c =>
      cwe.includes(c)
    )
  ) {
    return 'A07:2021-Identification and Authentication Failures';
  }

  // A08:2021 - Software and Data Integrity Failures
  if (['CWE-494', 'CWE-565', 'CWE-829', 'CWE-345'].some(c => cwe.includes(c))) {
    return 'A08:2021-Software and Data Integrity Failures';
  }

  // A09:2021 - Security Logging and Monitoring Failures
  if (['CWE-778', 'CWE-117', 'CWE-532'].some(c => cwe.includes(c))) {
    return 'A09:2021-Security Logging and Monitoring Failures';
  }

  // A10:2021 - Server-Side Request Forgery (SSRF)
  if (['CWE-918', 'CWE-611'].some(c => cwe.includes(c))) {
    return 'A10:2021-Server-Side Request Forgery (SSRF)';
  }

  return 'A06:2021-Vulnerable and Outdated Components';
}

/**
 * Extracts affected tech and CPEs from NVD configuration nodes
 */
export function extractCpeInfo(configurations: any[]): { tech: string; vendor: string; product: string; cpeList: string[] } {
  const cpeList: string[] = [];
  let detectedTech = '';
  let detectedVendor = '';
  let detectedProduct = '';

  if (Array.isArray(configurations)) {
    for (const config of configurations) {
      if (Array.isArray(config.nodes)) {
        for (const node of config.nodes) {
          if (Array.isArray(node.cpeMatch)) {
            for (const match of node.cpeMatch) {
              if (match.criteria) {
                cpeList.push(match.criteria);
                // Extract human-friendly software vendor/product from cpe:2.3:a:vendor:product:version:...
                const parts = match.criteria.split(':');
                if (parts.length >= 5 && !detectedTech) {
                  detectedVendor = parts[3].replace(/_/g, ' ').trim();
                  detectedProduct = parts[4].replace(/_/g, ' ').trim();
                  const vendorCap = detectedVendor.charAt(0).toUpperCase() + detectedVendor.slice(1);
                  const productCap = detectedProduct.charAt(0).toUpperCase() + detectedProduct.slice(1);
                  detectedTech = `${vendorCap} ${productCap}`.trim();
                }
              }
            }
          }
        }
      }
    }
  }

  return {
    tech: detectedTech || 'Enterprise Application / Web Service',
    vendor: detectedVendor,
    product: detectedProduct,
    cpeList: cpeList.slice(0, 10),
  };
}

/**
 * Generates a valid Nuclei-compliant YAML template from live NVD metadata.
 * NOTE: NVD templates are saved in reference mode (enabled: false) by default
 * to prevent false positives until verified by an auditor.
 */
export function generateYamlTemplateFromNvd(cveDetail: Omit<NvdCveDetail, 'generatedYamlTemplate'>): YamlTemplate {
  const templateId = cveDetail.cveId.toLowerCase().replace(/[^a-z0-9-]/g, '-');
  const yearMatch = cveDetail.cveId.match(/CVE-(\d{4})-/i);
  const year = yearMatch ? yearMatch[1] : '2024';

  const descSanitized = cveDetail.description.replace(/"/g, "'").replace(/\r?\n/g, ' ').trim();
  const descTruncated = descSanitized.length > 200 ? `${descSanitized.slice(0, 197)}...` : descSanitized;
  const safeName = cveDetail.name.replace(/"/g, "'").replace(/\r?\n/g, ' ').trim();
  const safeTech = cveDetail.affectedTech.replace(/"/g, "'").replace(/\r?\n/g, ' ').trim();

  // Extract a specific technology keyword if identifiable
  const { vendor, product } = extractCpeInfo(cveDetail.cpeConfigurations);
  const techKeyword = (product || vendor || '').trim();
  const hasSpecificTech =
    techKeyword.length >= 3 &&
    !['application', 'service', 'enterprise', 'web service'].includes(techKeyword.toLowerCase());

  // Technology fingerprint matcher: requires actual software signature presence + status 200
  // Never uses generic 200/403/500 status-only matchers that falsely match every website!
  const matchersYaml = hasSpecificTech
    ? `    matchers-condition: and
    matchers:
      - type: word
        part: all
        words:
          - "${techKeyword.toLowerCase().replace(/"/g, '')}"
        case-insensitive: true
      - type: status
        status:
          - 200`
    : `    # NOTE: NVD vulnerability entry imported in reference/advisory mode.
    # Specify targeted path and proof-of-concept word/header matchers before enabling active scans.
    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "X-Signature-Verified-Manual"
      - type: status
        status:
          - 200`;

  const rawYaml = `id: ${templateId}
info:
  name: "${safeName}"
  author: nvd-nist-cve-sync
  severity: ${cveDetail.cvss.severity}
  description: "${descTruncated}"
  reference:
    - https://nvd.nist.gov/vuln/detail/${cveDetail.cveId}
${cveDetail.references.slice(0, 3).map(r => `    - ${r.url}`).join('\n')}
  tags: cve,cve-${year},nvd-synced,cvss-${cveDetail.cvss.baseScore},nvd-advisory${
    hasSpecificTech ? `,tech-${techKeyword.toLowerCase().replace(/[^a-z0-9]/g, '-')}` : ''
  }
  classification:
    cvss-score: ${cveDetail.cvss.baseScore}
    cvss-vector: "${cveDetail.cvss.vectorString}"
    cwe-id: ${cveDetail.cweId}
    owasp-category: "${cveDetail.owaspCategory}"
  remediation: "Apply the vendor security patch or upgrade the affected component (${safeTech})."

requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    headers:
      User-Agent: "DevSecOps-CVE-Probe/2.4 (+https://nvd.nist.gov/vuln/detail/${cveDetail.cveId})"
${matchersYaml}
`;

  return syncTemplateWithYaml({
    id: templateId,
    rawYaml,
    name: safeName,
    severity: cveDetail.cvss.severity,
    description: cveDetail.description,
    tags: ['cve', `cve-${year}`, 'nvd-synced', `cvss-${cveDetail.cvss.baseScore}`, 'nvd-advisory'],
    enabled: false, // CRITICAL: Disabled by default to prevent false-positive contamination of active audits!
    isBuiltin: false,
    author: 'nvd-nist-cve-sync',
  });
}

/**
 * Queries NIST NVD 2.0 API for a specific CVE ID
 */
export async function fetchNvdCveById(cveId: string): Promise<NvdCveDetail | null> {
  const cleanId = cveId.trim().toUpperCase();
  if (!cleanId.startsWith('CVE-')) {
    throw new Error(`Invalid CVE ID format: "${cveId}". Expected format: CVE-YYYY-NNNNN`);
  }

  const url = `${NVD_API_BASE}?cveId=${encodeURIComponent(cleanId)}`;

  const headers: Record<string, string> = {
    'User-Agent': 'DevSecOps-CVE-Auditor/2.4 (NIST-NVD-Client)',
    Accept: 'application/json',
  };

  if (NVD_API_KEY) {
    headers['apiKey'] = NVD_API_KEY;
  }

  const response = await fetch(url, {
    method: 'GET',
    headers,
    signal: AbortSignal.timeout(12000),
  });

  if (!response.ok) {
    if (response.status === 404) return null;
    if (response.status === 403) {
      throw new Error(`NIST NVD API Access Forbidden (HTTP 403). Check if API Key is valid or rate limited.`);
    }
    if (response.status === 429) {
      throw new Error(`NIST NVD API Rate Limit Exceeded (HTTP 429). Please wait a few seconds and try again.`);
    }
    throw new Error(`NIST NVD API Error: HTTP ${response.status} - ${response.statusText}`);
  }

  const json: any = await response.json();

  if (!json.vulnerabilities || json.vulnerabilities.length === 0) {
    return null;
  }

  const cveObj = json.vulnerabilities[0].cve;
  const englishDesc = cveObj.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description available from NIST NVD.';
  const cvss = extractCvssMetrics(cveObj.metrics);

  // Extract primary CWE
  let cweId = 'CWE-Other';
  if (Array.isArray(cveObj.weaknesses) && cveObj.weaknesses.length > 0) {
    const cweDesc = cveObj.weaknesses[0].description?.find((d: any) => d.lang === 'en')?.value;
    if (cweDesc && cweDesc !== 'NVD-CWE-Other' && cweDesc !== 'NVD-CWE-noinfo') {
      cweId = cweDesc;
    }
  }

  const owaspCategory = mapCweToOwasp(cweId);
  const { tech, cpeList } = extractCpeInfo(cveObj.configurations);

  const refs = (cveObj.references || []).map((r: any) => ({
    url: r.url,
    source: r.source,
    tags: r.tags || [],
  }));

  // Generate concise title/name
  let name = `${cveObj.id}: ${tech}`;
  if (cvss.baseScore >= 9.0) {
    name += ' Critical Vulnerability';
  } else if (cvss.baseScore >= 7.0) {
    name += ' High Risk Vulnerability';
  } else {
    name += ' Security Flaw';
  }

  const detailWithoutTpl = {
    cveId: cveObj.id,
    name,
    description: englishDesc,
    publishedDate: cveObj.published ? cveObj.published.split('T')[0] : 'N/A',
    lastModifiedDate: cveObj.lastModified ? cveObj.lastModified.split('T')[0] : 'N/A',
    vulnStatus: cveObj.vulnStatus || 'Analyzed',
    sourceIdentifier: cveObj.sourceIdentifier || 'cve@mitre.org',
    cvss,
    cweId,
    owaspCategory,
    affectedTech: tech,
    cpeConfigurations: cpeList,
    references: refs,
    isKev: isCisaKev(cveObj),
  };

  const generatedYamlTemplate = generateYamlTemplateFromNvd(detailWithoutTpl);

  return {
    ...detailWithoutTpl,
    generatedYamlTemplate,
  };
}

/**
 * Searches NIST NVD 2.0 API with a keyword query
 */
export async function searchNvdCves(keyword: string, limit = 15): Promise<NvdCveDetail[]> {
  const url = `${NVD_API_BASE}?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=${limit}`;

  const headers: Record<string, string> = {
    'User-Agent': 'DevSecOps-CVE-Auditor/2.4 (NIST-NVD-Client)',
    Accept: 'application/json',
  };

  if (NVD_API_KEY) {
    headers['apiKey'] = NVD_API_KEY;
  }

  const response = await fetch(url, {
    method: 'GET',
    headers,
    signal: AbortSignal.timeout(15000),
  });

  if (!response.ok) {
    throw new Error(`NIST NVD Search failed: HTTP ${response.status} (${response.statusText})`);
  }

  const json: any = await response.json();
  const results: NvdCveDetail[] = [];

  if (Array.isArray(json.vulnerabilities)) {
    for (const item of json.vulnerabilities) {
      const cveObj = item.cve;
      const englishDesc = cveObj.descriptions?.find((d: any) => d.lang === 'en')?.value || '';
      const cvss = extractCvssMetrics(cveObj.metrics);

      let cweId = 'CWE-Other';
      if (Array.isArray(cveObj.weaknesses) && cveObj.weaknesses.length > 0) {
        const cweDesc = cveObj.weaknesses[0].description?.find((d: any) => d.lang === 'en')?.value;
        if (cweDesc && cweDesc !== 'NVD-CWE-Other') cweId = cweDesc;
      }

      const owaspCategory = mapCweToOwasp(cweId);
      const { tech, cpeList } = extractCpeInfo(cveObj.configurations);

      const refs = (cveObj.references || []).map((r: any) => ({
        url: r.url,
        source: r.source,
        tags: r.tags || [],
      }));

      const baseInfo = {
        cveId: cveObj.id,
        name: `${cveObj.id}: ${tech}`,
        description: englishDesc,
        publishedDate: cveObj.published ? cveObj.published.split('T')[0] : 'N/A',
        lastModifiedDate: cveObj.lastModified ? cveObj.lastModified.split('T')[0] : 'N/A',
        vulnStatus: cveObj.vulnStatus || 'Analyzed',
        sourceIdentifier: cveObj.sourceIdentifier || '',
        cvss,
        cweId,
        owaspCategory,
        affectedTech: tech,
        cpeConfigurations: cpeList,
        references: refs,
        isKev: isCisaKev(cveObj),
      };

      results.push({
        ...baseInfo,
        generatedYamlTemplate: generateYamlTemplateFromNvd(baseInfo),
      });
    }
  }

  return results;
}

// In-memory cache for API status to prevent rate-limit exhaustion
let cachedNvdStatus: { data: any; timestamp: number } | null = null;
const NVD_STATUS_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes cache

/**
 * Tests NVD API connectivity and verifies the API Key with a lightweight request.
 * Results are cached for 5 minutes unless force is set to true.
 */
export async function testNvdApiKeyStatus(force = false): Promise<{
  connected: boolean;
  apiKeyActive: boolean;
  apiKeyMasked: string;
  rateLimitPer30s: number;
  message: string;
  sampleCve?: string;
  latencyMs: number;
  cached?: boolean;
}> {
  const now = Date.now();
  if (!force && cachedNvdStatus && now - cachedNvdStatus.timestamp < NVD_STATUS_CACHE_TTL_MS) {
    return { ...cachedNvdStatus.data, cached: true };
  }

  const start = Date.now();
  const maskedKey = NVD_API_KEY
    ? `${NVD_API_KEY.slice(0, 8)}...${NVD_API_KEY.slice(-4)}`
    : 'None (Unauthenticated - 5 req/30s)';

  try {
    const sample = await fetchNvdCveById('CVE-2024-4577');
    const latency = Date.now() - start;

    const result = {
      connected: true,
      apiKeyActive: !!NVD_API_KEY,
      apiKeyMasked: maskedKey,
      rateLimitPer30s: NVD_API_KEY ? 50 : 5,
      message: NVD_API_KEY
        ? `NIST NVD API Key Terverifikasi Aktif (${latency}ms) - Limit: 50 requests/30s`
        : `NIST NVD Terhubung dalam mode anonim (Limit: 5 req/30s)`,
      sampleCve: sample ? `${sample.cveId} (CVSS ${sample.cvss.baseScore})` : undefined,
      latencyMs: latency,
      cached: false,
    };

    cachedNvdStatus = { data: result, timestamp: now };
    return result;
  } catch (err: any) {
    const latency = Date.now() - start;
    const result = {
      connected: false,
      apiKeyActive: !!NVD_API_KEY,
      apiKeyMasked: maskedKey,
      rateLimitPer30s: 5,
      message: `Gagal terhubung ke NIST NVD API: ${err.message}`,
      latencyMs: latency,
      cached: false,
    };
    cachedNvdStatus = { data: result, timestamp: now };
    return result;
  }
}
