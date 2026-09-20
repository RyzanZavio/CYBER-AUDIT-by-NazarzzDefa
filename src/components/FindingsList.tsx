import React, { useState } from 'react';
import {
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  FileDown,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Search,
  Filter,
  CheckCircle2,
  Copy,
  Info,
  Server,
  Code2,
  Shield,
  FileText,
  Lock,
  Layers,
  Zap,
  Globe,
} from 'lucide-react';
import { ScanResult, VulnerabilityFinding, VulnerabilitySeverity } from '../types';
import { generatePdfReport } from '../utils/pdfGenerator';
import { ReportLanguage } from '../utils/reportLocales';

interface FindingsListProps {
  scan: ScanResult | null;
  onOpenPdf?: () => void;
}

const SEVERITY_BADGES: Record<
  VulnerabilitySeverity,
  { bg: string; text: string; border: string; label: string }
> = {
  critical: {
    bg: 'bg-rose-500/10 text-rose-400',
    border: 'border-rose-500/30',
    text: 'text-rose-400',
    label: 'CRITICAL',
  },
  high: {
    bg: 'bg-orange-500/10 text-orange-400',
    border: 'border-orange-500/30',
    text: 'text-orange-400',
    label: 'HIGH',
  },
  medium: {
    bg: 'bg-amber-500/10 text-amber-400',
    border: 'border-amber-500/30',
    text: 'text-amber-400',
    label: 'MEDIUM',
  },
  low: {
    bg: 'bg-blue-500/10 text-blue-400',
    border: 'border-blue-500/30',
    text: 'text-blue-400',
    label: 'LOW',
  },
  info: {
    bg: 'bg-slate-500/10 text-slate-400',
    border: 'border-slate-500/30',
    text: 'text-slate-400',
    label: 'INFO',
  },
};

type ServerType = 'nginx' | 'apache' | 'express' | 'cloudflare' | 'litespeed';

const SERVER_CONFIGS: Record<ServerType, { label: string; code: string; filename: string }> = {
  nginx: {
    label: 'Nginx',
    filename: 'nginx.conf / sites-available/default',
    code: `# === OWASP Security Hardening Headers for Nginx ===
server {
    listen 443 ssl http2;
    server_name smkn3kotabekasi.sch.id;

    # 1. Content Security Policy (Mitigate XSS & Data Injections)
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' https:; frame-ancestors 'self';" always;

    # 2. X-Frame-Options (Mitigate Clickjacking)
    add_header X-Frame-Options "SAMEORIGIN" always;

    # 3. X-Content-Type-Options (Prevent MIME-type sniffing)
    add_header X-Content-Type-Options "nosniff" always;

    # 4. Strict-Transport-Security (Force HTTPS & Mitigate SSL Stripping)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # 5. Additional Defense-in-Depth Headers
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

    # Hide Server Version Signature
    server_tokens off;
}`,
  },
  apache: {
    label: 'Apache',
    filename: '.htaccess / httpd.conf',
    code: `# === OWASP Security Hardening Headers for Apache / LiteSpeed ===
<IfModule mod_headers.c>
    # 1. Content Security Policy (CSP)
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' https:; frame-ancestors 'self';"

    # 2. X-Frame-Options (Clickjacking Protection)
    Header always set X-Frame-Options "SAMEORIGIN"

    # 3. X-Content-Type-Options (nosniff)
    Header always set X-Content-Type-Options "nosniff"

    # 4. HTTP Strict Transport Security (HSTS)
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

    # 5. Referrer & Permissions Policy
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
</IfModule>

# Disable Server Signature
ServerSignature Off
ServerTokens Prod`,
  },
  express: {
    label: 'Express.js (Node)',
    filename: 'server.js / server.ts',
    code: `// === OWASP Security Hardening Middleware for Express ===
import helmet from 'helmet';

// Method 1: Using Helmet (Recommended)
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https:"],
        styleSrc: ["'self'", "'unsafe-inline'", "https:"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
    frameguard: { action: 'sameorigin' },
    noSniff: true,
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  })
);

// Method 2: Native Express Headers Middleware
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https:;");
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});`,
  },
  cloudflare: {
    label: 'Cloudflare',
    filename: 'Rules > Transform Rules > Modify Response Header',
    code: `// === Cloudflare HTTP Response Header Transform Rules ===
// Add these Static Response Headers in Cloudflare Dashboard:

1. Header Name:  Content-Security-Policy
   Value:        default-src 'self'; script-src 'self' https:; style-src 'self' 'unsafe-inline' https:;

2. Header Name:  X-Frame-Options
   Value:        SAMEORIGIN

3. Header Name:  X-Content-Type-Options
   Value:        nosniff

4. Header Name:  Strict-Transport-Security
   Value:        max-age=31536000; includeSubDomains; preload

5. Header Name:  Referrer-Policy
   Value:        strict-origin-when-cross-origin`,
  },
  litespeed: {
    label: 'LiteSpeed',
    filename: '.htaccess (cPanel / OpenLiteSpeed)',
    code: `# === LiteSpeed Web Server Security Rules ===
<IfModule mod_headers.c>
  Header always set Content-Security-Policy "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval';"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set X-Content-Type-Options "nosniff"
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>`,
  },
};

export const FindingsList: React.FC<FindingsListProps> = ({ scan }) => {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [activeServerTab, setActiveServerTab] = useState<ServerType>('nginx');
  const [pdfLanguage, setPdfLanguage] = useState<ReportLanguage>('en');

  if (!scan || scan.findings.length === 0) {
    return (
      <div id="no-findings-box" className="p-8 bg-slate-900 border border-slate-800 rounded-2xl text-center space-y-4">
        <div className="w-16 h-16 mx-auto rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
          <ShieldCheck className="w-8 h-8" />
        </div>
        <div className="max-w-md mx-auto space-y-1">
          <h3 className="text-lg font-semibold text-white">No Vulnerabilities Detected</h3>
          <p className="text-sm text-slate-400">
            {scan
              ? `Audit against ${scan.targetUrl} completed cleanly without triggering active security rules.`
              : 'Execute a security audit from the Scanner tab to discover OWASP, Nuclei, and Burp Suite issues.'}
          </p>
        </div>
        {scan && (
          <div className="flex items-center justify-center gap-2">
            <button
              onClick={() => generatePdfReport(scan, pdfLanguage)}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
            >
              <FileDown className="w-4 h-4 text-cyan-400" />
              Download Clean Audit PDF ({pdfLanguage.toUpperCase()})
            </button>
          </div>
        )}
      </div>
    );
  }

  const critCount = scan.findings.filter(f => f.severity === 'critical').length;
  const highCount = scan.findings.filter(f => f.severity === 'high').length;
  const medCount = scan.findings.filter(f => f.severity === 'medium').length;
  const lowCount = scan.findings.filter(f => f.severity === 'low').length;
  const infoCount = scan.findings.filter(f => f.severity === 'info').length;

  const isSecurityHeaderPresent = scan.findings.some(
    f =>
      f.templateId.includes('security-headers') ||
      f.templateId.includes('csp') ||
      f.templateId.includes('frame') ||
      f.templateId.includes('hsts') ||
      f.templateId.includes('sniff')
  );

  const toggleExpand = (id: string) => {
    setExpandedFindings(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const handleCopyText = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(key);
    setTimeout(() => setCopiedId(null), 2200);
  };

  const filteredFindings = scan.findings.filter(f => {
    const matchesSeverity = selectedSeverity === 'all' || f.severity === selectedSeverity;
    const matchesQuery =
      searchQuery === '' ||
      f.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.cweId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.owaspCategory.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.matchedAt.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSeverity && matchesQuery;
  });

  return (
    <div id="findings-audit-section" className="space-y-6">
      {/* Metrics Banner & PDF Export Button */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 p-5 bg-slate-900 border border-slate-800 rounded-2xl shadow-xl">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-semibold text-white">Vulnerability Audit Findings</h2>
            <span className="px-2 py-0.5 text-xs font-mono rounded bg-slate-800 text-slate-300 border border-slate-700">
              {scan.findings.length} Consolidated Issues
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Target: <span className="font-mono text-cyan-300">{scan.targetUrl}</span> · Scan completed in{' '}
            {((scan.durationMs || 1000) / 1000).toFixed(1)}s
          </p>
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          {/* PDF Report Language Selector */}
          <div className="flex items-center bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
            <button
              onClick={() => setPdfLanguage('en')}
              className={`px-2.5 py-1.5 rounded-lg font-medium transition ${
                pdfLanguage === 'en' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
              title="Generate PDF in English"
            >
              EN
            </button>
            <button
              onClick={() => setPdfLanguage('id')}
              className={`px-2.5 py-1.5 rounded-lg font-medium transition ${
                pdfLanguage === 'id' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
              title="Hasilkan PDF dalam Bahasa Indonesia"
            >
              ID
            </button>
          </div>

          <button
            id="export-pdf-report-btn"
            onClick={() => generatePdfReport(scan, pdfLanguage)}
            className="flex-1 md:flex-initial inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl font-medium text-xs bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-950 transition active:scale-95"
          >
            <FileDown className="w-4 h-4" />
            <span>Export Audit PDF ({pdfLanguage.toUpperCase()})</span>
          </button>
        </div>
      </div>

      {/* Security Hardening Quick Recipe Card if Security Headers are detected */}
      {isSecurityHeaderPresent && (
        <div className="bg-slate-900 border border-cyan-800/60 rounded-2xl p-5 shadow-xl space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-700/60 flex items-center justify-center text-cyan-400">
                <Lock className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white">
                  Panduan Pengerasan Server (Security Headers Hardening)
                </h3>
                <p className="text-xs text-slate-400">
                  Salin konfigurasi siap pakai untuk server web guna menyelesaikan catatan keamanan.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800">
              {(['nginx', 'apache', 'express', 'cloudflare', 'litespeed'] as ServerType[]).map(st => (
                <button
                  key={st}
                  onClick={() => setActiveServerTab(st)}
                  className={`px-3 py-1 rounded-lg text-xs font-mono font-medium transition ${
                    activeServerTab === st
                      ? 'bg-cyan-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {SERVER_CONFIGS[st].label}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400 font-mono text-[11px]">
                File Target: <strong className="text-cyan-300">{SERVER_CONFIGS[activeServerTab].filename}</strong>
              </span>
              <button
                onClick={() => handleCopyText(`server-${activeServerTab}`, SERVER_CONFIGS[activeServerTab].code)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 border border-slate-700 transition"
              >
                {copiedId === `server-${activeServerTab}` ? (
                  <>
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400 font-mono">Tersalin!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-slate-400" />
                    <span className="font-mono">Salin Konfigurasi</span>
                  </>
                )}
              </button>
            </div>

            <pre className="p-3.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-300 font-mono overflow-x-auto leading-relaxed max-h-56 scrollbar-thin scrollbar-thumb-slate-800">
              <code>{SERVER_CONFIGS[activeServerTab].code}</code>
            </pre>
          </div>
        </div>
      )}

      {/* Severity Filter Counters */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2">
        <button
          onClick={() => setSelectedSeverity('all')}
          className={`p-3 rounded-xl border text-left transition flex flex-col justify-between ${
            selectedSeverity === 'all'
              ? 'bg-slate-800 border-cyan-500 shadow-md'
              : 'bg-slate-900 border-slate-800 hover:bg-slate-800/50'
          }`}
        >
          <span className="text-xs text-slate-400">All Findings</span>
          <span className="text-xl font-bold font-mono text-white mt-1">{scan.findings.length}</span>
        </button>

        <button
          onClick={() => setSelectedSeverity('critical')}
          className={`p-3 rounded-xl border text-left transition flex flex-col justify-between ${
            selectedSeverity === 'critical'
              ? 'bg-rose-950/40 border-rose-500 shadow-md'
              : 'bg-slate-900 border-slate-800 hover:bg-slate-800/50'
          }`}
        >
          <span className="text-xs font-medium text-rose-400">Critical</span>
          <span className="text-xl font-bold font-mono text-rose-400 mt-1">{critCount}</span>
        </button>

        <button
          onClick={() => setSelectedSeverity('high')}
          className={`p-3 rounded-xl border text-left transition flex flex-col justify-between ${
            selectedSeverity === 'high'
              ? 'bg-orange-950/40 border-orange-500 shadow-md'
              : 'bg-slate-900 border-slate-800 hover:bg-slate-800/50'
          }`}
        >
          <span className="text-xs font-medium text-orange-400">High</span>
          <span className="text-xl font-bold font-mono text-orange-400 mt-1">{highCount}</span>
        </button>

        <button
          onClick={() => setSelectedSeverity('medium')}
          className={`p-3 rounded-xl border text-left transition flex flex-col justify-between ${
            selectedSeverity === 'medium'
              ? 'bg-amber-950/40 border-amber-500 shadow-md'
              : 'bg-slate-900 border-slate-800 hover:bg-slate-800/50'
          }`}
        >
          <span className="text-xs font-medium text-amber-400">Medium</span>
          <span className="text-xl font-bold font-mono text-amber-400 mt-1">{medCount}</span>
        </button>

        <button
          onClick={() => setSelectedSeverity('low')}
          className={`p-3 rounded-xl border text-left transition flex flex-col justify-between ${
            selectedSeverity === 'low'
              ? 'bg-blue-950/40 border-blue-500 shadow-md'
              : 'bg-slate-900 border-slate-800 hover:bg-slate-800/50'
          }`}
        >
          <span className="text-xs font-medium text-blue-400">Low</span>
          <span className="text-xl font-bold font-mono text-blue-400 mt-1">{lowCount}</span>
        </button>

        <button
          onClick={() => setSelectedSeverity('info')}
          className={`p-3 rounded-xl border text-left transition flex flex-col justify-between ${
            selectedSeverity === 'info'
              ? 'bg-slate-800 border-slate-600 shadow-md'
              : 'bg-slate-900 border-slate-800 hover:bg-slate-800/50'
          }`}
        >
          <span className="text-xs font-medium text-slate-400">Info</span>
          <span className="text-xl font-bold font-mono text-slate-400 mt-1">{infoCount}</span>
        </button>
      </div>

      {/* Search Input Bar */}
      <div className="relative">
        <Search className="w-4 h-4 absolute left-3.5 top-3.5 text-slate-500" />
        <input
          id="search-findings-input"
          type="text"
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          placeholder="Filter by vulnerability name, CWE ID, OWASP category, or URL..."
          className="w-full pl-10 pr-4 py-2.5 bg-slate-900 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
        />
      </div>

      {/* Findings List Items */}
      <div className="space-y-3">
        {filteredFindings.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-xs border border-slate-800 rounded-xl bg-slate-900/40">
            No vulnerabilities match current filter criteria.
          </div>
        ) : (
          filteredFindings.map((finding, idx) => {
            const isExpanded = expandedFindings[finding.id] ?? (idx === 0);
            const badge = SEVERITY_BADGES[finding.severity] || SEVERITY_BADGES.info;

            return (
              <div
                key={finding.id}
                id={`finding-card-${finding.id}`}
                className="bg-slate-900 border border-slate-800 hover:border-slate-700/80 rounded-xl overflow-hidden transition-all shadow-md"
              >
                {/* Header Row */}
                <div
                  onClick={() => toggleExpand(finding.id)}
                  className="p-4 cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 select-none"
                >
                  <div className="flex items-start sm:items-center gap-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-bold font-mono border ${badge.bg} ${badge.border}`}
                    >
                      {badge.label}
                    </span>
                    <div>
                      <div className="flex items-center gap-2">
                        <h4 className="text-sm font-semibold text-white hover:text-cyan-300 transition">
                          {finding.name}
                        </h4>
                        {finding.findingType === 'aggregated' && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-slate-800 text-cyan-400 border border-cyan-800/50 flex items-center gap-1">
                            <Layers className="w-3 h-3" /> Aggregated
                          </span>
                        )}
                      </div>
                      <div className="flex flex-wrap items-center gap-2 mt-1 text-[11px] text-slate-400">
                        <span className="font-mono text-cyan-400/90">{finding.cweId}</span>
                        <span>•</span>
                        <span className="text-slate-400">{finding.owaspCategory}</span>
                        <span>•</span>
                        <span className="font-mono text-slate-300">CVSS v3.1 {finding.cvssScore.toFixed(1)}</span>
                        {finding.cvssVector && (
                          <span className="font-mono text-[10px] text-slate-500 hidden lg:inline">
                            [{finding.cvssVector}]
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 self-end sm:self-center">
                    <span className="text-xs font-mono text-slate-500 hidden md:inline truncate max-w-xs">
                      {finding.matchedAt}
                    </span>
                    <button className="text-slate-400 hover:text-white p-1">
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Expanded Details Body */}
                {isExpanded && (
                  <div className="px-4 pb-4 pt-1 border-t border-slate-800/80 space-y-4 text-xs">
                    {/* Description */}
                    <div>
                      <h5 className="font-semibold text-slate-300 mb-1">Description &amp; Impact</h5>
                      <p className="text-slate-400 leading-relaxed">{finding.description}</p>
                    </div>

                    {/* Contextual Risk Escalation Note if present */}
                    {finding.contextualNotes && (
                      <div className="p-3 bg-amber-950/30 border border-amber-500/30 rounded-lg text-amber-300/90 text-xs flex items-start gap-2">
                        <Zap className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                        <div>
                          <strong className="text-amber-300">Contextual Severity Elevation:</strong>{' '}
                          {finding.contextualNotes}
                        </div>
                      </div>
                    )}

                    {/* Aggregated Sub-checks list */}
                    {finding.subFindings && finding.subFindings.length > 0 && (
                      <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-2">
                        <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-300 border-b border-slate-800 pb-1.5">
                          <Layers className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Consolidated Audit Sub-Checks ({finding.subFindings.length} Items)</span>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-1">
                          {finding.subFindings.map(sub => (
                            <div key={sub.id} className="p-2 bg-slate-900/80 rounded border border-slate-800 text-[11px] space-y-1">
                              <div className="font-semibold text-cyan-300 flex items-center justify-between">
                                <span>{sub.name}</span>
                                <span className="text-[10px] font-mono uppercase px-1 rounded bg-slate-800 text-slate-400">
                                  {sub.severity}
                                </span>
                              </div>
                              <p className="text-slate-400 text-[10px] font-mono">{sub.evidence}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Evidence & Technical Proof */}
                    <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-[11px] space-y-2">
                      <div className="flex items-center justify-between text-slate-400 border-b border-slate-800/80 pb-1.5">
                        <span className="font-semibold text-cyan-400">Probe Evidence &amp; Request Details</span>
                        <span className="text-[10px] text-slate-500">{finding.matchedAt}</span>
                      </div>
                      <div className="text-slate-300">
                        <span className="text-slate-500">Method:</span>{' '}
                        <span className="text-emerald-400">{finding.request?.method || 'GET'}</span>
                        <span className="ml-3 text-slate-500">Target:</span>{' '}
                        <span className="text-cyan-300">{finding.url}</span>
                      </div>
                      <div className="text-amber-300/90 whitespace-pre-line">
                        <span className="text-slate-500">Match Evidence:</span> {finding.evidence}
                      </div>
                      {finding.response?.statusCode ? (
                        <div className="text-slate-400 text-[10px]">
                          HTTP Response Status: <span className="text-white font-bold">{finding.response.statusCode} OK</span>{' '}
                          | Response Latency: <span className="text-cyan-300 font-bold">{finding.response.responseTimeMs || 1504}ms</span>
                        </div>
                      ) : null}
                    </div>

                    {/* Remediation Guide */}
                    <div className="bg-cyan-950/20 border border-cyan-900/40 p-3.5 rounded-lg space-y-2.5">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-1.5 text-cyan-300 font-semibold">
                          <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                          <span>Rekomendasi Perbaikan &amp; Konfigurasi Server</span>
                        </div>
                        <button
                          onClick={() => handleCopyText(`rem-${finding.id}`, finding.remediation)}
                          className="text-[10px] flex items-center gap-1 text-slate-400 hover:text-white"
                        >
                          {copiedId === `rem-${finding.id}` ? (
                            <span className="text-emerald-400">Tersalin!</span>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>Salin Panduan</span>
                            </>
                          )}
                        </button>
                      </div>
                      <div className="text-slate-300 whitespace-pre-line leading-relaxed font-sans">
                        {finding.remediation}
                      </div>
                    </div>

                    {/* Reference links */}
                    {finding.references && finding.references.length > 0 && (
                      <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px] text-slate-400">
                        <span className="font-semibold text-slate-400">Referensi Keamanan:</span>
                        {finding.references.map((ref, rIdx) => (
                          <a
                            key={rIdx}
                            href={ref}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-cyan-400 hover:underline"
                          >
                            <span>{ref.includes('owasp.org') ? 'OWASP Guide' : ref.includes('mozilla.org') ? 'MDN Docs' : 'Reference'}</span>
                            <ExternalLink className="w-2.5 h-2.5" />
                          </a>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
