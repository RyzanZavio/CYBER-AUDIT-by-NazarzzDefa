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
} from 'lucide-react';
import { ScanResult, VulnerabilityFinding, VulnerabilitySeverity } from '../types';
import { generatePdfReport } from '../utils/pdfGenerator';

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

export const FindingsList: React.FC<FindingsListProps> = ({ scan }) => {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});
  const [copiedRemediationId, setCopiedRemediationId] = useState<string | null>(null);

  if (!scan || scan.findings.length === 0) {
    return (
      <div id="no-findings-box" className="p-8 bg-slate-900/60 border border-slate-800 rounded-2xl text-center space-y-4">
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
          <button
            onClick={() => generatePdfReport(scan)}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
          >
            <FileDown className="w-4 h-4 text-cyan-400" />
            Download Clean Audit PDF
          </button>
        )}
      </div>
    );
  }

  const critCount = scan.findings.filter(f => f.severity === 'critical').length;
  const highCount = scan.findings.filter(f => f.severity === 'high').length;
  const medCount = scan.findings.filter(f => f.severity === 'medium').length;
  const lowCount = scan.findings.filter(f => f.severity === 'low').length;
  const infoCount = scan.findings.filter(f => f.severity === 'info').length;

  const toggleExpand = (id: string) => {
    setExpandedFindings(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const handleCopyRemediation = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedRemediationId(id);
    setTimeout(() => setCopiedRemediationId(null), 2000);
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
              {scan.findings.length} Total Issues
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Target: <span className="font-mono text-cyan-300">{scan.targetUrl}</span> · Scan completed in{' '}
            {((scan.durationMs || 1000) / 1000).toFixed(1)}s
          </p>
        </div>

        <button
          id="export-pdf-report-btn"
          onClick={() => generatePdfReport(scan)}
          className="w-full md:w-auto inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl font-medium text-xs bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-950 transition active:scale-95"
        >
          <FileDown className="w-4 h-4" />
          <span>Export Audit Report (PDF)</span>
        </button>
      </div>

      {/* Severity Filter Counters */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2">
        <button
          onClick={() => setSelectedSeverity('all')}
          className={`p-3 rounded-xl border text-left transition flex flex-col justify-between ${
            selectedSeverity === 'all'
              ? 'bg-slate-800 border-cyan-500 shadow-md'
              : 'bg-slate-900/60 border-slate-800 hover:bg-slate-800/50'
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
              : 'bg-slate-900/60 border-slate-800 hover:bg-slate-800/50'
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
              : 'bg-slate-900/60 border-slate-800 hover:bg-slate-800/50'
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
              : 'bg-slate-900/60 border-slate-800 hover:bg-slate-800/50'
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
              : 'bg-slate-900/60 border-slate-800 hover:bg-slate-800/50'
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
              : 'bg-slate-900/60 border-slate-800 hover:bg-slate-800/50'
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
                      <h4 className="text-sm font-semibold text-white hover:text-cyan-300 transition">
                        {finding.name}
                      </h4>
                      <div className="flex flex-wrap items-center gap-2 mt-1 text-[11px] text-slate-400">
                        <span className="font-mono text-cyan-400/90">{finding.cweId}</span>
                        <span>•</span>
                        <span className="text-slate-400">{finding.owaspCategory}</span>
                        <span>•</span>
                        <span className="font-mono text-slate-300">CVSS {finding.cvssScore.toFixed(1)}</span>
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
                      <h5 className="font-semibold text-slate-300 mb-1">Description & Impact</h5>
                      <p className="text-slate-400 leading-relaxed">{finding.description}</p>
                    </div>

                    {/* Evidence & Technical Proof */}
                    <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-[11px] space-y-2">
                      <div className="flex items-center justify-between text-slate-400 border-b border-slate-800/80 pb-1.5">
                        <span className="font-semibold text-cyan-400">Probe Evidence & Request Details</span>
                        <span className="text-[10px] text-slate-500">{finding.matchedAt}</span>
                      </div>
                      <div className="text-slate-300">
                        <span className="text-slate-500">Method:</span>{' '}
                        <span className="text-emerald-400">{finding.request?.method || 'GET'}</span>
                        <span className="ml-3 text-slate-500">Target:</span>{' '}
                        <span className="text-cyan-300">{finding.url}</span>
                      </div>
                      <div className="text-amber-300/90">
                        <span className="text-slate-500">Match Evidence:</span> {finding.evidence}
                      </div>
                      {finding.response?.statusCode ? (
                        <div className="text-slate-400 text-[10px]">
                          HTTP Response Status: <span className="text-white">{finding.response.statusCode}</span>{' '}
                          | Latency: {finding.response.responseTimeMs || 45}ms
                        </div>
                      ) : null}
                    </div>

                    {/* Remediation Guide */}
                    <div className="bg-cyan-950/20 border border-cyan-900/40 p-3 rounded-lg space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-1.5 text-cyan-300 font-semibold">
                          <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                          <span>Remediation Recommendation</span>
                        </div>
                        <button
                          onClick={() => handleCopyRemediation(finding.id, finding.remediation)}
                          className="text-[10px] flex items-center gap-1 text-slate-400 hover:text-white"
                        >
                          {copiedRemediationId === finding.id ? (
                            <span className="text-emerald-400">Copied!</span>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>Copy Fix</span>
                            </>
                          )}
                        </button>
                      </div>
                      <p className="text-slate-300 leading-relaxed">{finding.remediation}</p>
                    </div>

                    {/* Reference links */}
                    {finding.references && finding.references.length > 0 && (
                      <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px] text-slate-400">
                        <span className="font-semibold text-slate-400">References:</span>
                        {finding.references.map((ref, rIdx) => (
                          <a
                            key={rIdx}
                            href={ref}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-cyan-400 hover:underline"
                          >
                            <span>Link</span>
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
