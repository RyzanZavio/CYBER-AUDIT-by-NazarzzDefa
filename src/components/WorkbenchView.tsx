import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  ScanResult,
  VulnerabilityFinding,
  ScanLog,
  YamlTemplate,
  ProxyConfig,
} from '../types';
import {
  Terminal,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Globe,
  Lock,
  Search,
  Copy,
  Check,
  ChevronRight,
  ChevronDown,
  Folder,
  FileCode,
  AlertOctagon,
  AlertTriangle,
  Info,
  Layers,
  FileDown,
  Play,
  Square,
  Sliders,
  Maximize2,
  ExternalLink,
  Code,
  ArrowRight,
  Sparkles,
} from 'lucide-react';
import { generatePdfReport } from '../utils/pdfGenerator';

interface WorkbenchViewProps {
  scan: ScanResult | null;
  logs: ScanLog[];
  isScanning: boolean;
  templates: YamlTemplate[];
  proxyConfig: ProxyConfig;
  onStartScan: (targetUrl: string, selectedTemplateIds: string[], timeoutMs: number) => void;
  onQuickRun?: (targetUrl: string, preset: 'quick' | 'full' | 'high-only') => void;
  onClearLogs: () => void;
}

const SEVERITY_COLORS: Record<string, { bg: string; text: string; border: string; label: string }> = {
  critical: { bg: 'bg-red-950/80', text: 'text-red-400', border: 'border-red-800', label: 'CRIT' },
  high: { bg: 'bg-orange-950/80', text: 'text-orange-400', border: 'border-orange-800', label: 'HIGH' },
  medium: { bg: 'bg-amber-950/80', text: 'text-amber-400', border: 'border-amber-800', label: 'MED' },
  low: { bg: 'bg-cyan-950/80', text: 'text-cyan-400', border: 'border-cyan-800', label: 'LOW' },
  info: { bg: 'bg-zinc-900', text: 'text-zinc-400', border: 'border-zinc-700', label: 'INFO' },
};

export const WorkbenchView: React.FC<WorkbenchViewProps> = ({
  scan,
  logs,
  isScanning,
  templates,
  proxyConfig,
  onStartScan,
  onQuickRun,
  onClearLogs,
}) => {
  // Input Target State
  const [targetInput, setTargetInput] = useState('https://smkn3kotabekasi.sch.id');
  const [scanPreset, setScanPreset] = useState<'quick' | 'deep' | 'passive'>('quick');
  const [concurrency, setConcurrency] = useState(10);
  const [timeoutMs, setTimeoutMs] = useState(5000);

  // Workbench selection state
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [selectedTreePath, setSelectedTreePath] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [tableSearch, setTableSearch] = useState<string>('');
  const [inspectorTab, setInspectorTab] = useState<'request' | 'response' | 'remediation' | 'raw'>('response');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isLogDrawerOpen, setIsLogDrawerOpen] = useState(true);
  const [logFilter, setLogFilter] = useState<'all' | 'alert' | 'probe'>('all');
  const [expandedNodes, setExpandedNodes] = useState<Record<string, boolean>>({ root: true });

  const terminalEndRef = useRef<HTMLDivElement>(null);
  const findingsList = scan?.findings || [];

  // Default selection when findings arrive
  useEffect(() => {
    if (findingsList.length > 0 && !selectedFindingId) {
      setSelectedFindingId(findingsList[0].id);
    }
  }, [findingsList, selectedFindingId]);

  // Keyboard navigation: j/k, Tab, Ctrl+Enter
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ctrl+Enter or Cmd+Enter to run scan
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        handleTriggerScan();
        return;
      }

      // Ignore when user is typing in an input
      if (
        document.activeElement?.tagName === 'INPUT' ||
        document.activeElement?.tagName === 'TEXTAREA'
      ) {
        return;
      }

      if (e.key === 'j' || e.key === 'ArrowDown') {
        e.preventDefault();
        navigateFinding(1);
      } else if (e.key === 'k' || e.key === 'ArrowUp') {
        e.preventDefault();
        navigateFinding(-1);
      } else if (e.key === 'Tab') {
        e.preventDefault();
        setInspectorTab(prev => {
          if (prev === 'request') return 'response';
          if (prev === 'response') return 'remediation';
          if (prev === 'remediation') return 'raw';
          return 'request';
        });
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [findingsList, selectedFindingId, targetInput, isScanning]);

  // Scroll logs to bottom
  useEffect(() => {
    if (isLogDrawerOpen) {
      terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, isLogDrawerOpen]);

  const handleCopy = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const handleTriggerScan = () => {
    if (isScanning || !targetInput.trim()) return;
    let url = targetInput.trim();
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = `https://${url}`;
      setTargetInput(url);
    }

    const enabledTemplateIds = templates.filter(t => t.enabled).map(t => t.id);
    onStartScan(url, enabledTemplateIds, timeoutMs);
  };

  const navigateFinding = (direction: number) => {
    if (!filteredFindings.length) return;
    const currentIndex = filteredFindings.findIndex(f => f.id === selectedFindingId);
    let nextIndex = currentIndex + direction;
    if (nextIndex < 0) nextIndex = filteredFindings.length - 1;
    if (nextIndex >= filteredFindings.length) nextIndex = 0;
    setSelectedFindingId(filteredFindings[nextIndex].id);
  };

  // Filtered findings based on tree, search, severity
  const filteredFindings = useMemo(() => {
    return findingsList.filter(f => {
      if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
      if (selectedTreePath && !f.matchedAt.includes(selectedTreePath)) return false;
      if (tableSearch.trim()) {
        const q = tableSearch.toLowerCase();
        return (
          f.name.toLowerCase().includes(q) ||
          f.cweId.toLowerCase().includes(q) ||
          f.matchedAt.toLowerCase().includes(q) ||
          f.description.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [findingsList, severityFilter, selectedTreePath, tableSearch]);

  const currentFinding = useMemo(() => {
    return findingsList.find(f => f.id === selectedFindingId) || filteredFindings[0] || null;
  }, [findingsList, selectedFindingId, filteredFindings]);

  // Construct Target Scope Tree Nodes
  const treeNodes = useMemo(() => {
    const rootHost = scan?.targetUrl
      ? new URL(scan.targetUrl).hostname
      : targetInput
      ? targetInput.replace(/^https?:\/\//, '').split('/')[0]
      : 'target.com';

    const endpoints = [
      { path: '/', label: '/ (Root Page)', count: findingsList.filter(f => f.matchedAt.includes('/')).length, sev: 'low' },
      { path: '/.env', label: '/.env (Secret Leak)', count: findingsList.filter(f => f.matchedAt.includes('.env')).length, sev: 'critical' },
      { path: '/.git', label: '/.git/config (Source Leak)', count: findingsList.filter(f => f.matchedAt.includes('.git')).length, sev: 'high' },
      { path: '/actuator', label: '/actuator/env (Spring)', count: findingsList.filter(f => f.matchedAt.includes('actuator')).length, sev: 'high' },
      { path: '/wp-config', label: '/wp-config.php.bak', count: findingsList.filter(f => f.matchedAt.includes('wp-config')).length, sev: 'critical' },
      { path: '/headers', label: 'HTTP Security Headers', count: findingsList.filter(f => f.templateId.includes('security-headers') || f.cweId === 'CWE-693').length, sev: 'medium' },
      { path: '/cors', label: 'CORS & Origin Policy', count: findingsList.filter(f => f.templateId.includes('cors')).length, sev: 'medium' },
      { path: '/subdomain', label: 'Subdomain Takeover CNAME', count: findingsList.filter(f => f.templateId.includes('takeover')).length, sev: 'high' },
    ];

    return { rootHost, endpoints };
  }, [scan, targetInput, findingsList]);

  // Generate Raw HTTP Request text
  const rawRequestText = useMemo(() => {
    if (!currentFinding) return 'GET / HTTP/1.1\nHost: target.com\nUser-Agent: CyberAudit-Recon/2.4\nAccept: */*';
    const req = currentFinding.request;
    const urlObj = new URL(currentFinding.url || 'https://example.com');
    const path = urlObj.pathname + urlObj.search;
    const host = urlObj.host;

    let headersStr = `Host: ${host}\nUser-Agent: DevSecOps-Auditor/2.4 (Security Research Engine)\nAccept: */*\nAccept-Language: en-US,en;q=0.9\nConnection: close`;
    if (req?.headers) {
      headersStr = Object.entries(req.headers)
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n');
    }

    return `${req?.method || 'GET'} ${path || '/'} HTTP/1.1\n${headersStr}\n\n${req?.body || ''}`.trim();
  }, [currentFinding]);

  // Generate Raw HTTP Response text
  const rawResponseText = useMemo(() => {
    if (!currentFinding) return 'HTTP/1.1 200 OK\nServer: nginx/1.24.0\nContent-Type: text/plain\n\nNo active finding selected.';
    const res = currentFinding.response;
    const status = res?.statusCode || (currentFinding.severity === 'critical' ? 200 : 200);
    const statusText = status === 200 ? 'OK' : status === 403 ? 'Forbidden' : status === 404 ? 'Not Found' : 'OK';

    let headersStr = `Server: nginx/1.24.0 (Ubuntu)\nDate: ${new Date().toUTCString()}\nContent-Type: text/plain; charset=utf-8\nContent-Length: 142\nConnection: close`;
    if (res?.headers) {
      headersStr = Object.entries(res.headers)
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n');
    }

    const body = res?.bodySnippet || currentFinding.evidence || 'No response body snippet captured.';
    return `HTTP/1.1 ${status} ${statusText}\n${headersStr}\n\n${body}`;
  }, [currentFinding]);

  // cURL PoC Command
  const curlPoc = useMemo(() => {
    if (!currentFinding) return 'curl -s -i "https://target.com"';
    return `curl -s -i -k -X ${currentFinding.request?.method || 'GET'} "${currentFinding.url}" \\
  -H "User-Agent: CyberAudit/2.4" \\
  -H "Accept: */*"`;
  }, [currentFinding]);

  const filteredLogs = useMemo(() => {
    return logs.filter(l => {
      if (logFilter === 'alert') return l.level === 'crit' || l.level === 'warn';
      if (logFilter === 'probe') return l.message.includes('PROBE') || l.message.includes('GET') || l.message.includes('POST');
      return true;
    });
  }, [logs, logFilter]);

  return (
    <div className="flex flex-col space-y-2 font-mono text-slate-200">
      {/* 1. TOP INDUSTRIAL COMMAND / QUICK LAUNCH BAR */}
      <div className="bg-[#090a0f] border border-[#27272a] rounded-none p-2.5 flex flex-wrap items-center justify-between gap-2 text-xs">
        <div className="flex flex-1 items-center gap-2 min-w-[320px]">
          <div className="flex items-center gap-1.5 px-2 py-1 bg-[#12141a] border border-[#27272a] text-[#a1a1aa] font-bold">
            <Globe className="w-3.5 h-3.5 text-cyan-400" />
            <span>SCOPE:</span>
          </div>
          <input
            type="text"
            value={targetInput}
            onChange={e => setTargetInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleTriggerScan()}
            placeholder="https://target.com or 192.168.1.1"
            className="flex-1 bg-[#050507] border border-[#27272a] focus:border-cyan-500 px-3 py-1.5 text-xs text-white font-mono outline-none"
          />
        </div>

        {/* Scan Controls */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Preset selector */}
          <div className="flex items-center bg-[#050507] border border-[#27272a]">
            <button
              type="button"
              onClick={() => setScanPreset('quick')}
              className={`px-2 py-1 text-[11px] font-bold transition ${
                scanPreset === 'quick' ? 'bg-cyan-600 text-white' : 'text-[#71717a] hover:text-white'
              }`}
            >
              QUICK (ZAP)
            </button>
            <button
              type="button"
              onClick={() => setScanPreset('deep')}
              className={`px-2 py-1 text-[11px] font-bold transition ${
                scanPreset === 'deep' ? 'bg-cyan-600 text-white' : 'text-[#71717a] hover:text-white'
              }`}
            >
              DEEP (NUCLEI)
            </button>
            <button
              type="button"
              onClick={() => setScanPreset('passive')}
              className={`px-2 py-1 text-[11px] font-bold transition ${
                scanPreset === 'passive' ? 'bg-cyan-600 text-white' : 'text-[#71717a] hover:text-white'
              }`}
            >
              PASSIVE (BURP)
            </button>
          </div>

          {/* Proxy status tag */}
          <div className="hidden sm:flex items-center gap-1 px-2 py-1 bg-[#12141a] border border-[#27272a] text-[11px]">
            <span className={`w-2 h-2 ${proxyConfig.enabled ? 'bg-emerald-400 animate-pulse' : 'bg-[#52525b]'}`} />
            <span className="text-[#a1a1aa]">{proxyConfig.enabled ? 'BURP:8080' : 'DIRECT'}</span>
          </div>

          {/* Scan Action Button with Ctrl+Enter badge */}
          <button
            type="button"
            onClick={handleTriggerScan}
            disabled={isScanning}
            className={`px-4 py-1.5 font-bold flex items-center gap-2 text-xs border transition ${
              isScanning
                ? 'bg-red-950/80 text-red-300 border-red-800 animate-pulse cursor-wait'
                : 'bg-cyan-600 hover:bg-cyan-500 text-white border-cyan-500 active:translate-y-px shadow-sm'
            }`}
          >
            {isScanning ? (
              <>
                <Square className="w-3.5 h-3.5 fill-current animate-spin" />
                <span>SCANNING...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>EXECUTE AUDIT</span>
                <span className="text-[10px] opacity-70 border border-cyan-400/40 px-1 py-0.2 ml-0.5">
                  Ctrl+↵
                </span>
              </>
            )}
          </button>

          {scan && (
            <button
              type="button"
              onClick={() => generatePdfReport(scan)}
              className="px-2.5 py-1.5 bg-[#12141a] hover:bg-[#1f2430] border border-[#27272a] text-[#a1a1aa] hover:text-white text-xs flex items-center gap-1"
              title="Export Clean Security Audit PDF"
            >
              <FileDown className="w-3.5 h-3.5 text-cyan-400" />
              <span className="hidden md:inline">PDF REPORT</span>
            </button>
          )}
        </div>
      </div>

      {/* 2. THREE-PANE MAIN WORKBENCH SPLIT-VIEW (BURP / NUCLEI WORKBENCH) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-2 min-h-[580px]">
        {/* PANE 1: TARGET SCOPE & PROBE HIERARCHY TREE (Col-span 3) */}
        <div className="lg:col-span-3 bg-[#090a0f] border border-[#27272a] p-2 flex flex-col space-y-2">
          <div className="flex items-center justify-between pb-1.5 border-b border-[#27272a] text-[11px] font-bold text-[#a1a1aa]">
            <div className="flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-cyan-400" />
              <span>TARGET RECON TREE</span>
            </div>
            <span className="text-[10px] text-[#71717a] font-normal">{findingsList.length} Findings</span>
          </div>

          {/* Root Host Branch */}
          <div className="flex-1 overflow-y-auto space-y-0.5 text-xs select-none scrollbar-thin scrollbar-thumb-zinc-800">
            <div
              onClick={() => setSelectedTreePath(null)}
              className={`flex items-center justify-between px-2 py-1.5 border cursor-pointer ${
                selectedTreePath === null
                  ? 'bg-[#18181b] border-cyan-500/80 text-cyan-300 font-bold'
                  : 'border-transparent text-[#d4d4d8] hover:bg-[#12141a]'
              }`}
            >
              <div className="flex items-center gap-1.5 truncate">
                <Globe className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span className="truncate">{treeNodes.rootHost}</span>
              </div>
              <span className="text-[10px] px-1 py-0.2 bg-[#27272a] text-[#a1a1aa]">ALL</span>
            </div>

            {/* Sub-endpoints with badge */}
            <div className="pl-3 border-l border-[#27272a] ml-2 space-y-0.5 mt-1">
              {treeNodes.endpoints.map(ep => {
                const isSelected = selectedTreePath === ep.path;
                const badge = SEVERITY_COLORS[ep.sev] || SEVERITY_COLORS.info;

                return (
                  <div
                    key={ep.path}
                    onClick={() => setSelectedTreePath(isSelected ? null : ep.path)}
                    className={`flex items-center justify-between px-1.5 py-1 text-[11px] cursor-pointer border ${
                      isSelected
                        ? 'bg-[#18181b] border-cyan-500/80 text-white font-bold'
                        : 'border-transparent text-[#a1a1aa] hover:text-white hover:bg-[#12141a]'
                    }`}
                  >
                    <div className="flex items-center gap-1.5 truncate">
                      <FileCode className="w-3 h-3 text-[#71717a] shrink-0" />
                      <span className="truncate">{ep.label}</span>
                    </div>
                    {ep.count > 0 && (
                      <span
                        className={`text-[9px] font-bold px-1 rounded-none border ${badge.bg} ${badge.text} ${badge.border}`}
                      >
                        {ep.count}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Quick Stats Banner */}
          <div className="p-2 bg-[#050507] border border-[#27272a] text-[10px] text-[#71717a] space-y-1">
            <div className="flex justify-between">
              <span>SCAN DURATION:</span>
              <span className="text-white font-bold">{((scan?.durationMs || 1000) / 1000).toFixed(2)}s</span>
            </div>
            <div className="flex justify-between">
              <span>REQUESTS SENT:</span>
              <span className="text-white font-bold">{scan?.requestsSent || templates.length * 2}</span>
            </div>
            <div className="flex justify-between">
              <span>CVSS MAX:</span>
              <span className="text-red-400 font-bold">
                {findingsList.length > 0 ? Math.max(...findingsList.map(f => f.cvssScore)).toFixed(1) : '0.0'}
              </span>
            </div>
          </div>
        </div>

        {/* PANE 2: HIGH-DENSITY FINDINGS MATRIX TABLE (Col-span 5) */}
        <div className="lg:col-span-5 bg-[#090a0f] border border-[#27272a] p-2 flex flex-col space-y-2">
          {/* Table Header Controls */}
          <div className="flex items-center justify-between gap-2 pb-1 border-b border-[#27272a]">
            <div className="flex items-center gap-1 text-[11px]">
              <span className="font-bold text-[#a1a1aa]">FINDINGS MATRIX</span>
              <span className="text-[10px] text-[#71717a]">({filteredFindings.length})</span>
            </div>

            {/* Severity Quick Filters */}
            <div className="flex items-center gap-1 text-[10px]">
              {['all', 'critical', 'high', 'medium'].map(sev => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-1.5 py-0.5 uppercase border ${
                    severityFilter === sev
                      ? 'bg-cyan-600 border-cyan-500 text-white font-bold'
                      : 'bg-[#050507] border-[#27272a] text-[#71717a] hover:text-white'
                  }`}
                >
                  {sev === 'all' ? 'ALL' : sev.slice(0, 4)}
                </button>
              ))}
            </div>
          </div>

          {/* Quick Search */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2 top-2 text-[#71717a]" />
            <input
              type="text"
              value={tableSearch}
              onChange={e => setTableSearch(e.target.value)}
              placeholder="Filter findings by CWE, Name, Path..."
              className="w-full bg-[#050507] border border-[#27272a] pl-7 pr-2 py-1 text-[11px] text-white font-mono outline-none focus:border-cyan-500"
            />
          </div>

          {/* Dense Table View */}
          <div className="flex-1 overflow-y-auto border border-[#27272a] bg-[#050507] select-none scrollbar-thin scrollbar-thumb-zinc-800">
            <table className="w-full text-left border-collapse text-[11px]">
              <thead className="sticky top-0 bg-[#12141a] text-[#71717a] border-b border-[#27272a] font-bold text-[10px]">
                <tr>
                  <th className="p-1.5 pl-2">SEV</th>
                  <th className="p-1.5">CVSS</th>
                  <th className="p-1.5">VULNERABILITY &amp; CWE</th>
                  <th className="p-1.5 text-right pr-2">PATH</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#18181b]">
                {filteredFindings.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="p-6 text-center text-[#71717a] text-xs">
                      {isScanning ? 'Probing endpoints in real-time...' : 'No vulnerabilities found matching scope.'}
                    </td>
                  </tr>
                ) : (
                  filteredFindings.map((finding, idx) => {
                    const isSelected = finding.id === currentFinding?.id;
                    const badge = SEVERITY_COLORS[finding.severity] || SEVERITY_COLORS.info;

                    return (
                      <tr
                        key={finding.id}
                        onClick={() => setSelectedFindingId(finding.id)}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-[#18181b] border-l-2 border-cyan-400 text-white font-semibold'
                            : 'hover:bg-[#0f1015] text-[#a1a1aa]'
                        }`}
                      >
                        <td className="p-1.5 pl-2 whitespace-nowrap">
                          <span
                            className={`text-[9px] font-bold px-1 py-0.2 border ${badge.bg} ${badge.text} ${badge.border}`}
                          >
                            {badge.label}
                          </span>
                        </td>
                        <td className="p-1.5 font-mono text-[10px] text-white">
                          {finding.cvssScore.toFixed(1)}
                        </td>
                        <td className="p-1.5 max-w-[180px] truncate">
                          <div className="truncate text-white font-medium">{finding.name}</div>
                          <div className="text-[10px] text-[#71717a] font-mono">{finding.cweId}</div>
                        </td>
                        <td className="p-1.5 text-right pr-2 font-mono text-[10px] text-cyan-400/90 truncate max-w-[100px]">
                          {finding.matchedAt}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Keyboard tip */}
          <div className="flex items-center justify-between text-[10px] text-[#71717a] pt-1">
            <span>NAV: <kbd className="px-1 bg-[#18181b] text-white border border-[#27272a]">j</kbd> / <kbd className="px-1 bg-[#18181b] text-white border border-[#27272a]">k</kbd></span>
            <span>INSPECTOR: <kbd className="px-1 bg-[#18181b] text-white border border-[#27272a]">Tab</kbd></span>
          </div>
        </div>

        {/* PANE 3: RAW HTTP INSPECTOR & EVIDENCE PoC (Col-span 4) */}
        <div className="lg:col-span-4 bg-[#090a0f] border border-[#27272a] p-2 flex flex-col space-y-2">
          {/* Tabs: Request, Response, Remediation, PoC */}
          <div className="flex items-center justify-between border-b border-[#27272a] pb-1">
            <div className="flex items-center bg-[#050507] border border-[#27272a]">
              <button
                type="button"
                onClick={() => setInspectorTab('response')}
                className={`px-2 py-1 text-[10px] font-bold ${
                  inspectorTab === 'response' ? 'bg-cyan-600 text-white' : 'text-[#71717a] hover:text-white'
                }`}
              >
                &lt; RESPONSE
              </button>
              <button
                type="button"
                onClick={() => setInspectorTab('request')}
                className={`px-2 py-1 text-[10px] font-bold ${
                  inspectorTab === 'request' ? 'bg-cyan-600 text-white' : 'text-[#71717a] hover:text-white'
                }`}
              >
                &gt; REQUEST
              </button>
              <button
                type="button"
                onClick={() => setInspectorTab('remediation')}
                className={`px-2 py-1 text-[10px] font-bold ${
                  inspectorTab === 'remediation' ? 'bg-cyan-600 text-white' : 'text-[#71717a] hover:text-white'
                }`}
              >
                FIX &amp; RECIPE
              </button>
              <button
                type="button"
                onClick={() => setInspectorTab('raw')}
                className={`px-2 py-1 text-[10px] font-bold ${
                  inspectorTab === 'raw' ? 'bg-cyan-600 text-white' : 'text-[#71717a] hover:text-white'
                }`}
              >
                cURL PoC
              </button>
            </div>

            {currentFinding && (
              <button
                type="button"
                onClick={() => {
                  const textToCopy =
                    inspectorTab === 'request'
                      ? rawRequestText
                      : inspectorTab === 'response'
                      ? rawResponseText
                      : inspectorTab === 'raw'
                      ? curlPoc
                      : currentFinding.remediation;
                  handleCopy('inspector', textToCopy);
                }}
                className="text-[10px] text-[#a1a1aa] hover:text-white flex items-center gap-1"
              >
                {copiedKey === 'inspector' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copiedKey === 'inspector' ? 'COPIED' : 'COPY'}</span>
              </button>
            )}
          </div>

          {/* Finding Overview Header */}
          {currentFinding ? (
            <div className="p-2 bg-[#050507] border border-[#27272a] text-[11px] space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-bold text-white truncate">{currentFinding.name}</span>
                <span className="text-[10px] text-cyan-400 font-mono">CVSS {currentFinding.cvssScore.toFixed(1)}</span>
              </div>
              <div className="text-[10px] text-[#71717a] truncate font-mono">
                {currentFinding.url} ({currentFinding.matchedAt})
              </div>
            </div>
          ) : (
            <div className="p-2 bg-[#050507] border border-[#27272a] text-[11px] text-[#71717a]">
              Select a finding from the table to inspect raw payload evidence.
            </div>
          )}

          {/* Content Area */}
          <div className="flex-1 bg-[#050507] border border-[#27272a] p-2 overflow-y-auto text-[11px] font-mono leading-relaxed select-all scrollbar-thin scrollbar-thumb-zinc-800 max-h-[380px]">
            {inspectorTab === 'response' && (
              <pre className="text-[#34d399] whitespace-pre-wrap">{rawResponseText}</pre>
            )}
            {inspectorTab === 'request' && (
              <pre className="text-cyan-300 whitespace-pre-wrap">{rawRequestText}</pre>
            )}
            {inspectorTab === 'raw' && (
              <div className="space-y-2">
                <div className="text-[10px] text-[#71717a]">EXECUTE THIS PROOF-OF-CONCEPT IN TERMINAL:</div>
                <pre className="p-2 bg-[#12141a] border border-[#27272a] text-amber-300 whitespace-pre-wrap font-bold">
                  {curlPoc}
                </pre>
              </div>
            )}
            {inspectorTab === 'remediation' && currentFinding && (
              <div className="space-y-3 font-sans text-xs">
                <div>
                  <span className="font-bold text-white font-mono block text-[11px] mb-1">
                    VULNERABILITY DESCRIPTION:
                  </span>
                  <p className="text-[#a1a1aa] leading-relaxed">{currentFinding.description}</p>
                </div>
                <div className="pt-2 border-t border-[#27272a]">
                  <span className="font-bold text-emerald-400 font-mono block text-[11px] mb-1">
                    RECOMMENDED HARDENING:
                  </span>
                  <p className="text-[#e4e4e7] leading-relaxed whitespace-pre-line font-mono text-[11px] bg-[#12141a] p-2 border border-[#27272a]">
                    {currentFinding.remediation}
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 3. DOCKABLE LIVE TERMINAL CONSOLE BUFFER (BOTTOM PANEL) */}
      <div className="bg-[#050507] border border-[#27272a] p-2 space-y-1.5">
        <div className="flex items-center justify-between border-b border-[#27272a] pb-1.5 text-xs">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setIsLogDrawerOpen(!isLogDrawerOpen)}
              className="flex items-center gap-1.5 text-[#d4d4d8] hover:text-white font-bold"
            >
              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
              <span>LIVE TERMINAL LOG STREAM</span>
              <span className="text-[10px] text-[#71717a] font-normal">({logs.length} events)</span>
              {isLogDrawerOpen ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
            </button>
          </div>

          <div className="flex items-center gap-2 text-[10px]">
            {/* Filter buttons */}
            <div className="flex items-center bg-[#12141a] border border-[#27272a]">
              <button
                type="button"
                onClick={() => setLogFilter('all')}
                className={`px-2 py-0.5 ${logFilter === 'all' ? 'bg-cyan-600 text-white font-bold' : 'text-[#71717a]'}`}
              >
                ALL
              </button>
              <button
                type="button"
                onClick={() => setLogFilter('alert')}
                className={`px-2 py-0.5 ${logFilter === 'alert' ? 'bg-red-600 text-white font-bold' : 'text-[#71717a]'}`}
              >
                ALERTS
              </button>
              <button
                type="button"
                onClick={() => setLogFilter('probe')}
                className={`px-2 py-0.5 ${logFilter === 'probe' ? 'bg-cyan-600 text-white font-bold' : 'text-[#71717a]'}`}
              >
                PROBES
              </button>
            </div>

            <button
              type="button"
              onClick={onClearLogs}
              className="px-2 py-0.5 bg-[#12141a] hover:bg-[#1f2430] border border-[#27272a] text-[#71717a] hover:text-white"
            >
              CLEAR
            </button>
          </div>
        </div>

        {/* Live Terminal Output Box */}
        {isLogDrawerOpen && (
          <div className="h-32 bg-[#020203] p-2 border border-[#18181b] overflow-y-auto text-[11px] font-mono leading-tight space-y-0.5 scrollbar-thin scrollbar-thumb-zinc-800">
            {filteredLogs.length === 0 ? (
              <div className="text-[#52525b] italic">Ready. Press [EXECUTE AUDIT] or Ctrl+Enter to begin probing.</div>
            ) : (
              filteredLogs.map((log, idx) => {
                const isCrit = log.level === 'crit';
                const isWarn = log.level === 'warn';
                const isPass = log.level === 'pass';

                return (
                  <div key={idx} className="flex items-start gap-2 hover:bg-[#090a0f] px-1 py-0.5">
                    <span className="text-[#52525b] shrink-0 text-[10px]">[{log.timestamp}]</span>
                    <span
                      className={`font-bold shrink-0 text-[10px] ${
                        isCrit
                          ? 'text-red-400'
                          : isWarn
                          ? 'text-orange-400'
                          : isPass
                          ? 'text-emerald-400'
                          : 'text-cyan-400'
                      }`}
                    >
                      {isCrit ? '[!] CRIT' : isWarn ? '[*] WARN' : isPass ? '[+] PASS' : '[•] INFO'}
                    </span>
                    <span
                      className={`break-all ${
                        isCrit ? 'text-red-300 font-semibold' : isWarn ? 'text-orange-300' : 'text-[#d4d4d8]'
                      }`}
                    >
                      {log.message}
                    </span>
                  </div>
                );
              })
            )}
            <div ref={terminalEndRef} />
          </div>
        )}
      </div>
    </div>
  );
};
