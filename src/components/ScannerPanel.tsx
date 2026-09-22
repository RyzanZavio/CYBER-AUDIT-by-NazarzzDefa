import React, { useState, useEffect } from 'react';
import {
  Shield,
  Play,
  Square,
  Cpu,
  Zap,
  Settings2,
  ChevronDown,
  ChevronUp,
  Globe,
  Radio,
  Clock,
  Sparkles,
  CheckCircle,
  FileDown,
  ExternalLink,
  Sliders,
  AlertTriangle,
  ShieldAlert,
} from 'lucide-react';
import { ScanResult, YamlTemplate } from '../types';
import { generatePdfReport } from '../utils/pdfGenerator';

interface ScannerPanelProps {
  templates: YamlTemplate[];
  isScanning: boolean;
  onStartScan: (
    targetUrl: string,
    selectedTemplateIds: string[],
    timeoutMs: number,
    threads?: number,
    options?: { adaptiveDelay?: boolean; allowInternal?: boolean }
  ) => Promise<void>;
  onCancelScan?: () => void;
  lastScan: ScanResult | null;
  onViewFindingsTab: () => void;
}

export const ScannerPanel: React.FC<ScannerPanelProps> = ({
  templates,
  isScanning,
  onStartScan,
  onCancelScan,
  lastScan,
  onViewFindingsTab,
}) => {
  const [targetUrl, setTargetUrl] = useState<string>('http://localhost:3000');
  const [selectedTemplateIds, setSelectedTemplateIds] = useState<string[]>(
    templates.filter(t => t.enabled).map(t => t.id)
  );
  const [showAdvanced, setShowAdvanced] = useState<boolean>(false);
  const [timeoutSec, setTimeoutSec] = useState<number>(8);
  const [threads, setThreads] = useState<number>(10);
  const [adaptiveDelay, setAdaptiveDelay] = useState<boolean>(true);
  const [allowInternal, setAllowInternal] = useState<boolean>(false);

  // Allow ESC key to immediately cancel active audit
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isScanning && onCancelScan) {
        onCancelScan();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isScanning, onCancelScan]);

  const presets = [
    { label: 'smkn3kotabekasi.sch.id (Audit Target)', url: 'https://smkn3kotabekasi.sch.id' },
    { label: 'Local Dev App (Port 3000)', url: 'http://localhost:3000' },
    { label: 'OWASP Official Portal', url: 'https://owasp.org' },
    { label: 'Httpbin Testbed', url: 'https://httpbin.org' },
  ];

  const threadPresets = [
    { label: '1 (Stealth/IDS Evasion)', value: 1, desc: 'Safe for sensitive targets' },
    { label: '5 (Balanced)', value: 5, desc: 'Default safe concurrency' },
    { label: '10 (Fast Audit)', value: 10, desc: 'High-throughput security testing' },
    { label: '20 (Turbo Mode)', value: 20, desc: 'Maximum worker concurrency' },
  ];

  const handleToggleTemplate = (id: string) => {
    setSelectedTemplateIds(prev =>
      prev.includes(id) ? prev.filter(t => t !== id) : [...prev, id]
    );
  };

  const handleSelectAll = (select: boolean) => {
    if (select) {
      setSelectedTemplateIds(templates.map(t => t.id));
    } else {
      setSelectedTemplateIds([]);
    }
  };

  const handleLaunch = () => {
    if (!targetUrl.trim() || isScanning) return;
    onStartScan(targetUrl.trim(), selectedTemplateIds, timeoutSec * 1000, threads, {
      adaptiveDelay,
      allowInternal,
    });
  };

  const enabledCount = selectedTemplateIds.length;

  return (
    <div id="scanner-panel-container" className="space-y-6">
      {/* Target & Execution Hero Card */}
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-2xl shadow-xl space-y-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-cyan-400" />
              <h2 className="text-base font-semibold text-white">
                Vulnerability Assessment Target
              </h2>
            </div>
            <p className="text-xs text-slate-400">
              Audits web applications against OWASP Top 10, Nuclei templates, and Burp Suite heuristics with multi-threaded execution.
            </p>
          </div>

          <div className="flex items-center gap-3 text-xs flex-wrap">
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-slate-400 font-mono">Threads:</span>
              <span className="text-cyan-300 font-mono font-bold">{threads}</span>
            </div>
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-cyan-950/80 border border-cyan-800">
              <span className="text-slate-300">Templates:</span>
              <span className="font-mono font-bold text-cyan-300">
                {enabledCount} of {templates.length}
              </span>
            </div>
          </div>
        </div>

        {/* Input & Launch Group */}
        <div className="space-y-3">
          <label className="block text-xs font-medium text-slate-300">
            Target Host or Web URL (HTTP/HTTPS)
          </label>
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Globe className="w-4 h-4 absolute left-3.5 top-3.5 text-slate-500" />
              <input
                id="target-url-input"
                type="text"
                value={targetUrl}
                onChange={e => setTargetUrl(e.target.value)}
                placeholder="https://example.com"
                disabled={isScanning}
                className="w-full pl-10 pr-4 py-3 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 font-mono transition shadow-inner"
              />
            </div>

            {/* Launch or Cancel Button */}
            {isScanning ? (
              <div className="flex items-center gap-2">
                <button
                  id="scanning-status-badge"
                  disabled
                  className="inline-flex items-center justify-center gap-2 px-4 py-3 rounded-xl text-xs font-semibold bg-cyan-950 border border-cyan-800 text-cyan-300 cursor-wait whitespace-nowrap"
                >
                  <Radio className="w-4 h-4 animate-spin text-cyan-400" />
                  <span>Auditing ({threads} Threads)...</span>
                </button>
                <button
                  id="cancel-scan-btn"
                  onClick={onCancelScan}
                  className="inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl text-xs font-bold bg-red-600 hover:bg-red-500 text-white shadow-lg shadow-red-950 border border-red-500 transition active:scale-95 whitespace-nowrap animate-pulse"
                  title="Immediately abort active worker threads and cancel audit (ESC)"
                >
                  <Square className="w-4 h-4 fill-current" />
                  <span>Cancel Audit (ESC)</span>
                </button>
              </div>
            ) : (
              <button
                id="start-scan-btn"
                onClick={handleLaunch}
                disabled={!targetUrl.trim() || enabledCount === 0}
                className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white shadow-lg shadow-cyan-950 transition active:scale-95 whitespace-nowrap"
              >
                <Play className="w-4 h-4 fill-current" />
                <span>Start Vulnerability Audit</span>
              </button>
            )}
          </div>

          {/* Quick Target Presets */}
          <div className="flex flex-wrap items-center gap-2 pt-1">
            <span className="text-[11px] text-slate-500">Quick Targets:</span>
            {presets.map((preset, pIdx) => (
              <button
                key={pIdx}
                type="button"
                onClick={() => setTargetUrl(preset.url)}
                disabled={isScanning}
                className="px-2.5 py-1 rounded-lg bg-slate-950 hover:bg-slate-800 text-[11px] text-slate-400 hover:text-cyan-300 border border-slate-800 transition font-mono"
              >
                {preset.label}
              </button>
            ))}
          </div>
        </div>

        {/* Dedicated Thread & Concurrency Controller */}
        <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="space-y-0.5">
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-semibold text-white font-mono">CONCURRENCY & THREAD CONTROLLER</span>
              <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-400 border border-cyan-800">
                {threads} WORKERS
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              Configure concurrent worker pool size to balance speed against server load and IDS/IPS detection.
            </p>
          </div>

          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-1.5 bg-slate-900 p-1 rounded-lg border border-slate-800">
              {threadPresets.map(tp => (
                <button
                  key={tp.value}
                  type="button"
                  onClick={() => setThreads(tp.value)}
                  disabled={isScanning}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono font-bold transition ${
                    threads === tp.value
                      ? 'bg-cyan-600 text-white shadow'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                  }`}
                  title={tp.desc}
                >
                  {tp.value}T
                </button>
              ))}
            </div>

            <div className="flex items-center gap-2">
              <input
                type="range"
                min="1"
                max="25"
                value={threads}
                onChange={e => setThreads(Number(e.target.value))}
                disabled={isScanning}
                className="w-24 accent-cyan-500 cursor-pointer"
              />
              <input
                type="number"
                min="1"
                max="25"
                value={threads}
                onChange={e => setThreads(Math.max(1, Math.min(25, Number(e.target.value))))}
                disabled={isScanning}
                className="w-12 px-1.5 py-1 bg-slate-900 border border-slate-700 rounded text-center text-cyan-300 font-mono text-xs font-bold"
              />
            </div>
          </div>
        </div>

        {/* Scan Status Ribbon if running or recently completed */}
        {lastScan && (
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs">
            <div className="flex items-center gap-2 flex-wrap">
              {lastScan.status === 'cancelled' ? (
                <>
                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                  <span className="text-slate-300">
                    Audit on <span className="font-mono text-cyan-300">{lastScan.targetUrl}</span> was{' '}
                    <strong className="text-amber-400 uppercase font-mono">CANCELLED</strong> after{' '}
                    {((lastScan.durationMs || 500) / 1000).toFixed(1)}s ({lastScan.findings.length} findings identified before abort)
                  </span>
                </>
              ) : (
                <>
                  <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span className="text-slate-300">
                    Latest audit on <span className="font-mono text-cyan-300">{lastScan.targetUrl}</span>:{' '}
                    <strong className="text-white">{lastScan.findings.length} findings</strong> across {lastScan.threads || 5} threads in{' '}
                    {((lastScan.durationMs || 1000) / 1000).toFixed(1)}s
                  </span>
                </>
              )}

              {lastScan.wafDetected && (
                <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-amber-950/80 border border-amber-600/70 text-amber-300 font-semibold flex items-center gap-1">
                  <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                  WAF Detected: {lastScan.wafDetected}
                </span>
              )}
            </div>

            <div className="flex items-center gap-2 self-end sm:self-center">
              <button
                onClick={onViewFindingsTab}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 hover:text-cyan-300 font-mono text-[11px] transition"
              >
                Inspect Findings →
              </button>
              <button
                onClick={() => generatePdfReport(lastScan)}
                className="px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 font-mono text-[11px] flex items-center gap-1 transition"
              >
                <FileDown className="w-3 h-3" />
                <span>PDF</span>
              </button>
            </div>
          </div>
        )}

        {/* Collapsible Advanced Config */}
        <div className="border-t border-slate-800/80 pt-3">
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center justify-between w-full text-xs text-slate-400 hover:text-slate-200 transition py-1"
          >
            <div className="flex items-center gap-1.5">
              <Settings2 className="w-3.5 h-3.5 text-cyan-400" />
              <span className="font-medium">Audit Templates Selection &amp; Engine Tuning</span>
            </div>
            {showAdvanced ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>

          {showAdvanced && (
            <div className="mt-4 space-y-4 pt-2 border-t border-slate-800/60">
              {/* Select all / Deselect all */}
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-400">Active Vulnerability Checksuites</span>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => handleSelectAll(true)}
                    className="text-[11px] text-cyan-400 hover:underline"
                  >
                    Select All
                  </button>
                  <span className="text-slate-600">|</span>
                  <button
                    type="button"
                    onClick={() => handleSelectAll(false)}
                    className="text-[11px] text-slate-400 hover:underline"
                  >
                    Clear All
                  </button>
                </div>
              </div>

              {/* Grid of Templates to Toggle */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-56 overflow-y-auto pr-1 scrollbar-thin scrollbar-thumb-slate-800">
                {templates.map(tpl => {
                  const isChecked = selectedTemplateIds.includes(tpl.id);
                  const badgeColor =
                    tpl.severity === 'critical'
                      ? 'text-rose-400'
                      : tpl.severity === 'high'
                      ? 'text-orange-400'
                      : tpl.severity === 'medium'
                      ? 'text-amber-400'
                      : 'text-blue-400';

                  return (
                    <label
                      key={tpl.id}
                      className={`flex items-start gap-2.5 p-2.5 rounded-xl border cursor-pointer select-none transition ${
                        isChecked
                          ? 'bg-slate-950 border-cyan-500/50'
                          : 'bg-slate-950/40 border-slate-800 opacity-60'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => handleToggleTemplate(tpl.id)}
                        className="mt-0.5 rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0"
                      />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-1">
                          <span className="text-xs font-semibold text-white truncate">
                            {tpl.name}
                          </span>
                          <span className={`text-[10px] font-mono font-bold uppercase ${badgeColor}`}>
                            {tpl.severity}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 truncate mt-0.5">{tpl.description}</p>
                      </div>
                    </label>
                  );
                })}
              </div>

              {/* Request timeout setting */}
              <div className="flex items-center justify-between p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs">
                <div>
                  <span className="font-medium text-white block">HTTP Request Timeout</span>
                  <span className="text-[11px] text-slate-500">Max milliseconds to wait for target response before timeout.</span>
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    min="2"
                    max="30"
                    value={timeoutSec}
                    onChange={e => setTimeoutSec(Number(e.target.value))}
                    className="w-16 px-2 py-1 bg-slate-900 border border-slate-700 rounded text-center text-white font-mono text-xs"
                  />
                  <span className="text-slate-400">seconds</span>
                </div>
              </div>

              {/* Adaptive Delay & Jitter Anti-Banned Toggle */}
              <div className="flex items-center justify-between p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-white">Adaptive Delay &amp; Jitter (Anti-Banned / Anonymity)</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold">
                      STEALTH
                    </span>
                  </div>
                  <span className="text-[11px] text-slate-400 block max-w-xl">
                    Randomizes inter-request probe intervals and engages automatic backoff when Cloudflare/AWS/Imperva WAFs or HTTP 429 rate-limits are detected.
                  </span>
                </div>
                <label className="relative inline-flex items-center cursor-pointer shrink-0">
                  <input
                    type="checkbox"
                    checked={adaptiveDelay}
                    onChange={e => setAdaptiveDelay(e.target.checked)}
                    className="sr-only peer"
                  />
                  <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600"></div>
                </label>
              </div>

              {/* Allow Internal Scope Toggle */}
              <div className="flex items-center justify-between p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-white">Allow Internal Subnets &amp; Localhost</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-950 text-amber-300 border border-amber-800 font-bold">
                      SSRF OVERRIDE
                    </span>
                  </div>
                  <span className="text-[11px] text-slate-500 block max-w-xl">
                    By default, scanning loopback (127.0.0.1) and RFC1918 subnets is blocked for safety. Enable this for testing isolated local testbeds.
                  </span>
                </div>
                <label className="relative inline-flex items-center cursor-pointer shrink-0">
                  <input
                    type="checkbox"
                    checked={allowInternal}
                    onChange={e => setAllowInternal(e.target.checked)}
                    className="sr-only peer"
                  />
                  <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-amber-600"></div>
                </label>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

