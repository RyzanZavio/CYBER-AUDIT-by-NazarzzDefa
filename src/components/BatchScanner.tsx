import React, { useState, useRef, useEffect } from 'react';
import {
  Upload,
  FileText,
  Play,
  Square,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  HardDrive,
  Trash2,
  Search,
  ExternalLink,
  ShieldAlert,
  Layers,
  ArrowRight,
  FileDown,
  RotateCw,
  Clock,
  ShieldCheck,
  Check,
} from 'lucide-react';
import { BatchScanSummary, ScanResult, VulnerabilityFinding, YamlTemplate, ProxyConfig } from '../types';
import { extractDomainsFromText, ParsedTargetItem } from '../utils/domainExtractor';
import { generatePdfReport } from '../utils/pdfGenerator';

interface BatchScannerProps {
  templates: YamlTemplate[];
  proxyConfig: ProxyConfig;
  onViewProxyTab: () => void;
  onBatchCompleted?: (summary: BatchScanSummary) => void;
}

export const BatchScanner: React.FC<BatchScannerProps> = ({
  templates,
  proxyConfig,
  onViewProxyTab,
  onBatchCompleted,
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [parsedTargets, setParsedTargets] = useState<ParsedTargetItem[]>([]);
  const [manualInput, setManualInput] = useState('');
  const [sourceFileName, setSourceFileName] = useState<string | null>(null);
  const [selectedTemplateIds, setSelectedTemplateIds] = useState<string[]>(
    templates.filter(t => t.enabled).map(t => t.id)
  );
  const [isScanning, setIsScanning] = useState(false);
  const [threads, setThreads] = useState<number>(10);
  const [progress, setProgress] = useState<{ current: number; total: number; currentTarget?: string }>({
    current: 0,
    total: 0,
  });
  const [batchSummary, setBatchSummary] = useState<BatchScanSummary | null>(null);
  const [selectedTargetDetail, setSelectedTargetDetail] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const batchAbortControllerRef = useRef<AbortController | null>(null);
  const currentBatchScanIdRef = useRef<string | null>(null);

  const handleCancelBatchScan = async () => {
    const scanId = currentBatchScanIdRef.current;
    if (batchAbortControllerRef.current) {
      batchAbortControllerRef.current.abort();
    }
    if (scanId) {
      try {
        await fetch('/api/scan/cancel', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scanId }),
        });
      } catch (e) {
        console.warn('Failed to cancel backend batch scan:', e);
      }
    }
    setIsScanning(false);
  };

  // Keyboard shortcut Esc to cancel batch scan
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isScanning) {
        e.preventDefault();
        handleCancelBatchScan();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isScanning]);

  const handleProcessFile = (file: File) => {
    setSourceFileName(file.name);
    const reader = new FileReader();
    reader.onload = e => {
      const text = e.target?.result as string;
      if (text) {
        const extracted = extractDomainsFromText(text);
        setParsedTargets(extracted);
      }
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleProcessFile(e.dataTransfer.files[0]);
    }
  };

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleProcessFile(e.target.files[0]);
    }
  };

  const handleManualParse = () => {
    if (!manualInput.trim()) return;
    const extracted = extractDomainsFromText(manualInput);
    setParsedTargets(extracted);
    setSourceFileName('manual-pasted-list.txt');
  };

  const handleLoadSampleSubfinder = () => {
    const sample = `
# Subfinder recon output for target.internal
api.example.com
admin.example.com
portal.example.com
staging.example.com
dev.internal.example.com
auth.example.com
git.example.com
testbed.example.com
`;
    const extracted = extractDomainsFromText(sample);
    setParsedTargets(extracted);
    setSourceFileName('subfinder-recon-export.txt');
    setManualInput(sample.trim());
  };

  const handleClearTargets = () => {
    setParsedTargets([]);
    setSourceFileName(null);
    setManualInput('');
    setBatchSummary(null);
    setSelectedTargetDetail(null);
  };

  const handleRemoveSingle = (id: string) => {
    setParsedTargets(prev => prev.filter(t => t.id !== id));
  };

  const handleStartBatchScan = async () => {
    if (parsedTargets.length === 0 || isScanning) return;

    const scanId = `batch-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    currentBatchScanIdRef.current = scanId;
    const controller = new AbortController();
    batchAbortControllerRef.current = controller;

    setIsScanning(true);
    setBatchSummary(null);
    setSelectedTargetDetail(null);
    setProgress({ current: 0, total: parsedTargets.length });

    try {
      const targetUrls = parsedTargets.map(t => t.normalizedUrl);

      const res = await fetch('/api/scan/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify({
          scanId,
          targets: targetUrls,
          templateIds: selectedTemplateIds,
          timeoutMs: 6000,
          threads,
          proxy: proxyConfig.enabled ? proxyConfig : undefined,
        }),
      });

      if (!res.ok) {
        throw new Error(`Batch scan request failed with status ${res.status}`);
      }

      const data: BatchScanSummary = await res.json();
      setBatchSummary(data);
      setProgress({ current: parsedTargets.length, total: parsedTargets.length });
      if (onBatchCompleted) {
        onBatchCompleted(data);
      }
    } catch (err: any) {
      if (err.name === 'AbortError') {
        console.info('Batch scan aborted by user');
      } else {
        console.error('Batch scan error:', err);
        alert(`Batch scan error: ${err.message}`);
      }
    } finally {
      setIsScanning(false);
      batchAbortControllerRef.current = null;
    }
  };

  const handleExportBatchPdf = () => {
    if (!batchSummary) return;

    // Synthesize a consolidated scan result for the batch
    const allFindings = Object.values(batchSummary.resultsByTarget || {}).flatMap(
      r => r.findings || []
    );
    const consolidatedResult: ScanResult = {
      id: batchSummary.id,
      targetUrl: `Subdomain Recon Batch (${batchSummary.totalTargets} Hosts)`,
      startTime: batchSummary.startTime,
      durationMs: 4800,
      status: 'completed',
      findings: allFindings,
      templatesExecuted: selectedTemplateIds.length,
      requestsSent: batchSummary.totalTargets * selectedTemplateIds.length,
      logs: [
        {
          timestamp: new Date().toLocaleTimeString(),
          level: 'info',
          message: `Consolidated report generated for ${batchSummary.totalTargets} scanned hosts.`,
        },
      ],
    };

    generatePdfReport(consolidatedResult);
  };

  return (
    <div id="batch-scanner-view" className="space-y-6">
      {/* Header & Feature Context */}
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-2xl shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Layers className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-semibold text-white">
              Multi-Target &amp; Subfinder Batch Scanner
            </h2>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
              LAPTOP / USB RECON IMPORT
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Drag and drop domain lists or Subfinder, Amass, and Assetfinder recon output files directly from your laptop or flash drive to audit all subdomains automatically.
          </p>
        </div>

        {/* Proxy Tunnel Status Pill */}
        <div className="flex items-center gap-2 text-xs">
          <button
            onClick={onViewProxyTab}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono transition ${
              proxyConfig.enabled
                ? 'bg-emerald-950/40 text-emerald-300 border-emerald-800 hover:bg-emerald-900/50'
                : 'bg-slate-800 text-slate-400 border-slate-700 hover:text-white hover:bg-slate-700'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                proxyConfig.enabled ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'
              }`}
            ></span>
            <span>Proxy: {proxyConfig.enabled ? proxyConfig.url : 'Direct (Disabled)'}</span>
          </button>
        </div>
      </div>

      {/* Drag and Drop Zone & Input */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Dropzone Column */}
        <div className="lg:col-span-7 space-y-4">
          <div
            id="drag-drop-zone"
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onClick={() => fileInputRef.current?.click()}
            className={`cursor-pointer border-2 border-dashed rounded-2xl p-8 text-center transition flex flex-col items-center justify-center min-h-[220px] ${
              isDragging
                ? 'border-cyan-400 bg-cyan-950/30 shadow-lg shadow-cyan-950'
                : 'border-slate-800 bg-slate-900/60 hover:border-slate-700 hover:bg-slate-900'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".txt,.csv,.lst,.json,.log"
              onChange={handleFileInputChange}
              className="hidden"
            />
            <div className="w-12 h-12 rounded-xl bg-slate-800 flex items-center justify-center text-cyan-400 mb-3 group-hover:scale-105 transition">
              <Upload className="w-6 h-6" />
            </div>
            <h3 className="text-sm font-semibold text-white">
              Drag &amp; drop subfinder list from laptop or flashdisk
            </h3>
            <p className="text-xs text-slate-400 mt-1 max-w-sm">
              Supports <span className="text-cyan-400 font-mono">.txt</span>, <span className="text-cyan-400 font-mono">.csv</span>, or raw line-separated subdomain reconnaissance files.
            </p>
            <div className="mt-4 flex items-center gap-3">
              <span className="text-[11px] text-slate-500">or click to browse local files</span>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  handleLoadSampleSubfinder();
                }}
                className="px-2.5 py-1 text-[11px] font-mono rounded bg-slate-800 text-cyan-300 border border-slate-700 hover:bg-slate-700 transition"
              >
                Load Subfinder Demo
              </button>
            </div>
          </div>

          {/* Manual Input or Paste Area */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300">
                Or Paste Raw Domain &amp; Subdomain Text
              </span>
              {manualInput && (
                <button
                  onClick={handleManualParse}
                  className="px-2 py-0.5 text-[11px] rounded bg-cyan-600 hover:bg-cyan-500 text-white transition font-mono"
                >
                  Extract Targets
                </button>
              )}
            </div>
            <textarea
              id="manual-domains-textarea"
              value={manualInput}
              onChange={e => setManualInput(e.target.value)}
              placeholder="sub1.target.com&#10;sub2.target.com&#10;https://api.target.com&#10;admin.target.internal"
              rows={3}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 resize-none"
            />
          </div>
        </div>

        {/* Parsed Target Manifest Card */}
        <div className="lg:col-span-5 flex flex-col bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-xl">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
            <div>
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-semibold text-white uppercase tracking-wider">
                  Target Queue ({parsedTargets.length})
                </h3>
              </div>
              {sourceFileName && (
                <p className="text-[11px] text-cyan-400 font-mono mt-0.5 truncate max-w-[220px]">
                  From: {sourceFileName}
                </p>
              )}
            </div>

            {parsedTargets.length > 0 && (
              <button
                onClick={handleClearTargets}
                className="text-xs text-rose-400 hover:text-rose-300 flex items-center gap-1 font-mono transition"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear</span>
              </button>
            )}
          </div>

          {/* Scrollable list of extracted targets */}
          <div className="flex-1 overflow-y-auto max-h-[220px] space-y-1.5 pr-1 scrollbar-thin">
            {parsedTargets.length === 0 ? (
              <div className="h-full min-h-[140px] flex flex-col items-center justify-center text-slate-500 text-xs text-center p-4">
                <HardDrive className="w-8 h-8 mb-2 opacity-40 text-cyan-400" />
                <span>No targets loaded yet.</span>
                <span className="text-[10px] text-slate-600 mt-1">
                  Drag a file or paste domains to begin.
                </span>
              </div>
            ) : (
              parsedTargets.map(item => (
                <div
                  key={item.id}
                  className="flex items-center justify-between p-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono group hover:border-cyan-800 transition"
                >
                  <div className="flex items-center gap-2 truncate">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 shrink-0"></span>
                    <span className="text-slate-300 truncate">{item.hostname}</span>
                  </div>
                  <button
                    onClick={() => handleRemoveSingle(item.id)}
                    className="opacity-0 group-hover:opacity-100 text-slate-500 hover:text-rose-400 p-1 transition"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              ))
            )}
          </div>

          {/* Concurrency Threads Tuning for Batch Recon */}
          <div className="pt-3 border-t border-slate-800 mt-2 flex items-center justify-between gap-2 text-xs">
            <div className="flex items-center gap-1.5 text-slate-400">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              <span className="font-mono text-[11px]">Audit Threads:</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1 bg-slate-950 p-0.5 rounded border border-slate-800">
                {[5, 10, 15, 20].map(tVal => (
                  <button
                    key={tVal}
                    type="button"
                    onClick={() => setThreads(tVal)}
                    disabled={isScanning}
                    className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded transition ${
                      threads === tVal
                        ? 'bg-cyan-600 text-white shadow'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {tVal}T
                  </button>
                ))}
              </div>
              <input
                type="number"
                min="1"
                max="25"
                value={threads}
                onChange={e => setThreads(Math.max(1, Math.min(25, Number(e.target.value))))}
                disabled={isScanning}
                className="w-10 px-1 py-0.5 bg-slate-950 border border-slate-800 rounded text-center text-cyan-300 font-mono text-[11px] font-bold"
              />
            </div>
          </div>

          {/* Action Launch & Cancel Bar */}
          <div className="pt-3 border-t border-slate-800 mt-2 space-y-2">
            {isScanning ? (
              <div className="flex items-center gap-2">
                <div className="flex-1 py-2.5 px-3 rounded-xl text-xs font-semibold flex items-center justify-center gap-2 bg-cyan-950 border border-cyan-800 text-cyan-300">
                  <RotateCw className="w-4 h-4 animate-spin text-cyan-400 shrink-0" />
                  <span className="truncate">Auditing {parsedTargets.length} Domains ({threads} Threads)...</span>
                </div>
                <button
                  id="cancel-batch-scan-btn"
                  onClick={handleCancelBatchScan}
                  className="py-2.5 px-4 rounded-xl text-xs font-bold flex items-center justify-center gap-1.5 bg-red-600 hover:bg-red-500 text-white border border-red-500 shadow-md shadow-red-950 transition active:scale-95 animate-pulse shrink-0 cursor-pointer"
                  title="Cancel batch audit immediately (ESC)"
                >
                  <Square className="w-3.5 h-3.5 fill-current" />
                  <span>Cancel (ESC)</span>
                </button>
              </div>
            ) : (
              <button
                id="start-batch-scan-btn"
                disabled={parsedTargets.length === 0}
                onClick={handleStartBatchScan}
                className={`w-full py-2.5 px-4 rounded-xl text-xs font-semibold flex items-center justify-center gap-2 shadow-lg transition ${
                  parsedTargets.length === 0
                    ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                    : 'bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-cyan-950 cursor-pointer'
                }`}
              >
                <Play className="w-4 h-4 fill-current" />
                <span>Execute Audit Across {parsedTargets.length} Domains ({threads} Threads)</span>
              </button>
            )}

            {isScanning && (
              <div className="text-[11px] font-mono text-center text-cyan-400 animate-pulse">
                Auditing subdomains with {selectedTemplateIds.length} YAML templates concurrently...
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Batch Results Overview if completed */}
      {batchSummary && (
        <div id="batch-results-section" className="space-y-4">
          {/* Summary Metric Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <span className="text-[11px] text-slate-400 font-mono">Audited Targets</span>
              <div className="text-xl font-bold font-mono text-white mt-1">
                {batchSummary.completedTargets} / {batchSummary.totalTargets}
              </div>
            </div>

            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <span className="text-[11px] text-slate-400 font-mono">Total Vulnerabilities</span>
              <div className="text-xl font-bold font-mono text-cyan-400 mt-1">
                {batchSummary.totalFindings}
              </div>
            </div>

            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <span className="text-[11px] text-slate-400 font-mono">Critical Findings</span>
              <div className={`text-xl font-bold font-mono mt-1 ${batchSummary.criticalCount > 0 ? 'text-rose-400' : 'text-slate-400'}`}>
                {batchSummary.criticalCount}
              </div>
            </div>

            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <span className="text-[11px] text-slate-400 font-mono">High Severity</span>
              <div className={`text-xl font-bold font-mono mt-1 ${batchSummary.highCount > 0 ? 'text-amber-400' : 'text-slate-400'}`}>
                {batchSummary.highCount}
              </div>
            </div>
          </div>

          {/* Results Table per Subdomain */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-semibold text-white">
                  Subdomain Audit Results Matrix
                </h3>
              </div>
              <button
                onClick={handleExportBatchPdf}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium shadow transition"
              >
                <FileDown className="w-3.5 h-3.5" />
                <span>Export Batch PDF Report</span>
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 text-[11px]">
                  <tr>
                    <th className="p-3">Target Subdomain</th>
                    <th className="p-3">Audit Status</th>
                    <th className="p-3">Findings</th>
                    <th className="p-3">Severity Breakdown</th>
                    <th className="p-3 text-right">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {Object.entries(batchSummary.resultsByTarget).map(([targetUrl, res]) => {
                    const crits = res.findings.filter(f => f.severity === 'critical').length;
                    const highs = res.findings.filter(f => f.severity === 'high').length;
                    const meds = res.findings.filter(f => f.severity === 'medium').length;
                    const isSelected = selectedTargetDetail === targetUrl;

                    return (
                      <React.Fragment key={targetUrl}>
                        <tr
                          onClick={() => setSelectedTargetDetail(isSelected ? null : targetUrl)}
                          className={`cursor-pointer transition hover:bg-slate-800/40 ${
                            isSelected ? 'bg-slate-800/60' : ''
                          }`}
                        >
                          <td className="p-3 font-semibold text-cyan-300 truncate max-w-[200px]">
                            {targetUrl}
                          </td>
                          <td className="p-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] ${
                                res.status === 'completed'
                                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                                  : 'bg-rose-950 text-rose-400 border border-rose-800'
                              }`}
                            >
                              {res.status.toUpperCase()}
                            </span>
                          </td>
                          <td className="p-3">
                            {res.findings.length > 0 ? (
                              <span className="text-amber-400 font-bold">
                                {res.findings.length} issues
                              </span>
                            ) : (
                              <span className="text-emerald-400 flex items-center gap-1">
                                <Check className="w-3.5 h-3.5" /> Clean
                              </span>
                            )}
                          </td>
                          <td className="p-3">
                            <div className="flex items-center gap-1.5 text-[10px]">
                              {crits > 0 && (
                                <span className="px-1.5 py-0.2 rounded bg-rose-950 text-rose-400 border border-rose-800">
                                  {crits} crit
                                </span>
                              )}
                              {highs > 0 && (
                                <span className="px-1.5 py-0.2 rounded bg-amber-950 text-amber-400 border border-amber-800">
                                  {highs} high
                                </span>
                              )}
                              {meds > 0 && (
                                <span className="px-1.5 py-0.2 rounded bg-yellow-950 text-yellow-400 border border-yellow-800">
                                  {meds} med
                                </span>
                              )}
                              {res.findings.length === 0 && (
                                <span className="text-slate-500">No vulnerabilities detected</span>
                              )}
                            </div>
                          </td>
                          <td className="p-3 text-right">
                            <span className="text-xs text-cyan-400 underline">
                              {isSelected ? 'Collapse' : 'Inspect'}
                            </span>
                          </td>
                        </tr>

                        {/* Detailed Findings Drawer for Selected Subdomain */}
                        {isSelected && (
                          <tr className="bg-slate-950/80">
                            <td colSpan={5} className="p-4">
                              <div className="space-y-3">
                                <div className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                                  <span>Vulnerabilities Identified on {targetUrl}:</span>
                                  <button
                                    onClick={() => generatePdfReport(res)}
                                    className="text-[11px] text-cyan-400 hover:text-cyan-300 underline font-mono flex items-center gap-1"
                                  >
                                    <FileDown className="w-3 h-3" />
                                    Download Target PDF
                                  </button>
                                </div>

                                {res.findings.length === 0 ? (
                                  <p className="text-xs text-slate-400 italic">
                                    No vulnerabilities flagged for this target under current active templates.
                                  </p>
                                ) : (
                                  <div className="space-y-2">
                                    {res.findings.map(f => (
                                      <div
                                        key={f.id}
                                        className="p-3 bg-slate-900 border border-slate-800 rounded-xl space-y-1 text-xs"
                                      >
                                        <div className="flex items-center justify-between">
                                          <span className="font-semibold text-white">
                                            {f.name}
                                          </span>
                                          <span
                                            className={`px-2 py-0.2 rounded text-[10px] uppercase font-bold ${
                                              f.severity === 'critical'
                                                ? 'bg-rose-950 text-rose-400 border border-rose-800'
                                                : f.severity === 'high'
                                                ? 'bg-amber-950 text-amber-400 border border-amber-800'
                                                : 'bg-yellow-950 text-yellow-400 border border-yellow-800'
                                            }`}
                                          >
                                            {f.severity}
                                          </span>
                                        </div>
                                        <p className="text-slate-400 text-[11px]">
                                          {f.description}
                                        </p>
                                        {f.remediation && (
                                          <div className="text-[11px] text-emerald-400/90 pt-1">
                                            <span className="font-bold">Fix:</span> {f.remediation}
                                          </div>
                                        )}
                                      </div>
                                    ))}
                                  </div>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
