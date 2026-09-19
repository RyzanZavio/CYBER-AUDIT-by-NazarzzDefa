import React, { useEffect, useRef, useState } from 'react';
import { Terminal, Copy, Check, Trash2, ArrowDown, Shield, Play } from 'lucide-react';
import { ScanLog } from '../types';

interface TerminalViewProps {
  logs: ScanLog[];
  isScanning: boolean;
  onClearLogs?: () => void;
  onQuickRun?: (cmd: string) => void;
}

export const TerminalView: React.FC<TerminalViewProps> = ({
  logs,
  isScanning,
  onClearLogs,
  onQuickRun,
}) => {
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (autoScroll && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  const handleCopyLogs = () => {
    const text = logs.map(l => `[${l.timestamp}] [${l.level.toUpperCase()}] ${l.message}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div id="terminal-console-container" className="flex flex-col bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl h-[520px]">
      {/* Terminal Title Bar */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-slate-900 border-b border-slate-800 select-none">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 mr-2">
            <div className="w-3 h-3 rounded-full bg-rose-500/80"></div>
            <div className="w-3 h-3 rounded-full bg-amber-500/80"></div>
            <div className="w-3 h-3 rounded-full bg-emerald-500/80"></div>
          </div>
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-mono font-medium text-slate-300">
            secops@linux-wsl: ~/cyber-audit-engine (bash)
          </span>
          {isScanning && (
            <span className="ml-2 inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800 animate-pulse">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
              SCANNING...
            </span>
          )}
        </div>

        <div className="flex items-center gap-1 text-slate-400">
          <button
            id="toggle-autoscroll-btn"
            onClick={() => setAutoScroll(!autoScroll)}
            title={autoScroll ? 'Disable Auto-scroll' : 'Enable Auto-scroll'}
            className={`p-1.5 rounded hover:bg-slate-800 transition text-xs flex items-center gap-1 ${
              autoScroll ? 'text-cyan-400' : 'text-slate-500'
            }`}
          >
            <ArrowDown className="w-3.5 h-3.5" />
            <span className="text-[10px] font-mono hidden sm:inline">Auto-scroll</span>
          </button>

          <button
            id="copy-terminal-logs-btn"
            onClick={handleCopyLogs}
            title="Copy Terminal Logs"
            className="p-1.5 rounded hover:bg-slate-800 transition text-xs flex items-center gap-1"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span className="text-[10px] font-mono hidden sm:inline">{copied ? 'Copied' : 'Copy'}</span>
          </button>

          {onClearLogs && (
            <button
              id="clear-terminal-logs-btn"
              onClick={onClearLogs}
              title="Clear Terminal Output"
              className="p-1.5 rounded hover:bg-slate-800 transition text-xs text-slate-400 hover:text-rose-400"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Terminal Content Body */}
      <div className="flex-1 p-4 font-mono text-xs overflow-y-auto space-y-1 bg-slate-950/95 scrollbar-thin scrollbar-thumb-slate-800">
        {/* Banner */}
        <div className="text-slate-500 text-[11px] leading-relaxed pb-2 border-b border-slate-800/80 mb-2">
          <span className="text-cyan-400 font-bold">[*] DevSecOps Cybersecurity Vulnerability Auditor v2.4</span>
          <br />
          <span className="text-slate-400">[*] Engine: Hybrid OWASP ZAP Core + Nuclei YAML Engine + Burp Suite Passive/Active Rules</span>
          <br />
          <span className="text-slate-500">[*] Type commands below or click &quot;Start Vulnerability Audit&quot; to probe targets.</span>
        </div>

        {logs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-slate-600 gap-2">
            <Shield className="w-8 h-8 text-slate-700" />
            <p>Ready for audit. Enter target URL and run scan.</p>
            <p className="text-[10px] text-slate-700">Output logs with color-coded severity will stream here in real-time.</p>
          </div>
        ) : (
          logs.map((log, index) => {
            let badgeClass = 'text-cyan-400 bg-cyan-950/50 border-cyan-800/50';
            let label = '[INF]';
            let textClass = 'text-slate-300';

            if (log.level === 'crit') {
              badgeClass = 'text-rose-400 bg-rose-950/80 border-rose-800';
              label = '[CRIT]';
              textClass = 'text-rose-200 font-semibold';
            } else if (log.level === 'warn') {
              badgeClass = 'text-amber-400 bg-amber-950/80 border-amber-800';
              label = '[WARN]';
              textClass = 'text-amber-200';
            } else if (log.level === 'pass') {
              badgeClass = 'text-emerald-400 bg-emerald-950/50 border-emerald-800/50';
              label = '[PASS]';
              textClass = 'text-emerald-300/80';
            }

            return (
              <div key={index} className="flex items-start gap-2 leading-relaxed hover:bg-slate-900/40 px-1 rounded transition-colors">
                <span className="text-slate-600 select-none text-[10px] pt-0.5">{log.timestamp}</span>
                <span className={`px-1.5 py-0.2 rounded border text-[10px] font-semibold tracking-wider ${badgeClass}`}>
                  {label}
                </span>
                <span className={`flex-1 break-all ${textClass}`}>
                  {log.message}
                </span>
              </div>
            );
          })
        )}
        <div ref={terminalEndRef} />
      </div>

      {/* Terminal Quick Command Bar */}
      <div className="px-3 py-2 bg-slate-900/90 border-t border-slate-800 flex items-center justify-between text-xs font-mono">
        <div className="flex items-center gap-2 overflow-x-auto text-slate-400 py-0.5">
          <span className="text-emerald-400 font-bold">$</span>
          <span className="text-slate-500 text-[11px] whitespace-nowrap">Quick CLI Tests:</span>
          {onQuickRun && (
            <>
              <button
                onClick={() => onQuickRun('nuclei -t owasp-security-headers')}
                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] transition whitespace-nowrap"
              >
                headers-audit
              </button>
              <button
                onClick={() => onQuickRun('nuclei -t exposed-env-credentials')}
                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] transition whitespace-nowrap"
              >
                check-.env
              </button>
              <button
                onClick={() => onQuickRun('nuclei -t cors-misconfiguration')}
                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] transition whitespace-nowrap"
              >
                cors-probe
              </button>
            </>
          )}
        </div>
        <div className="text-[11px] text-slate-500 hidden sm:block">
          Linux / WSL Terminal Active
        </div>
      </div>
    </div>
  );
};
