import React, { useEffect, useRef, useState } from 'react';
import {
  Terminal,
  Copy,
  Check,
  Trash2,
  ArrowDown,
  Shield,
  ChevronDown,
  ChevronRight,
  Code,
  Radio,
  Search,
  Filter,
  Send,
  ExternalLink,
} from 'lucide-react';
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
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [copiedAll, setCopiedAll] = useState(false);
  const [filterMode, setFilterMode] = useState<'all' | 'payloads' | 'vulns'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedLogIds, setExpandedLogIds] = useState<Record<string, boolean>>({});

  useEffect(() => {
    if (autoScroll && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  const toggleExpand = (id: string) => {
    setExpandedLogIds(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const handleCopyLogs = () => {
    const text = logs
      .map(l => {
        let line = `[${l.timestamp}] [${l.level.toUpperCase()}] ${l.message}`;
        if (l.payload) {
          line += `\n  >> REQUEST: ${l.payload.method} ${l.payload.url}`;
          if (l.payload.body) line += `\n  >> BODY: ${l.payload.body}`;
          if (l.payload.statusCode) line += `\n  >> RESPONSE: HTTP ${l.payload.statusCode} (${l.payload.responseTimeMs || 0}ms)`;
        }
        return line;
      })
      .join('\n');
    navigator.clipboard.writeText(text);
    setCopiedAll(true);
    setTimeout(() => setCopiedAll(false), 2000);
  };

  const copyCurl = (log: ScanLog, index: number) => {
    if (!log.payload) return;
    const { method, url, headers, body } = log.payload;
    let cmd = `curl -i -X ${method} "${url}"`;
    if (headers) {
      Object.entries(headers).forEach(([k, v]) => {
        cmd += ` \\\n  -H "${k}: ${v}"`;
      });
    }
    if (body) {
      cmd += ` \\\n  --data '${body.replace(/'/g, "'\\''")}'`;
    }
    navigator.clipboard.writeText(cmd);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  // Filter logs based on category and search query
  const filteredLogs = logs.filter(log => {
    if (filterMode === 'payloads' && !log.payload) return false;
    if (filterMode === 'vulns' && log.level !== 'crit' && log.level !== 'warn') return false;

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchMsg = log.message.toLowerCase().includes(q);
      const matchUrl = log.payload?.url?.toLowerCase().includes(q);
      const matchTpl = log.templateId?.toLowerCase().includes(q);
      const matchBody = log.payload?.body?.toLowerCase().includes(q);
      return matchMsg || matchUrl || matchTpl || matchBody;
    }
    return true;
  });

  const payloadCount = logs.filter(l => !!l.payload).length;
  const vulnCount = logs.filter(l => l.level === 'crit' || l.level === 'warn').length;

  return (
    <div
      id="terminal-console-container"
      className="flex flex-col bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl h-[560px]"
    >
      {/* Terminal Title Bar */}
      <div className="flex flex-wrap items-center justify-between px-4 py-2.5 bg-slate-900 border-b border-slate-800 select-none gap-2">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 mr-2">
            <div className="w-3 h-3 rounded-full bg-rose-500/80"></div>
            <div className="w-3 h-3 rounded-full bg-amber-500/80"></div>
            <div className="w-3 h-3 rounded-full bg-emerald-500/80"></div>
          </div>
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-mono font-medium text-slate-300">
            secops@parrot-os: ~/reconize-audit (live-stream)
          </span>
          {isScanning ? (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800 animate-pulse">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
              REALTIME TRANSMITTING...
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
              IDLE / READY
            </span>
          )}
        </div>

        <div className="flex items-center gap-1 text-slate-400">
          <button
            id="toggle-autoscroll-btn"
            onClick={() => setAutoScroll(!autoScroll)}
            title={autoScroll ? 'Matikan Auto-scroll' : 'Aktifkan Auto-scroll'}
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
            title="Salin Seluruh Log & Payload"
            className="p-1.5 rounded hover:bg-slate-800 transition text-xs flex items-center gap-1"
          >
            {copiedAll ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span className="text-[10px] font-mono hidden sm:inline">{copiedAll ? 'Tersalin' : 'Copy Log'}</span>
          </button>

          {onClearLogs && (
            <button
              id="clear-terminal-logs-btn"
              onClick={onClearLogs}
              title="Bersihkan Log Terminal"
              className="p-1.5 rounded hover:bg-slate-800 transition text-xs text-slate-400 hover:text-rose-400"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Filter & Live Search Toolbar */}
      <div className="flex flex-wrap items-center justify-between px-3 py-1.5 bg-slate-900/60 border-b border-slate-800/80 text-xs font-mono gap-2">
        <div className="flex items-center gap-1.5">
          <span className="text-[11px] text-slate-500 flex items-center gap-1">
            <Filter className="w-3 h-3 text-slate-400" /> Filter:
          </span>
          <button
            onClick={() => setFilterMode('all')}
            className={`px-2 py-0.5 rounded text-[11px] transition ${
              filterMode === 'all'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            Semua ({logs.length})
          </button>
          <button
            onClick={() => setFilterMode('payloads')}
            className={`px-2 py-0.5 rounded text-[11px] transition flex items-center gap-1 ${
              filterMode === 'payloads'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <Send className="w-2.5 h-2.5" />
            Payload Terkirim ({payloadCount})
          </button>
          <button
            onClick={() => setFilterMode('vulns')}
            className={`px-2 py-0.5 rounded text-[11px] transition ${
              filterMode === 'vulns'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            Temuan ({vulnCount})
          </button>
        </div>

        <div className="relative flex items-center">
          <Search className="w-3 h-3 text-slate-500 absolute left-2 pointer-events-none" />
          <input
            type="text"
            placeholder="Cari URL / payload..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="bg-slate-950/80 border border-slate-800 text-slate-300 placeholder-slate-600 pl-6 pr-2 py-0.5 rounded text-[11px] w-40 sm:w-52 focus:outline-none focus:border-cyan-500"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-1.5 text-slate-500 hover:text-slate-300 text-[10px]"
            >
              ✕
            </button>
          )}
        </div>
      </div>

      {/* Terminal Content Body */}
      <div className="flex-1 p-3 font-mono text-xs overflow-y-auto space-y-1.5 bg-slate-950/95 scrollbar-thin scrollbar-thumb-slate-800">
        {/* Banner */}
        <div className="text-slate-500 text-[11px] leading-relaxed pb-2 border-b border-slate-800/80 mb-2">
          <span className="text-cyan-400 font-bold">[*] DevSecOps Cybersecurity Vulnerability Auditor v2.4 (Live Wire Engine)</span>
          <br />
          <span className="text-slate-400">
            [*] Protocols: HTTP/HTTPS Raw Transmit · Upstream Security Tunneling · Real-time Matcher Evaluation
          </span>
          <br />
          <span className="text-slate-500">
            [*] Menampilkan data log realtime &amp; transmisi payload HTTP yang dikirimkan ke target.
          </span>
        </div>

        {filteredLogs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-slate-600 gap-2">
            <Shield className="w-8 h-8 text-slate-700" />
            <p>
              {logs.length === 0
                ? 'Terminal siap. Masukkan URL target dan klik "Mulai Audit Keamanan".'
                : 'Tidak ada log yang sesuai dengan filter pencarian.'}
            </p>
            <p className="text-[10px] text-slate-700">
              Log dan payload HTTP request/response akan dialirkan (streaming) secara langsung di sini.
            </p>
          </div>
        ) : (
          filteredLogs.map((log, index) => {
            const logId = log.id || `log-${index}`;
            const isExpanded = !!expandedLogIds[logId];

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
              textClass = 'text-amber-200 font-medium';
            } else if (log.level === 'pass') {
              badgeClass = 'text-emerald-400 bg-emerald-950/50 border-emerald-800/50';
              label = '[PASS]';
              textClass = 'text-emerald-300/80';
            }

            const hasPayload = !!log.payload;

            return (
              <div
                key={logId}
                className="group flex flex-col rounded border border-transparent hover:border-slate-800 hover:bg-slate-900/40 p-1 transition-colors"
              >
                {/* Main Log Row */}
                <div className="flex items-start gap-2 leading-relaxed">
                  <span className="text-slate-600 select-none text-[10px] pt-0.5 shrink-0">
                    {log.timestamp}
                  </span>

                  <span
                    className={`px-1.5 py-0.2 rounded border text-[10px] font-semibold tracking-wider shrink-0 ${badgeClass}`}
                  >
                    {label}
                  </span>

                  <span className={`flex-1 break-all ${textClass}`}>
                    {log.message}
                  </span>

                  {hasPayload && (
                    <button
                      onClick={() => toggleExpand(logId)}
                      className="ml-auto shrink-0 flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[10px] border border-slate-700"
                      title="Lihat Rincian Payload HTTP Wire"
                    >
                      <Code className="w-2.5 h-2.5" />
                      <span>{isExpanded ? 'Tutup Payload' : 'Payload'}</span>
                      {isExpanded ? (
                        <ChevronDown className="w-3 h-3" />
                      ) : (
                        <ChevronRight className="w-3 h-3" />
                      )}
                    </button>
                  )}
                </div>

                {/* Interactive Payload Drawer (Request & Response Wire) */}
                {hasPayload && isExpanded && log.payload && (
                  <div className="mt-2 ml-7 mr-1 p-2.5 rounded-lg bg-slate-900/90 border border-cyan-900/50 text-[11px] space-y-2">
                    {/* Header Row: Method + URL + Actions */}
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-1.5">
                      <div className="flex items-center gap-2 font-mono">
                        <span className="px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 font-bold border border-cyan-800 text-[10px]">
                          {log.payload.method}
                        </span>
                        <span className="text-slate-200 font-semibold break-all">
                          {log.payload.url}
                        </span>
                      </div>

                      <div className="flex items-center gap-2">
                        {log.payload.statusCode && (
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              log.payload.statusCode >= 200 && log.payload.statusCode < 300
                                ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                                : log.payload.statusCode >= 300 && log.payload.statusCode < 400
                                ? 'bg-blue-950 text-blue-400 border border-blue-800'
                                : log.payload.statusCode >= 400 && log.payload.statusCode < 500
                                ? 'bg-amber-950 text-amber-400 border border-amber-800'
                                : 'bg-rose-950 text-rose-400 border border-rose-800'
                            }`}
                          >
                            HTTP {log.payload.statusCode}
                          </span>
                        )}

                        {log.payload.responseTimeMs !== undefined && (
                          <span className="text-[10px] text-slate-400">
                            {log.payload.responseTimeMs}ms
                          </span>
                        )}

                        <button
                          onClick={() => copyCurl(log, index)}
                          className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] flex items-center gap-1 border border-slate-700 transition"
                          title="Salin sebagai perintah cURL untuk Linux terminal"
                        >
                          {copiedIndex === index ? (
                            <>
                              <Check className="w-2.5 h-2.5 text-emerald-400" />
                              <span className="text-emerald-400 font-medium">cURL Tersalin!</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-2.5 h-2.5" />
                              <span>Copy cURL</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>

                    {/* Request Headers */}
                    {log.payload.headers && Object.keys(log.payload.headers).length > 0 && (
                      <div>
                        <span className="text-slate-400 text-[10px] font-semibold uppercase tracking-wider block mb-1">
                          Request Headers:
                        </span>
                        <div className="bg-slate-950 p-2 rounded border border-slate-800 text-slate-300 font-mono text-[10px] space-y-0.5 overflow-x-auto">
                          {Object.entries(log.payload.headers).map(([k, v]) => (
                            <div key={k}>
                              <span className="text-cyan-400">{k}:</span>{' '}
                              <span className="text-slate-400">{v}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Request Body Payload */}
                    {log.payload.body && (
                      <div>
                        <span className="text-slate-400 text-[10px] font-semibold uppercase tracking-wider block mb-1">
                          Request Body Payload:
                        </span>
                        <pre className="bg-slate-950 p-2 rounded border border-slate-800 text-amber-300 font-mono text-[10px] whitespace-pre-wrap break-all overflow-x-auto">
                          {log.payload.body}
                        </pre>
                      </div>
                    )}

                    {/* Match Evidence / Result */}
                    {log.payload.evidence && (
                      <div className="bg-slate-950/80 p-2 rounded border border-slate-800 text-[10px]">
                        <span className="text-slate-400 font-semibold">Hasil Evaluasi Matcher: </span>
                        <span className={log.payload.matched ? 'text-rose-300 font-medium' : 'text-emerald-300'}>
                          {log.payload.evidence}
                        </span>
                      </div>
                    )}
                  </div>
                )}
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
          <span className="text-slate-500 text-[11px] whitespace-nowrap">Tes Payload Cepat:</span>
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
              <button
                onClick={() => onQuickRun('nuclei -t exposed-git-repository')}
                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] transition whitespace-nowrap"
              >
                git-exposure
              </button>
            </>
          )}
        </div>
        <div className="text-[11px] text-slate-500 hidden sm:flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
          <span>HTTP Payload Wire Inspector Aktif</span>
        </div>
      </div>
    </div>
  );
};
