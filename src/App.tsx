import React, { useEffect, useState } from 'react';
import {
  Shield,
  Terminal,
  FileCode,
  Bell,
  Clock,
  AlertTriangle,
  FileDown,
  Activity,
  Layers,
  ChevronRight,
  Sparkles,
  ExternalLink,
  Package,
  Radio,
  Palette,
  Sliders,
} from 'lucide-react';
import { DEFAULT_TEMPLATES } from './data/defaultTemplates';
import { DEFAULT_EXTENSIONS } from './data/defaultExtensions';
import {
  BatchScanSummary,
  ExtensionManifest,
  ProxyConfig,
  ScanLog,
  ScanResult,
  ScheduleConfig,
  VisualSettings,
  WebhookConfig,
  YamlTemplate,
} from './types';
import { TerminalView } from './components/TerminalView';
import { ScannerPanel } from './components/ScannerPanel';
import { FindingsList } from './components/FindingsList';
import { TemplateManager } from './components/TemplateManager';
import { WebhookSettings } from './components/WebhookSettings';
import { SchedulerAndCliGuide } from './components/SchedulerAndCliGuide';
import { BatchScanner } from './components/BatchScanner';
import { ProxySettings } from './components/ProxySettings';
import { ExtensionManager } from './components/ExtensionManager';
import { VisualCustomizer } from './components/VisualCustomizer';
import { cyberSound } from './utils/cyberSound';
import { generatePdfReport } from './utils/pdfGenerator';

type TabId =
  | 'scanner'
  | 'batch'
  | 'findings'
  | 'templates'
  | 'extensions'
  | 'proxy'
  | 'webhook'
  | 'scheduler'
  | 'visual';

const DEFAULT_VISUAL_SETTINGS: VisualSettings = {
  theme: 'cyber-slate',
  accent: 'cyan',
  fontFamily: 'sans',
  density: 'normal',
  fontSizeScale: 100,
  enableScanlines: false,
  scanlineIntensity: 2,
  enableNeonGlow: true,
  enableBackgroundGrid: true,
  enableSoundFx: true,
  soundVolume: 50,
  reducedMotion: false,
};

export default function App() {
  const [activeTab, setActiveTab] = useState<TabId>('scanner');
  const [isVisualCustomizerOpen, setIsVisualCustomizerOpen] = useState(false);
  const [visualSettings, setVisualSettings] = useState<VisualSettings>(() => {
    if (typeof window !== 'undefined') {
      try {
        const saved = localStorage.getItem('devsecops_visual_settings');
        if (saved) {
          return { ...DEFAULT_VISUAL_SETTINGS, ...JSON.parse(saved) };
        }
      } catch {}
    }
    return DEFAULT_VISUAL_SETTINGS;
  });
  const [templates, setTemplates] = useState<YamlTemplate[]>(DEFAULT_TEMPLATES);

  const [extensions, setExtensions] = useState<ExtensionManifest[]>(DEFAULT_EXTENSIONS);
  const [proxyConfig, setProxyConfig] = useState<ProxyConfig>({
    enabled: false,
    url: 'http://127.0.0.1:8080',
    insecureSkipVerify: true,
    customUserAgent: 'Mozilla/5.0 (compatible; DevSecOps-Auditor/2.4; +https://owasp.org)',
  });
  const [isScanning, setIsScanning] = useState(false);
  const [scanLogs, setScanLogs] = useState<ScanLog[]>([]);
  const [currentScanResult, setCurrentScanResult] = useState<ScanResult | null>(null);

  const [webhookConfig, setWebhookConfig] = useState<WebhookConfig>({
    type: 'discord',
    url: '',
    enabled: false,
    minSeverity: 'medium',
    channelName: '#security-alerts',
  });

  const [scheduleConfig, setScheduleConfig] = useState<ScheduleConfig>({
    enabled: true,
    timeString: '02:00',
    cronExpression: '0 2 * * *',
    targetUrl: 'http://localhost:3000',
    selectedTemplateIds: [],
    notifyWebhook: true,
    status: 'idle',
    lastStatus: 'Daily scan ready',
  });

  // Fetch initial state from API
  useEffect(() => {
    fetchTemplates();
    fetchExtensions();
    fetchProxyConfig();
    fetchWebhookConfig();
    fetchScheduleConfig();
  }, []);

  const fetchTemplates = async () => {
    try {
      const res = await fetch('/api/templates');
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data) && data.length > 0) {
          setTemplates(data);
        }
      }
    } catch (e) {
      console.warn('Using local default templates:', e);
    }
  };

  const fetchExtensions = async () => {
    try {
      const res = await fetch('/api/extensions');
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data)) {
          setExtensions(data);
        }
      }
    } catch (e) {
      console.warn('Using local extensions:', e);
    }
  };

  const fetchProxyConfig = async () => {
    try {
      const res = await fetch('/api/proxy');
      if (res.ok) {
        const data = await res.json();
        if (data && data.url) {
          setProxyConfig(data);
        }
      }
    } catch (e) {
      console.warn('Using local proxy config:', e);
    }
  };

  const fetchWebhookConfig = async () => {
    try {
      const res = await fetch('/api/webhook');
      if (res.ok) {
        const data = await res.json();
        setWebhookConfig(data);
      }
    } catch (e) {
      console.warn('Webhook config fetch failed:', e);
    }
  };

  const fetchScheduleConfig = async () => {
    try {
      const res = await fetch('/api/schedule');
      if (res.ok) {
        const data = await res.json();
        if (data && data.config) {
          setScheduleConfig(data.config);
        }
      }
    } catch (e) {
      console.warn('Schedule config fetch failed:', e);
    }
  };

  const handleSaveVisualSettings = (newSettings: VisualSettings) => {
    setVisualSettings(newSettings);
    try {
      localStorage.setItem('devsecops_visual_settings', JSON.stringify(newSettings));
    } catch {}
  };

  const handleResetVisualDefaults = () => {
    setVisualSettings(DEFAULT_VISUAL_SETTINGS);
    try {
      localStorage.removeItem('devsecops_visual_settings');
    } catch {}
    if (DEFAULT_VISUAL_SETTINGS.enableSoundFx) {
      cyberSound.playClick(50);
    }
  };

  const handleTabChange = (tab: TabId) => {
    setActiveTab(tab);
    if (visualSettings.enableSoundFx) {
      cyberSound.playClick(visualSettings.soundVolume);
    }
  };

  // Run security scan
  const handleStartScan = async (
    targetUrl: string,
    selectedTemplateIds: string[],
    timeoutMs: number
  ) => {
    setIsScanning(true);
    if (visualSettings.enableSoundFx) {
      cyberSound.playPing('scan', visualSettings.soundVolume);
    }

    const initLogs: ScanLog[] = [
      {
        timestamp: new Date().toLocaleTimeString(),
        level: 'info',
        message: `DevSecOps Vulnerability Auditor v2.4 initialized`,
      },
      {
        timestamp: new Date().toLocaleTimeString(),
        level: 'info',
        message: `Target: ${targetUrl} | Templates: ${selectedTemplateIds.length}`,
      },
      {
        timestamp: new Date().toLocaleTimeString(),
        level: 'info',
        message: `Engine: OWASP ZAP Core + Nuclei YAML Engine + Burp Suite Passive Heuristics`,
      },
    ];
    setScanLogs(initLogs);

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetUrl,
          templateIds: selectedTemplateIds,
          timeoutMs,
          webhook: webhookConfig,
        }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({ error: 'Scan request failed' }));
        throw new Error(errData.error || `HTTP ${res.status}`);
      }

      const result: ScanResult = await res.json();
      setCurrentScanResult(result);
      if (visualSettings.enableSoundFx) {
        if (result.findings && result.findings.length > 0) {
          cyberSound.playPing('alert', visualSettings.soundVolume);
        } else {
          cyberSound.playPing('success', visualSettings.soundVolume);
        }
      }
      if (result.logs && result.logs.length > 0) {
        setScanLogs(result.logs);
      }
    } catch (err: any) {
      if (visualSettings.enableSoundFx) {
        cyberSound.playPing('alert', visualSettings.soundVolume);
      }
      setScanLogs(prev => [
        ...prev,
        {
          timestamp: new Date().toLocaleTimeString(),
          level: 'crit',
          message: `Scan execution halted: ${err.message}`,
        },
      ]);
    } finally {
      setIsScanning(false);
    }
  };

  const handleUpdateTemplate = async (template: YamlTemplate) => {
    try {
      const res = await fetch('/api/templates', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(template),
      });
      if (res.ok) {
        setTemplates(prev => {
          const idx = prev.findIndex(t => t.id === template.id);
          if (idx >= 0) {
            const copy = [...prev];
            copy[idx] = template;
            return copy;
          }
          return [...prev, template];
        });
      }
    } catch (err) {
      console.error('Failed to save template:', err);
    }
  };

  const handleDeleteTemplate = async (id: string) => {
    try {
      const res = await fetch(`/api/templates/${id}`, { method: 'DELETE' });
      if (res.ok) {
        setTemplates(prev => prev.filter(t => t.id !== id));
      }
    } catch (err) {
      console.error('Failed to delete template:', err);
    }
  };

  const handleResetDefaults = async () => {
    try {
      const res = await fetch('/api/templates/reset', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setTemplates(data.templates);
      }
    } catch (err) {
      setTemplates(DEFAULT_TEMPLATES);
    }
  };

  const handleSaveWebhook = async (newConfig: WebhookConfig) => {
    setWebhookConfig(newConfig);
    try {
      await fetch('/api/webhook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newConfig),
      });
    } catch (e) {
      console.error('Webhook save error:', e);
    }
  };

  const handleTestWebhook = async (config: WebhookConfig) => {
    const res = await fetch('/api/webhook/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
    return await res.json();
  };

  const handleUpdateSchedule = async (newConfig: Partial<ScheduleConfig>) => {
    setScheduleConfig(prev => ({ ...prev, ...newConfig }));
    try {
      const res = await fetch('/api/schedule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newConfig),
      });
      if (res.ok) {
        const data = await res.json();
        if (data && data.config) {
          setScheduleConfig(data.config);
        }
      }
    } catch (e) {
      console.error('Schedule update error:', e);
    }
  };

  const handleQuickRun = (cmd: string) => {
    if (cmd.includes('owasp-security-headers')) {
      handleStartScan('http://localhost:3000', ['owasp-security-headers'], 8000);
    } else if (cmd.includes('exposed-env-credentials')) {
      handleStartScan('http://localhost:3000', ['exposed-env-credentials'], 8000);
    } else if (cmd.includes('cors-misconfiguration')) {
      handleStartScan('http://localhost:3000', ['cors-misconfiguration'], 8000);
    }
  };

  const handleToggleExtension = async (id: string, enabled: boolean) => {
    try {
      const res = await fetch('/api/extensions/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, enabled }),
      });
      if (res.ok) {
        setExtensions(prev =>
          prev.map(e => (e.id === id ? { ...e, enabled, installed: true } : e))
        );
        fetchTemplates();
      }
    } catch (err) {
      console.error('Failed to toggle extension:', err);
    }
  };

  const handleInstallExtension = async (manifest: Partial<ExtensionManifest>) => {
    const res = await fetch('/api/extensions/install', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(manifest),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Install failed' }));
      throw new Error(err.error || 'Install failed');
    }
    fetchExtensions();
    fetchTemplates();
  };

  const handleDeleteExtension = async (id: string) => {
    try {
      const res = await fetch(`/api/extensions/${id}`, { method: 'DELETE' });
      if (res.ok) {
        setExtensions(prev => prev.filter(e => e.id !== id));
        fetchTemplates();
      }
    } catch (err) {
      console.error('Failed to uninstall extension:', err);
    }
  };

  const handleSaveProxyConfig = async (newConfig: ProxyConfig) => {
    setProxyConfig(newConfig);
    const res = await fetch('/api/proxy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(newConfig),
    });
    if (!res.ok) {
      throw new Error('Failed to persist proxy config');
    }
  };

  const handleBatchCompleted = (summary: BatchScanSummary) => {
    const allFindings = Object.values(summary.resultsByTarget || {}).flatMap(
      r => r.findings || []
    );
    const consolidatedResult: ScanResult = {
      id: summary.id,
      targetUrl: `Subdomain Recon Batch (${summary.totalTargets} Hosts)`,
      startTime: summary.startTime,
      durationMs: 4800,
      status: 'completed',
      findings: allFindings,
      templatesExecuted: templates.filter(t => t.enabled).length,
      requestsSent: summary.totalTargets * templates.filter(t => t.enabled).length,
      logs: [
        {
          timestamp: new Date().toLocaleTimeString(),
          level: 'info',
          message: `Batch scan finalized: ${summary.completedTargets}/${summary.totalTargets} hosts audited, ${summary.totalFindings} vulnerabilities found.`,
        },
      ],
    };
    setCurrentScanResult(consolidatedResult);
  };

  const findingsCount = currentScanResult?.findings.length ?? 0;
  const critCount = currentScanResult?.findings.filter(f => f.severity === 'critical').length ?? 0;

  return (
    <div
      id="cyber-audit-app"
      data-theme={visualSettings.theme}
      data-font={visualSettings.fontFamily}
      data-density={visualSettings.density}
      style={{ fontSize: `${visualSettings.fontSizeScale}%` }}
      className={`min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-900/70 relative transition-colors duration-300 ${
        visualSettings.enableNeonGlow ? 'neon-glow-active' : ''
      }`}
    >
      {/* Retro CRT Scanlines Effect Overlay */}
      {visualSettings.enableScanlines && (
        <div className="crt-scanline-overlay fixed inset-0 z-30 pointer-events-none opacity-30" />
      )}

      {/* Cyber Grid Overlay */}
      {visualSettings.enableBackgroundGrid && (
        <div className="cyber-grid-overlay fixed inset-0 z-0 pointer-events-none opacity-50" />
      )}

      {/* Top Navigation Bar */}
      <header className="sticky top-0 z-40 bg-slate-900/90 backdrop-blur-md border-b border-slate-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          {/* Logo & Platform Title */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center text-white shadow-lg shadow-cyan-900/30">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-bold tracking-tight text-white">
                  CYBERSECURITY AUDIT SCANNER
                </h1>
                <span className="hidden sm:inline px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-cyan-950 text-cyan-400 border border-cyan-800">
                  v2.4
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-mono hidden sm:block">
                OWASP ZAP · Nuclei YAML · Burp Suite Pro Rules Engine
              </p>
            </div>
          </div>

          {/* Quick Metrics Ribbon & Visual Trigger in Nav */}
          <div className="flex items-center gap-2 sm:gap-3 text-xs font-mono">
            {/* Quick Visual Customizer Trigger Button */}
            <button
              id="open-visual-customizer-btn"
              onClick={() => {
                setIsVisualCustomizerOpen(true);
                if (visualSettings.enableSoundFx) {
                  cyberSound.playClick(visualSettings.soundVolume);
                }
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyan-700/70 bg-cyan-950/60 text-cyan-300 hover:bg-cyan-900/60 transition shadow-sm font-sans"
              title="Sesuaikan Visual, Tema, Tipografi & Audio"
            >
              <Palette className="w-3.5 h-3.5 text-cyan-400" />
              <span className="hidden sm:inline">Visual:</span>
              <span className="capitalize font-bold font-mono text-[11px] text-white px-1.5 py-0.5 rounded bg-cyan-900/80 border border-cyan-700">
                {visualSettings.theme.replace('-', ' ')}
              </span>
            </button>

            <button
              onClick={() => handleTabChange('proxy')}
              className={`hidden md:flex items-center gap-1.5 px-3 py-1.5 rounded-lg border transition ${
                proxyConfig.enabled
                  ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                  : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
              }`}
            >
              <Radio
                className={`w-3.5 h-3.5 ${
                  proxyConfig.enabled ? 'text-emerald-400 animate-pulse' : 'text-slate-500'
                }`}
              />
              <span>Proxy: {proxyConfig.enabled ? 'ON' : 'DIRECT'}</span>
            </button>

            <div className="hidden lg:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>Daily Cron:</span>
              <span className="text-cyan-400 font-semibold">{scheduleConfig.timeString} UTC</span>
            </div>

            {webhookConfig.enabled && webhookConfig.url && (
              <div className="hidden xl:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-950/40 border border-indigo-900/50 text-indigo-300">
                <Bell className="w-3.5 h-3.5 text-indigo-400" />
                <span>{webhookConfig.type.toUpperCase()}</span>
              </div>
            )}

            {currentScanResult && (
              <button
                onClick={() => generatePdfReport(currentScanResult)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white shadow transition"
              >
                <FileDown className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Export PDF</span>
              </button>
            )}
          </div>
        </div>

        {/* Tab Navigation Menu */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex space-x-1 overflow-x-auto scrollbar-none border-t border-slate-800/80">
          <button
            id="tab-scanner-btn"
            onClick={() => handleTabChange('scanner')}
            className={`px-4 py-2.5 text-xs font-medium border-b-2 whitespace-nowrap transition flex items-center gap-2 ${
              activeTab === 'scanner'
                ? 'border-cyan-400 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>Target Scanner &amp; Terminal</span>
          </button>

          <button
            id="tab-batch-btn"
            onClick={() => handleTabChange('batch')}
            className={`px-4 py-2.5 text-xs font-medium border-b-2 whitespace-nowrap transition flex items-center gap-2 ${
              activeTab === 'batch'
                ? 'border-cyan-400 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>Subfinder &amp; File Import</span>
            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
              RECON
            </span>
          </button>

          <button
            id="tab-findings-btn"
            onClick={() => handleTabChange('findings')}
            className={`px-4 py-2.5 text-xs font-medium border-b-2 whitespace-nowrap transition flex items-center gap-2 ${
              activeTab === 'findings'
                ? 'border-cyan-400 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <AlertTriangle className="w-4 h-4" />
            <span>Audit Findings</span>
            {findingsCount > 0 && (
              <span
                className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono font-bold ${
                  critCount > 0
                    ? 'bg-rose-900/80 text-rose-300 border border-rose-700'
                    : 'bg-amber-900/80 text-amber-300 border border-amber-700'
                }`}
              >
                {findingsCount}
              </span>
            )}
          </button>

          <button
            id="tab-templates-btn"
            onClick={() => handleTabChange('templates')}
            className={`px-4 py-2.5 text-xs font-medium border-b-2 whitespace-nowrap transition flex items-center gap-2 ${
              activeTab === 'templates'
                ? 'border-cyan-400 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-4 h-4" />
            <span>YAML Templates ({templates.length})</span>
          </button>

          <button
            id="tab-extensions-btn"
            onClick={() => handleTabChange('extensions')}
            className={`px-4 py-2.5 text-xs font-medium border-b-2 whitespace-nowrap transition flex items-center gap-2 ${
              activeTab === 'extensions'
                ? 'border-cyan-400 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Package className="w-4 h-4" />
            <span>Extensions ({extensions.filter(e => e.enabled).length})</span>
          </button>

          <button
            id="tab-proxy-btn"
            onClick={() => handleTabChange('proxy')}
            className={`px-4 py-2.5 text-xs font-medium border-b-2 whitespace-nowrap transition flex items-center gap-2 ${
              activeTab === 'proxy'
                ? 'border-cyan-400 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Radio className="w-4 h-4" />
            <span>Proxy &amp; Tor</span>
            {proxyConfig.enabled && (
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            )}
          </button>

          <button
            id="tab-webhook-btn"
            onClick={() => handleTabChange('webhook')}
            className={`px-4 py-2.5 text-xs font-medium border-b-2 whitespace-nowrap transition flex items-center gap-2 ${
              activeTab === 'webhook'
                ? 'border-cyan-400 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Bell className="w-4 h-4" />
            <span>Webhooks</span>
          </button>

          <button
            id="tab-scheduler-btn"
            onClick={() => handleTabChange('scheduler')}
            className={`px-4 py-2.5 text-xs font-medium border-b-2 whitespace-nowrap transition flex items-center gap-2 ${
              activeTab === 'scheduler'
                ? 'border-cyan-400 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Clock className="w-4 h-4" />
            <span>Schedule &amp; CLI</span>
          </button>

          <button
            id="tab-visual-btn"
            onClick={() => handleTabChange('visual')}
            className={`px-4 py-2.5 text-xs font-medium border-b-2 whitespace-nowrap transition flex items-center gap-2 ${
              activeTab === 'visual'
                ? 'border-cyan-400 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Palette className="w-4 h-4 text-cyan-400" />
            <span>Sesuaikan Visual</span>
            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
              GAYA
            </span>
          </button>
        </div>
      </header>

      {/* Main Container Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        {/* Tab 1: Scanner & Terminal */}
        {activeTab === 'scanner' && (
          <div className="space-y-6">
            <ScannerPanel
              templates={templates}
              isScanning={isScanning}
              onStartScan={handleStartScan}
              lastScan={currentScanResult}
              onViewFindingsTab={() => handleTabChange('findings')}
            />

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold text-slate-300 font-mono flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  Live Linux &amp; WSL Terminal Stream (Audit Logs)
                </h3>
                <span className="text-[11px] text-slate-500 font-mono">
                  {scanLogs.length} events logged
                </span>
              </div>
              <TerminalView
                logs={scanLogs}
                isScanning={isScanning}
                onClearLogs={() => setScanLogs([])}
                onQuickRun={handleQuickRun}
              />
            </div>
          </div>
        )}

        {/* Tab 2: Subfinder & Batch Recon */}
        {activeTab === 'batch' && (
          <BatchScanner
            templates={templates}
            proxyConfig={proxyConfig}
            onViewProxyTab={() => handleTabChange('proxy')}
            onBatchCompleted={handleBatchCompleted}
          />
        )}

        {/* Tab 3: Findings List & PDF Export */}
        {activeTab === 'findings' && (
          <FindingsList
            scan={currentScanResult}
            onOpenPdf={() => currentScanResult && generatePdfReport(currentScanResult)}
          />
        )}

        {/* Tab 4: YAML Template Manager (Nuclei format) */}
        {activeTab === 'templates' && (
          <TemplateManager
            templates={templates}
            onUpdateTemplate={handleUpdateTemplate}
            onDeleteTemplate={handleDeleteTemplate}
            onResetDefaults={handleResetDefaults}
          />
        )}

        {/* Tab 5: Extensions Store */}
        {activeTab === 'extensions' && (
          <ExtensionManager
            extensions={extensions}
            onToggleExtension={handleToggleExtension}
            onInstallExtension={handleInstallExtension}
            onDeleteExtension={handleDeleteExtension}
            totalActiveTemplates={templates.length}
          />
        )}

        {/* Tab 6: Upstream Proxy & Anonymization */}
        {activeTab === 'proxy' && (
          <ProxySettings config={proxyConfig} onSaveConfig={handleSaveProxyConfig} />
        )}

        {/* Tab 7: Webhook Integration (Discord / Slack) */}
        {activeTab === 'webhook' && (
          <WebhookSettings
            config={webhookConfig}
            onSaveConfig={handleSaveWebhook}
            onTestWebhook={handleTestWebhook}
          />
        )}

        {/* Tab 8: Daily Schedule & Linux/WSL CLI */}
        {activeTab === 'scheduler' && (
          <SchedulerAndCliGuide
            schedule={scheduleConfig}
            webhookConfig={webhookConfig}
            templates={templates}
            onUpdateSchedule={handleUpdateSchedule}
            onTriggerManualScan={() => handleTabChange('scanner')}
          />
        )}

        {/* Tab 9: Dedicated Visual Customizer View */}
        {activeTab === 'visual' && (
          <VisualCustomizer
            settings={visualSettings}
            onChangeSettings={handleSaveVisualSettings}
            onResetDefaults={handleResetVisualDefaults}
            isModal={false}
            onClose={() => handleTabChange('scanner')}
          />
        )}
      </main>

      {/* Modal Visual Customizer */}
      <VisualCustomizer
        settings={visualSettings}
        onChangeSettings={handleSaveVisualSettings}
        onResetDefaults={handleResetVisualDefaults}
        isOpen={isVisualCustomizerOpen}
        onClose={() => setIsVisualCustomizerOpen(false)}
        isModal={true}
      />


      {/* Footer */}
      <footer className="mt-auto border-t border-slate-800/80 py-4 px-6 text-center text-xs text-slate-500 font-mono flex flex-col sm:flex-row items-center justify-between max-w-7xl mx-auto w-full gap-2">
        <div>
          DevSecOps Cybersecurity Auditor · Inspired by OWASP, Nuclei &amp; Burp Suite Pro
        </div>
        <div className="flex items-center gap-4 text-slate-400">
          <span>Linux &amp; WSL Ready</span>
          <span>•</span>
          <span>YAML Declarative Checks</span>
          <span>•</span>
          <span>PDF Reports</span>
        </div>
      </footer>
    </div>
  );
}
