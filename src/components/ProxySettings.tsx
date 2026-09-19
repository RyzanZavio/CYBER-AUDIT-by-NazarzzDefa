import React, { useState } from 'react';
import {
  Shield,
  Radio,
  CheckCircle2,
  AlertTriangle,
  Lock,
  EyeOff,
  Globe,
  RefreshCw,
  Server,
  Zap,
  Save,
  Check,
  Info,
} from 'lucide-react';
import { ProxyConfig } from '../types';

interface ProxySettingsProps {
  config: ProxyConfig;
  onSaveConfig: (config: ProxyConfig) => Promise<void>;
}

export const ProxySettings: React.FC<ProxySettingsProps> = ({ config, onSaveConfig }) => {
  const [proxyData, setProxyData] = useState<ProxyConfig>(config);
  const [isTesting, setIsTesting] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [testResult, setTestResult] = useState<{
    success: boolean;
    message: string;
    outgoingIp?: string;
    latencyMs?: number;
  } | null>(null);
  const [saveSuccess, setSaveSuccess] = useState(false);

  const presets = [
    {
      name: 'Burp Suite Pro',
      url: 'http://127.0.0.1:8080',
      insecureSkipVerify: true,
      desc: 'Route all auditor traffic through Burp Suite proxy for active/passive inspection & repeater.',
    },
    {
      name: 'OWASP ZAP',
      url: 'http://127.0.0.1:8081',
      insecureSkipVerify: true,
      desc: 'Default port for OWASP Zed Attack Proxy local daemon.',
    },
    {
      name: 'Tor SOCKS5 Anonymizer',
      url: 'socks5://127.0.0.1:9050',
      insecureSkipVerify: false,
      desc: 'Route scanner requests through the Tor onion routing network for anonymized egress.',
    },
    {
      name: 'Custom Corporate / Squid',
      url: 'http://proxy.corp.internal:3128',
      insecureSkipVerify: false,
      desc: 'Corporate egress proxy with enterprise authentication.',
    },
  ];

  const handleApplyPreset = (presetUrl: string, insecure: boolean) => {
    setProxyData(prev => ({
      ...prev,
      enabled: true,
      url: presetUrl,
      insecureSkipVerify: insecure,
    }));
  };

  const handleTestProxy = async () => {
    setIsTesting(true);
    setTestResult(null);
    try {
      const res = await fetch('/api/proxy/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(proxyData),
      });
      const data = await res.json();
      setTestResult(data);
    } catch (err: any) {
      setTestResult({
        success: false,
        message: `Proxy test dispatch error: ${err.message}`,
      });
    } finally {
      setIsTesting(false);
    }
  };

  const handleSave = async () => {
    setIsSaving(true);
    setSaveSuccess(false);
    try {
      await onSaveConfig(proxyData);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err) {
      console.error('Failed to save proxy config:', err);
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div id="proxy-settings-view" className="space-y-6 max-w-4xl mx-auto">
      {/* Header card */}
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-2xl shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Radio className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-semibold text-white">
              Upstream Security Proxy &amp; Anonymization
            </h2>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
              BURP · TOR · SOCKS5 · HTTP
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Route all vulnerability audit requests, CLI pipelines, and batch subdomain scans through an upstream proxy for traffic analysis, debugging, or enhanced operational security.
          </p>
        </div>

        {/* Master Toggle */}
        <label className="relative inline-flex items-center cursor-pointer shrink-0">
          <input
            type="checkbox"
            checked={proxyData.enabled}
            onChange={e => setProxyData(prev => ({ ...prev, enabled: e.target.checked }))}
            className="sr-only peer"
          />
          <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-600"></div>
          <span className="ml-3 text-xs font-mono font-medium text-slate-300">
            {proxyData.enabled ? 'PROXY ACTIVE' : 'DIRECT CONNECTION'}
          </span>
        </label>
      </div>

      {/* 1-Click Presets */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex items-center gap-2">
          <Zap className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-semibold text-white uppercase tracking-wider">
            Quick Upstream Presets
          </h3>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {presets.map(preset => (
            <button
              key={preset.name}
              type="button"
              onClick={() => handleApplyPreset(preset.url, preset.insecureSkipVerify)}
              className={`p-3 rounded-xl border text-left transition flex flex-col justify-between ${
                proxyData.url === preset.url && proxyData.enabled
                  ? 'bg-cyan-950/40 border-cyan-500 shadow-md shadow-cyan-950'
                  : 'bg-slate-950/70 border-slate-800 hover:border-slate-700 hover:bg-slate-900'
              }`}
            >
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white">{preset.name}</span>
                  <span className="text-[10px] font-mono text-cyan-400">{preset.url}</span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1 leading-snug">{preset.desc}</p>
              </div>
              <span className="text-[10px] text-cyan-400 font-mono mt-2 flex items-center gap-1">
                Apply Preset &rarr;
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Detailed Configuration Form */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-5">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
          <Server className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-semibold text-white uppercase tracking-wider">
            Upstream Proxy Parameters
          </h3>
        </div>

        <div className="space-y-4 text-xs font-mono">
          {/* Proxy URL */}
          <div className="space-y-1">
            <label className="text-slate-300 font-medium">Proxy URI / Address</label>
            <input
              type="text"
              value={proxyData.url}
              onChange={e => setProxyData(prev => ({ ...prev, url: e.target.value }))}
              placeholder="http://127.0.0.1:8080 or socks5://127.0.0.1:9050"
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            />
            <p className="text-[11px] text-slate-500 font-sans">
              Format: <code className="text-cyan-400">http://host:port</code>, <code className="text-cyan-400">https://host:port</code>, or <code className="text-cyan-400">socks5://host:port</code>.
            </p>
          </div>

          {/* Authentication (Optional) */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
            <div className="space-y-1">
              <label className="text-slate-300 font-medium flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-slate-400" />
                <span>Username (Optional)</span>
              </label>
              <input
                type="text"
                value={proxyData.username || ''}
                onChange={e => setProxyData(prev => ({ ...prev, username: e.target.value }))}
                placeholder="proxy_user"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div className="space-y-1">
              <label className="text-slate-300 font-medium flex items-center gap-1.5">
                <EyeOff className="w-3.5 h-3.5 text-slate-400" />
                <span>Password (Optional)</span>
              </label>
              <input
                type="password"
                value={proxyData.password || ''}
                onChange={e => setProxyData(prev => ({ ...prev, password: e.target.value }))}
                placeholder="••••••••••••"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
          </div>

          {/* Insecure Skip TLS & Spoofed User Agent */}
          <div className="pt-3 border-t border-slate-800/80 space-y-4 font-sans">
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={proxyData.insecureSkipVerify}
                onChange={e =>
                  setProxyData(prev => ({ ...prev, insecureSkipVerify: e.target.checked }))
                }
                className="mt-0.5 rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-cyan-500"
              />
              <div>
                <span className="text-xs font-medium text-slate-200">
                  Allow Untrusted / Self-Signed Proxy TLS Certificates (Burp Suite CA)
                </span>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Essential when routing through Burp Suite or OWASP ZAP without importing their custom CA root certificates into Node's system trust store.
                </p>
              </div>
            </label>

            <div className="space-y-1">
              <label className="text-xs font-medium text-slate-300">Custom User-Agent Spoofing</label>
              <input
                type="text"
                value={proxyData.customUserAgent || ''}
                onChange={e => setProxyData(prev => ({ ...prev, customUserAgent: e.target.value }))}
                placeholder="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36..."
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>
        </div>

        {/* Live Test Feedback Banner */}
        {testResult && (
          <div
            className={`p-4 rounded-xl border text-xs font-mono flex items-start gap-3 ${
              testResult.success
                ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                : 'bg-rose-950/40 border-rose-800 text-rose-300'
            }`}
          >
            {testResult.success ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            )}
            <div>
              <div className="font-bold">{testResult.message}</div>
              {testResult.outgoingIp && (
                <div className="mt-1 text-[11px] text-slate-300">
                  Outgoing Egress IP: <span className="text-cyan-400 font-bold">{testResult.outgoingIp}</span>
                  {testResult.latencyMs && ` · Latency: ${testResult.latencyMs}ms`}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Action Buttons */}
        <div className="pt-4 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
          <button
            type="button"
            onClick={handleTestProxy}
            disabled={isTesting || !proxyData.url}
            className="w-full sm:w-auto px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium flex items-center justify-center gap-2 border border-slate-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isTesting ? 'animate-spin text-cyan-400' : ''}`} />
            <span>{isTesting ? 'Probing Egress Connection...' : 'Test Proxy Tunnel'}</span>
          </button>

          <button
            type="button"
            onClick={handleSave}
            disabled={isSaving}
            className="w-full sm:w-auto px-5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center justify-center gap-2 shadow-lg shadow-cyan-950 transition"
          >
            {saveSuccess ? (
              <>
                <Check className="w-4 h-4 text-emerald-300" />
                <span>Saved &amp; Applied!</span>
              </>
            ) : (
              <>
                <Save className="w-4 h-4" />
                <span>Save &amp; Activate Proxy</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
