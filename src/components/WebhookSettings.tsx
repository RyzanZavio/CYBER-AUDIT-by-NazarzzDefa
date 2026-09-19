import React, { useState } from 'react';
import {
  Bell,
  Send,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
  ExternalLink,
  MessageSquare,
  ShieldAlert,
} from 'lucide-react';
import { VulnerabilitySeverity, WebhookConfig } from '../types';

interface WebhookSettingsProps {
  config: WebhookConfig;
  onSaveConfig: (config: WebhookConfig) => Promise<void>;
  onTestWebhook: (config: WebhookConfig) => Promise<{ success: boolean; message: string }>;
}

export const WebhookSettings: React.FC<WebhookSettingsProps> = ({
  config,
  onSaveConfig,
  onTestWebhook,
}) => {
  const [formConfig, setFormConfig] = useState<WebhookConfig>(config);
  const [isTesting, setIsTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [saveSuccess, setSaveSuccess] = useState(false);

  const handleTest = async () => {
    setIsTesting(true);
    setTestResult(null);
    try {
      const res = await onTestWebhook(formConfig);
      setTestResult(res);
    } catch (err: any) {
      setTestResult({ success: false, message: err.message });
    } finally {
      setIsTesting(false);
    }
  };

  const handleSave = async () => {
    await onSaveConfig(formConfig);
    setSaveSuccess(true);
    setTimeout(() => setSaveSuccess(false), 2500);
  };

  return (
    <div id="webhook-settings-container" className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-5 bg-slate-900 border border-slate-800 rounded-2xl shadow-xl">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Bell className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-semibold text-white">Discord & Slack Webhooks</h2>
            <span className="px-2 py-0.5 text-xs font-mono rounded bg-slate-800 text-slate-300 border border-slate-700">
              Real-Time DevSecOps Alerts
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Dispatch automated notifications to developer channels when vulnerabilities are detected.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {saveSuccess && (
            <span className="text-xs text-emerald-400 font-mono flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> Saved!
            </span>
          )}
          <button
            id="save-webhook-settings-btn"
            onClick={handleSave}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-white shadow-md transition"
          >
            Save Webhook Config
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Configuration form */}
        <div className="lg:col-span-6 space-y-4">
          <div className="p-5 bg-slate-900 border border-slate-800 rounded-2xl space-y-4">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <MessageSquare className="w-4 h-4 text-cyan-400" />
              Webhook Service Setup
            </h3>

            {/* Platform Selector */}
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-2">Notification Platform</label>
              <div className="grid grid-cols-2 gap-3">
                <button
                  type="button"
                  onClick={() => setFormConfig(prev => ({ ...prev, type: 'discord' }))}
                  className={`p-3 rounded-xl border text-xs font-medium flex items-center justify-center gap-2 transition ${
                    formConfig.type === 'discord'
                      ? 'bg-indigo-950/40 border-indigo-500 text-indigo-300 shadow'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:bg-slate-850'
                  }`}
                >
                  <span className="w-2.5 h-2.5 rounded-full bg-indigo-500"></span>
                  Discord Webhook
                </button>

                <button
                  type="button"
                  onClick={() => setFormConfig(prev => ({ ...prev, type: 'slack' }))}
                  className={`p-3 rounded-xl border text-xs font-medium flex items-center justify-center gap-2 transition ${
                    formConfig.type === 'slack'
                      ? 'bg-emerald-950/40 border-emerald-500 text-emerald-300 shadow'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:bg-slate-850'
                  }`}
                >
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
                  Slack Webhook
                </button>
              </div>
            </div>

            {/* Enable switch */}
            <div className="flex items-center justify-between p-3 rounded-xl bg-slate-950 border border-slate-800">
              <div>
                <span className="text-xs font-medium text-white block">Enable Automated Webhook Dispatch</span>
                <span className="text-[11px] text-slate-400">
                  Sends scan summary on daily scheduled runs and on-demand audits.
                </span>
              </div>
              <input
                id="enable-webhook-checkbox"
                type="checkbox"
                checked={formConfig.enabled}
                onChange={e => setFormConfig(prev => ({ ...prev, enabled: e.target.checked }))}
                className="w-4 h-4 rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0 cursor-pointer"
              />
            </div>

            {/* Webhook URL Input */}
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                {formConfig.type === 'discord' ? 'Discord Webhook URL' : 'Slack Incoming Webhook URL'}
              </label>
              <input
                id="webhook-url-input"
                type="url"
                value={formConfig.url}
                onChange={e => setFormConfig(prev => ({ ...prev, url: e.target.value }))}
                placeholder={
                  formConfig.type === 'discord'
                    ? 'https://discord.com/api/webhooks/...'
                    : 'https://hooks.slack.com/services/...'
                }
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
              />
              <p className="mt-1 text-[11px] text-slate-500">
                {formConfig.type === 'discord'
                  ? 'Server Settings -> Integrations -> Webhooks -> New Webhook -> Copy Webhook URL'
                  : 'Slack App Directory -> Incoming WebHooks -> Add to Slack -> Copy URL'}
              </p>
            </div>

            {/* Severity Trigger Filter */}
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Minimum Severity to Alert
              </label>
              <select
                id="webhook-min-severity-select"
                value={formConfig.minSeverity}
                onChange={e =>
                  setFormConfig(prev => ({
                    ...prev,
                    minSeverity: e.target.value as VulnerabilitySeverity,
                  }))
                }
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="info">All Findings (Informational, Low, Medium, High, Critical)</option>
                <option value="low">Low & Above</option>
                <option value="medium">Medium & Above (Recommended for DevSecOps)</option>
                <option value="high">High & Critical Only</option>
                <option value="critical">Critical Only (Zero-Tolerance)</option>
              </select>
            </div>

            {/* Test Action */}
            <div className="pt-2 flex items-center justify-between gap-3">
              <button
                id="test-webhook-btn"
                type="button"
                onClick={handleTest}
                disabled={isTesting || !formConfig.url.trim()}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white border border-slate-700 transition"
              >
                <Send className="w-3.5 h-3.5 text-cyan-400" />
                <span>{isTesting ? 'Sending Probe...' : 'Send Test Notification'}</span>
              </button>

              {testResult && (
                <div
                  className={`text-xs flex items-center gap-1.5 font-mono ${
                    testResult.success ? 'text-emerald-400' : 'text-rose-400'
                  }`}
                >
                  {testResult.success ? (
                    <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
                  ) : (
                    <AlertCircle className="w-4 h-4 flex-shrink-0" />
                  )}
                  <span className="truncate max-w-[220px]">{testResult.message}</span>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Right: Mock Payload Card Preview */}
        <div className="lg:col-span-6 space-y-4">
          <div className="p-5 bg-slate-900 border border-slate-800 rounded-2xl space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">Live Channel Message Preview</h3>
              <span className="text-[10px] font-mono text-slate-500 uppercase">
                {formConfig.type} Embed Style
              </span>
            </div>

            {formConfig.type === 'discord' ? (
              /* Discord Embed Mockup */
              <div className="bg-[#313338] p-4 rounded-xl font-sans text-xs text-[#dbdee1] border border-slate-700 shadow-inner space-y-2">
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 rounded-full bg-cyan-600 flex items-center justify-center text-white text-[10px] font-bold">
                    SA
                  </div>
                  <span className="font-semibold text-white text-xs">DevSecOps Audit Bot</span>
                  <span className="px-1 py-0.2 bg-[#5865F2] text-white text-[9px] rounded font-bold">BOT</span>
                  <span className="text-[10px] text-[#949ba4]">Today at 02:00 AM</span>
                </div>

                <p className="text-xs text-[#dbdee1]">
                  🚨 <strong>Security Vulnerability Scan Alert</strong> for <code className="bg-[#2b2d31] px-1 py-0.5 rounded text-[#f2f3f5]">https://target-service.internal</code>
                </p>

                {/* Discord Embed Box */}
                <div className="border-l-4 border-rose-500 bg-[#2b2d31] p-3 rounded-r-lg space-y-2 text-[11px]">
                  <div className="font-bold text-white text-xs">
                    OWASP · Nuclei · Burp Suite Audit Summary
                  </div>
                  <p className="text-[#949ba4]">
                    Automated daily vulnerability audit completed. Total templates: <strong>10</strong>.
                  </p>

                  <div className="grid grid-cols-2 gap-2 pt-1">
                    <div>
                      <span className="text-[#949ba4] block text-[10px]">🎯 Target URL</span>
                      <span className="text-white font-mono text-[10px]">https://target-service.internal</span>
                    </div>
                    <div>
                      <span className="text-[#949ba4] block text-[10px]">📊 Total Findings</span>
                      <span className="text-rose-400 font-bold">2 issues detected</span>
                    </div>
                  </div>

                  <div className="pt-1 border-t border-[#3f4147]">
                    <span className="text-[#949ba4] block text-[10px] mb-1">🔍 Top Identified Vulnerabilities</span>
                    <div className="space-y-0.5 text-[10px]">
                      <div>🔴 <strong>[CRITICAL]</strong> Exposed Environment (.env) Credentials (CWE-200)</div>
                      <div>🟡 <strong>[MEDIUM]</strong> Missing Security Headers: HSTS &amp; CSP (CWE-693)</div>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              /* Slack Block Kit Mockup */
              <div className="bg-[#1a1d21] p-4 rounded-xl font-sans text-xs text-[#d1d2d3] border border-slate-700 shadow-inner space-y-3">
                <div className="flex items-center gap-2">
                  <div className="w-5 h-5 rounded bg-emerald-600 flex items-center justify-center text-white text-[10px] font-bold">
                    S
                  </div>
                  <span className="font-bold text-white">DevSecOps Bot</span>
                  <span className="px-1 py-0.2 bg-[#2c3136] text-[#abacad] text-[9px] rounded">APP</span>
                  <span className="text-[10px] text-[#abacad]">2:00 AM</span>
                </div>

                <div className="font-bold text-white text-sm">
                  🛡️ Security Vulnerability Alert (OWASP / Nuclei)
                </div>

                <div className="grid grid-cols-2 gap-2 text-[11px] border-b border-[#2c3136] pb-2">
                  <div>
                    <span className="text-[#abacad] block text-[10px]">Target:</span>
                    <span className="text-cyan-400 underline">https://target-service.internal</span>
                  </div>
                  <div>
                    <span className="text-[#abacad] block text-[10px]">Total Findings:</span>
                    <span className="text-white font-bold">2 vulnerabilities</span>
                  </div>
                </div>

                <div className="text-[11px] space-y-1">
                  <span className="text-[#abacad] block text-[10px]">Severity Breakdown:</span>
                  <div>• 🔴 Critical: <strong>1</strong></div>
                  <div>• 🟡 Medium: <strong>1</strong></div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
