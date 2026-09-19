import React, { useState } from 'react';
import {
  Calendar,
  Clock,
  Terminal,
  Copy,
  Check,
  Download,
  Play,
  Server,
  Code,
  Shield,
  RefreshCw,
  ExternalLink,
  GitBranch,
  FolderGit2,
  Cpu,
  Layers,
} from 'lucide-react';
import { ScheduleConfig, WebhookConfig, YamlTemplate } from '../types';

interface SchedulerAndCliGuideProps {
  schedule: ScheduleConfig;
  webhookConfig: WebhookConfig;
  templates: YamlTemplate[];
  onUpdateSchedule: (schedule: Partial<ScheduleConfig>) => Promise<void>;
  onTriggerManualScan?: () => void;
}

type CliMethod = 'wget' | 'git' | 'curl' | 'cron' | 'cicd';

export const SchedulerAndCliGuide: React.FC<SchedulerAndCliGuideProps> = ({
  schedule,
  webhookConfig,
  templates,
  onUpdateSchedule,
  onTriggerManualScan,
}) => {
  const [formSchedule, setFormSchedule] = useState<ScheduleConfig>(schedule);
  const [copiedSection, setCopiedSection] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const [selectedMethod, setSelectedMethod] = useState<CliMethod>('wget');

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(id);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const handleSaveSchedule = async () => {
    setIsSaving(true);
    try {
      await onUpdateSchedule(formSchedule);
    } finally {
      setIsSaving(false);
    }
  };

  const currentHost = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000';
  const targetDemo = formSchedule.targetUrl || 'https://mywebsite.com';

  // Commands
  const wgetPipeCommand = `wget -qO- ${currentHost}/install.sh | bash -s -- -u ${targetDemo}`;
  const wgetDownloadCommand = `wget -q ${currentHost}/cyber-audit && chmod +x cyber-audit && ./cyber-audit -u ${targetDemo}`;
  
  const curlPipeCommand = `curl -sSL ${currentHost}/install.sh | bash -s -- -u ${targetDemo}`;
  const curlGlobalInstall = `curl -sSL ${currentHost}/install.sh | sudo bash -s -- --install`;

  const gitGlobalSetup = `sudo curl -sSL ${currentHost}/cyber-audit -o /usr/local/bin/git-audit && sudo chmod +x /usr/local/bin/git-audit`;
  const gitRunCommand = `git audit -u ${targetDemo}`;
  const gitHookCommand = `# Add to .git/hooks/pre-commit or pre-push:
./cyber-audit -u ${targetDemo} --output audit-precommit.json || exit 1`;

  const cronCommand = `0 ${parseInt(formSchedule.timeString.split(':')[1] || '0', 10)} ${parseInt(
    formSchedule.timeString.split(':')[0] || '2',
    10
  )} * * * /usr/local/bin/cyber-audit -u ${targetDemo} >> /var/log/cyber-audit-daily.log 2>&1`;

  const githubActionsYaml = `name: Daily Cybersecurity Vulnerability Audit
on:
  schedule:
    - cron: '0 2 * * *' # Daily at 02:00 AM UTC
  workflow_dispatch:

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Download & Run DevSecOps Auditor via wget
        run: |
          wget -qO- ${currentHost}/install.sh | bash -s -- -u "\${{ secrets.STAGING_APP_URL }}" -o audit-report.json
      - name: Archive Audit Report
        uses: actions/upload-artifact@v4
        with:
          name: security-audit-report
          path: audit-report.json
`;

  return (
    <div id="scheduler-cli-guide-container" className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-5 bg-slate-900 border border-slate-800 rounded-2xl shadow-xl">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Clock className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-semibold text-white">
              Terminal Call Suite (git, wget, curl) &amp; Daily Automation
            </h2>
            <span className="px-2 py-0.5 text-xs font-mono rounded bg-slate-800 text-slate-300 border border-slate-700">
              Linux / WSL Ready
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Execute security audits directly from your terminal using <code className="text-cyan-300">wget</code>, <code className="text-cyan-300">curl</code>, or custom <code className="text-cyan-300">git audit</code> commands.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <a
            href="/cyber-audit"
            download="cyber-audit"
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download Binary</span>
          </a>
          <button
            id="save-daily-schedule-btn"
            onClick={handleSaveSchedule}
            disabled={isSaving}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-medium bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white shadow-md transition"
          >
            {isSaving ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Clock className="w-3.5 h-3.5" />}
            <span>Save Schedule</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Schedule Setup */}
        <div className="lg:col-span-5 space-y-4">
          <div className="p-5 bg-slate-900 border border-slate-800 rounded-2xl space-y-4 shadow-lg">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Calendar className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-white">Daily Automated Cron Scheduler</h3>
              </div>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                  formSchedule.enabled
                    ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800'
                    : 'bg-slate-800 text-slate-400 border-slate-700'
                }`}
              >
                {formSchedule.enabled ? 'ACTIVE' : 'PAUSED'}
              </span>
            </div>

            {/* Toggle active */}
            <div className="flex items-center justify-between p-3 rounded-xl bg-slate-950 border border-slate-800">
              <div>
                <span className="text-xs font-medium text-white block">Automated Daily Scan Status</span>
                <span className="text-[11px] text-slate-400">
                  Daemon executes every 24 hours continuously on background server.
                </span>
              </div>
              <input
                id="toggle-schedule-enabled-checkbox"
                type="checkbox"
                checked={formSchedule.enabled}
                onChange={e => setFormSchedule(prev => ({ ...prev, enabled: e.target.checked }))}
                className="w-4 h-4 rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0 cursor-pointer"
              />
            </div>

            {/* Daily Execution Time */}
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Daily Execution Time (24h format, Local / Server Time)
              </label>
              <input
                id="daily-time-input"
                type="time"
                value={formSchedule.timeString}
                onChange={e => setFormSchedule(prev => ({ ...prev, timeString: e.target.value }))}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
              <p className="mt-1 text-[11px] text-slate-500 font-mono">
                Cron: <span className="text-cyan-300">{formSchedule.cronExpression || '0 2 * * *'}</span> (Every day at {formSchedule.timeString})
              </p>
            </div>

            {/* Target URL */}
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Target Website / Host for Daily Audit
              </label>
              <input
                id="daily-target-url-input"
                type="url"
                value={formSchedule.targetUrl}
                onChange={e => setFormSchedule(prev => ({ ...prev, targetUrl: e.target.value }))}
                placeholder="https://mywebsite.com"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            {/* Webhook alert toggle */}
            <div className="flex items-center justify-between p-3 rounded-xl bg-slate-950 border border-slate-800">
              <div>
                <span className="text-xs font-medium text-white block">Dispatch Real-Time Webhook Alert</span>
                <span className="text-[11px] text-slate-400">
                  Deliver results directly to Discord or Slack after each scheduled audit.
                </span>
              </div>
              <input
                id="schedule-notify-webhook-checkbox"
                type="checkbox"
                checked={formSchedule.notifyWebhook}
                onChange={e => setFormSchedule(prev => ({ ...prev, notifyWebhook: e.target.checked }))}
                className="w-4 h-4 rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0 cursor-pointer"
              />
            </div>

            {/* Scheduler Status Box */}
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono space-y-1.5">
              <div className="flex items-center justify-between text-slate-400">
                <span>Scheduler State:</span>
                <span className="text-cyan-400">{schedule.status.toUpperCase()}</span>
              </div>
              <div className="flex items-center justify-between text-slate-400">
                <span>Last Status:</span>
                <span className="text-slate-300 truncate max-w-[200px]">{schedule.lastStatus || 'Daily scan ready'}</span>
              </div>
              <div className="flex items-center justify-between text-slate-400 pt-1 border-t border-slate-800/80">
                <span>Frequency:</span>
                <span className="text-emerald-400">Daily at {formSchedule.timeString}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Multi-Protocol Terminal Invocation Guide */}
        <div className="lg:col-span-7 space-y-4">
          <div className="p-5 bg-slate-900 border border-slate-800 rounded-2xl space-y-4 shadow-lg">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-white">Call into Linux &amp; WSL Terminal</h3>
              </div>
              <span className="text-[11px] text-slate-400 font-mono">
                Select your preferred terminal tool:
              </span>
            </div>

            {/* Method Selector Tabs */}
            <div className="flex flex-wrap gap-1 p-1 bg-slate-950 rounded-xl border border-slate-800 text-xs font-mono">
              <button
                type="button"
                onClick={() => setSelectedMethod('wget')}
                className={`px-3 py-1.5 rounded-lg font-semibold transition ${
                  selectedMethod === 'wget'
                    ? 'bg-cyan-600 text-white shadow'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                wget
              </button>
              <button
                type="button"
                onClick={() => setSelectedMethod('git')}
                className={`px-3 py-1.5 rounded-lg font-semibold transition ${
                  selectedMethod === 'git'
                    ? 'bg-cyan-600 text-white shadow'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                git (git audit)
              </button>
              <button
                type="button"
                onClick={() => setSelectedMethod('curl')}
                className={`px-3 py-1.5 rounded-lg font-semibold transition ${
                  selectedMethod === 'curl'
                    ? 'bg-cyan-600 text-white shadow'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                curl
              </button>
              <button
                type="button"
                onClick={() => setSelectedMethod('cron')}
                className={`px-3 py-1.5 rounded-lg font-semibold transition ${
                  selectedMethod === 'cron'
                    ? 'bg-cyan-600 text-white shadow'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                crontab -e
              </button>
              <button
                type="button"
                onClick={() => setSelectedMethod('cicd')}
                className={`px-3 py-1.5 rounded-lg font-semibold transition ${
                  selectedMethod === 'cicd'
                    ? 'bg-cyan-600 text-white shadow'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                CI/CD Action
              </button>
            </div>

            {/* METHOD 1: WGET */}
            {selectedMethod === 'wget' && (
              <div className="space-y-3">
                <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 text-xs text-slate-300">
                  <span className="font-semibold text-white">Call via WGET:</span> Perfect for standard Linux distributions, headless servers, and minimal containers where only wget is pre-installed.
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-300">
                      Option A: Instant One-Line Scan (No file saved to disk):
                    </span>
                    <button
                      onClick={() => handleCopy(wgetPipeCommand, 'wget-pipe')}
                      className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
                    >
                      {copiedSection === 'wget-pipe' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedSection === 'wget-pipe' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-cyan-300 overflow-x-auto select-all">
                    {wgetPipeCommand}
                  </pre>
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-300">
                      Option B: Download Executable Binary &amp; Run:
                    </span>
                    <button
                      onClick={() => handleCopy(wgetDownloadCommand, 'wget-down')}
                      className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
                    >
                      {copiedSection === 'wget-down' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedSection === 'wget-down' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-emerald-300 overflow-x-auto select-all">
                    {wgetDownloadCommand}
                  </pre>
                </div>
              </div>
            )}

            {/* METHOD 2: GIT AUDIT */}
            {selectedMethod === 'git' && (
              <div className="space-y-3">
                <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 text-xs text-slate-300">
                  <div className="flex items-center gap-1.5 text-white font-semibold mb-1">
                    <FolderGit2 className="w-4 h-4 text-cyan-400" />
                    <span>Native Git Subcommand Integration</span>
                  </div>
                  Git automatically recognizes executables named <code className="text-cyan-300">git-audit</code> located in your system PATH. Once installed, developers can simply type <code className="text-emerald-400">git audit</code> anywhere!
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-300">
                      1. Install 'git-audit' into Linux / WSL PATH:
                    </span>
                    <button
                      onClick={() => handleCopy(gitGlobalSetup, 'git-setup')}
                      className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
                    >
                      {copiedSection === 'git-setup' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedSection === 'git-setup' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-cyan-300 overflow-x-auto select-all">
                    {gitGlobalSetup}
                  </pre>
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-300">
                      2. Call from ANY Terminal as a Native Git Command:
                    </span>
                    <button
                      onClick={() => handleCopy(gitRunCommand, 'git-run')}
                      className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
                    >
                      {copiedSection === 'git-run' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedSection === 'git-run' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-[12px] font-mono text-emerald-300 overflow-x-auto select-all font-bold">
                    {gitRunCommand}
                  </pre>
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-300">
                      3. Git Pre-Commit Security Guard (.git/hooks/pre-commit):
                    </span>
                    <button
                      onClick={() => handleCopy(gitHookCommand, 'git-hook')}
                      className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
                    >
                      {copiedSection === 'git-hook' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedSection === 'git-hook' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-[10px] font-mono text-amber-300/90 overflow-x-auto select-all">
                    {gitHookCommand}
                  </pre>
                </div>
              </div>
            )}

            {/* METHOD 3: CURL */}
            {selectedMethod === 'curl' && (
              <div className="space-y-3">
                <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 text-xs text-slate-300">
                  <span className="font-semibold text-white">Call via CURL:</span> Standard POSIX-compliant execution for Linux, WSL, macOS, and automated build scripts.
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-300">
                      Option A: Pipe Directly to Bash:
                    </span>
                    <button
                      onClick={() => handleCopy(curlPipeCommand, 'curl-pipe')}
                      className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
                    >
                      {copiedSection === 'curl-pipe' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedSection === 'curl-pipe' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-cyan-300 overflow-x-auto select-all">
                    {curlPipeCommand}
                  </pre>
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-300">
                      Option B: Global System-Wide Installation (/usr/local/bin):
                    </span>
                    <button
                      onClick={() => handleCopy(curlGlobalInstall, 'curl-global')}
                      className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
                    >
                      {copiedSection === 'curl-global' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedSection === 'curl-global' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-emerald-300 overflow-x-auto select-all">
                    {curlGlobalInstall}
                  </pre>
                </div>
              </div>
            )}

            {/* METHOD 4: CRONTAB */}
            {selectedMethod === 'cron' && (
              <div className="space-y-3">
                <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 text-xs text-slate-300">
                  <span className="font-semibold text-white">Daily Linux/WSL Crontab Automation:</span> Automate security audits on your Linux server or developer workstation every day without manual intervention.
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-300">
                      Paste into <code className="text-cyan-300">crontab -e</code> (Runs daily at {formSchedule.timeString}):
                    </span>
                    <button
                      onClick={() => handleCopy(cronCommand, 'cron-tab')}
                      className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
                    >
                      {copiedSection === 'cron-tab' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedSection === 'cron-tab' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-amber-300/90 overflow-x-auto select-all">
                    {cronCommand}
                  </pre>
                </div>
              </div>
            )}

            {/* METHOD 5: CI/CD */}
            {selectedMethod === 'cicd' && (
              <div className="space-y-3">
                <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 text-xs text-slate-300">
                  <span className="font-semibold text-white">CI/CD Automated Security Pipeline:</span> Run scans on pull requests, deployment events, or daily schedule via GitHub Actions.
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-300">
                      .github/workflows/security-audit.yml:
                    </span>
                    <button
                      onClick={() => handleCopy(githubActionsYaml, 'gh-actions')}
                      className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
                    >
                      {copiedSection === 'gh-actions' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedSection === 'gh-actions' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <div className="max-h-44 overflow-y-auto p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-300 scrollbar-thin">
                    <pre>{githubActionsYaml}</pre>
                  </div>
                </div>
              </div>
            )}

            {/* CLI Flags Summary */}
            <div className="pt-2 border-t border-slate-800">
              <span className="text-xs font-semibold text-slate-300 block mb-1.5">CLI Execution Flags Reference:</span>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px] font-mono">
                <div className="p-2 bg-slate-950 rounded-lg border border-slate-800">
                  <span className="text-cyan-400 block">-u, --target</span>
                  <span className="text-slate-400">Target host URL</span>
                </div>
                <div className="p-2 bg-slate-950 rounded-lg border border-slate-800">
                  <span className="text-cyan-400 block">--discord</span>
                  <span className="text-slate-400">Discord webhook</span>
                </div>
                <div className="p-2 bg-slate-950 rounded-lg border border-slate-800">
                  <span className="text-cyan-400 block">--slack</span>
                  <span className="text-slate-400">Slack webhook</span>
                </div>
                <div className="p-2 bg-slate-950 rounded-lg border border-slate-800">
                  <span className="text-cyan-400 block">-o, --output</span>
                  <span className="text-slate-400">Save JSON file</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
