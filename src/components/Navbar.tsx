import React from 'react';
import {
  Shield,
  Terminal,
  FileCode,
  Bell,
  Clock,
  AlertCircle,
  FileText,
} from 'lucide-react';
import { VulnerabilityFinding } from '../types';

export type ActiveTab = 'scanner' | 'findings' | 'templates' | 'webhooks' | 'schedule';

interface NavbarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  findingsCount: number;
  criticalCount: number;
  isSchedulerActive: boolean;
  isWebhookActive: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  findingsCount,
  criticalCount,
  isSchedulerActive,
  isWebhookActive,
}) => {
  return (
    <header className="bg-slate-900 border-b border-slate-800 sticky top-0 z-40 backdrop-blur-md bg-slate-900/90">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand */}
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center text-white shadow-lg shadow-cyan-950">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm tracking-wide text-white font-mono">
                  CYBER-AUDIT
                </span>
                <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
                  OWASP · NUCLEI · BURP
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">
                Web Vulnerability Audit &amp; DevSecOps Automation
              </p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="hidden md:flex items-center gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800">
            <button
              id="tab-scanner-btn"
              onClick={() => setActiveTab('scanner')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                activeTab === 'scanner'
                  ? 'bg-cyan-600 text-white shadow'
                  : 'text-slate-400 hover:text-white hover:bg-slate-900'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Scan &amp; Terminal</span>
            </button>

            <button
              id="tab-findings-btn"
              onClick={() => setActiveTab('findings')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                activeTab === 'findings'
                  ? 'bg-cyan-600 text-white shadow'
                  : 'text-slate-400 hover:text-white hover:bg-slate-900'
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Findings</span>
              {findingsCount > 0 && (
                <span
                  className={`ml-1 px-1.5 py-0.2 rounded-full text-[10px] font-mono ${
                    criticalCount > 0
                      ? 'bg-rose-500 text-white font-bold'
                      : 'bg-slate-800 text-cyan-300'
                  }`}
                >
                  {findingsCount}
                </span>
              )}
            </button>

            <button
              id="tab-templates-btn"
              onClick={() => setActiveTab('templates')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                activeTab === 'templates'
                  ? 'bg-cyan-600 text-white shadow'
                  : 'text-slate-400 hover:text-white hover:bg-slate-900'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>YAML Templates</span>
            </button>

            <button
              id="tab-webhooks-btn"
              onClick={() => setActiveTab('webhooks')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                activeTab === 'webhooks'
                  ? 'bg-cyan-600 text-white shadow'
                  : 'text-slate-400 hover:text-white hover:bg-slate-900'
              }`}
            >
              <Bell className="w-3.5 h-3.5" />
              <span>Webhooks</span>
              {isWebhookActive && (
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
              )}
            </button>

            <button
              id="tab-schedule-btn"
              onClick={() => setActiveTab('schedule')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                activeTab === 'schedule'
                  ? 'bg-cyan-600 text-white shadow'
                  : 'text-slate-400 hover:text-white hover:bg-slate-900'
              }`}
            >
              <Clock className="w-3.5 h-3.5" />
              <span>Daily Schedule &amp; CLI</span>
              {isSchedulerActive && (
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
              )}
            </button>
          </nav>

          {/* Right Status Indicators */}
          <div className="flex items-center gap-2 text-xs font-mono">
            <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-[11px] text-slate-400">
              <span className="flex items-center gap-1">
                <span
                  className={`w-2 h-2 rounded-full ${
                    isSchedulerActive ? 'bg-emerald-400' : 'bg-slate-600'
                  }`}
                ></span>
                <span>Daily Cron</span>
              </span>
              <span>·</span>
              <span className="flex items-center gap-1">
                <span
                  className={`w-2 h-2 rounded-full ${
                    isWebhookActive ? 'bg-indigo-400' : 'bg-slate-600'
                  }`}
                ></span>
                <span>Webhook</span>
              </span>
            </div>
          </div>
        </div>

        {/* Mobile Navigation bar */}
        <div className="flex md:hidden overflow-x-auto py-2 gap-1 border-t border-slate-800">
          <button
            onClick={() => setActiveTab('scanner')}
            className={`px-2.5 py-1 rounded text-xs whitespace-nowrap ${
              activeTab === 'scanner' ? 'bg-cyan-600 text-white font-medium' : 'text-slate-400'
            }`}
          >
            Scan &amp; Terminal
          </button>
          <button
            onClick={() => setActiveTab('findings')}
            className={`px-2.5 py-1 rounded text-xs whitespace-nowrap ${
              activeTab === 'findings' ? 'bg-cyan-600 text-white font-medium' : 'text-slate-400'
            }`}
          >
            Findings {findingsCount > 0 ? `(${findingsCount})` : ''}
          </button>
          <button
            onClick={() => setActiveTab('templates')}
            className={`px-2.5 py-1 rounded text-xs whitespace-nowrap ${
              activeTab === 'templates' ? 'bg-cyan-600 text-white font-medium' : 'text-slate-400'
            }`}
          >
            YAML Templates
          </button>
          <button
            onClick={() => setActiveTab('webhooks')}
            className={`px-2.5 py-1 rounded text-xs whitespace-nowrap ${
              activeTab === 'webhooks' ? 'bg-cyan-600 text-white font-medium' : 'text-slate-400'
            }`}
          >
            Webhooks
          </button>
          <button
            onClick={() => setActiveTab('schedule')}
            className={`px-2.5 py-1 rounded text-xs whitespace-nowrap ${
              activeTab === 'schedule' ? 'bg-cyan-600 text-white font-medium' : 'text-slate-400'
            }`}
          >
            Schedule &amp; CLI
          </button>
        </div>
      </div>
    </header>
  );
};
