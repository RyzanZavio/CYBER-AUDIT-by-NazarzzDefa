import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  Search,
  CheckCircle2,
  ExternalLink,
  Code2,
  SlidersHorizontal,
  Flame,
  Zap,
  Tag,
  AlertCircle,
  Copy,
  Check,
  Cpu,
  Layers,
  Sparkles,
  RefreshCw,
  Globe,
  Database,
} from 'lucide-react';
import { CVE_DATABASE } from '../data/cveDatabase';
import { CveEntry, YamlTemplate } from '../types';
import { NvdLiveInspectorModal } from './NvdLiveInspectorModal';

interface CveDatabaseExplorerProps {
  activeTemplates: YamlTemplate[];
  onToggleTemplate: (templateId: string) => void;
  onEnableAllCves: (cveIds?: string[]) => void;
  onSelectTargetForScan?: (cveTemplateId: string) => void;
}

export function CveDatabaseExplorer({
  activeTemplates,
  onToggleTemplate,
  onEnableAllCves,
}: CveDatabaseExplorerProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedYear, setSelectedYear] = useState<string>('all');
  const [onlyKev, setOnlyKev] = useState(false);
  const [selectedTech, setSelectedTech] = useState<string>('all');
  const [activeCveModal, setActiveCveModal] = useState<CveEntry | null>(null);
  const [copiedYamlId, setCopiedYamlId] = useState<string | null>(null);

  // NIST NVD Live Modal State
  const [nvdModalOpen, setNvdModalOpen] = useState(false);
  const [nvdLookupCveId, setNvdLookupCveId] = useState('');
  const [syncingAllNvd, setSyncingAllNvd] = useState(false);
  const [syncFeedback, setSyncFeedback] = useState<string | null>(null);

  const activeTemplateIdSet = useMemo(() => {
    return new Set(activeTemplates.filter(t => t.enabled).map(t => t.id));
  }, [activeTemplates]);

  const yearOptions = useMemo(() => {
    const years = new Set<string>();
    CVE_DATABASE.forEach(item => {
      const match = item.cveId.match(/CVE-(\d{4})-/i);
      if (match && match[1]) {
        years.add(match[1]);
      }
    });
    return Array.from(years).sort((a, b) => Number(b) - Number(a));
  }, []);

  const techOptions = useMemo(() => {
    const list = new Set<string>();
    CVE_DATABASE.forEach(item => {
      if (item.affectedTech.includes('Apache')) list.add('Apache');
      if (item.affectedTech.includes('Spring')) list.add('Spring');
      if (item.affectedTech.includes('PHP')) list.add('PHP');
      if (item.affectedTech.includes('Confluence') || item.affectedTech.includes('Atlassian')) list.add('Atlassian');
      if (item.affectedTech.includes('Citrix')) list.add('Citrix');
      if (item.affectedTech.includes('F5')) list.add('F5');
      if (item.affectedTech.includes('Grafana')) list.add('Grafana');
      if (item.affectedTech.includes('TeamCity')) list.add('TeamCity');
      if (item.affectedTech.includes('Jenkins')) list.add('Jenkins');
      if (item.affectedTech.includes('MinIO')) list.add('MinIO');
      if (item.affectedTech.includes('Laravel')) list.add('Laravel');
      if (item.affectedTech.includes('Palo Alto') || item.affectedTech.includes('PAN-OS')) list.add('Palo Alto');
      if (item.affectedTech.includes('Ollama') || item.affectedTech.includes('AI')) list.add('AI/LLM (Ollama)');
      if (item.affectedTech.includes('Next.js')) list.add('Next.js');
      if (item.affectedTech.includes('Ivanti')) list.add('Ivanti');
      if (item.affectedTech.includes('Oracle') || item.affectedTech.includes('WebLogic')) list.add('Oracle');
      if (item.affectedTech.includes('Cisco')) list.add('Cisco');
    });
    return Array.from(list);
  }, []);

  const filteredCves = useMemo(() => {
    return CVE_DATABASE.filter(cve => {
      if (onlyKev && !cve.isKev) return false;
      if (selectedSeverity !== 'all' && cve.severity !== selectedSeverity) return false;
      if (selectedYear !== 'all' && !cve.cveId.toUpperCase().includes(`CVE-${selectedYear}-`)) return false;
      if (selectedTech !== 'all' && !cve.affectedTech.toLowerCase().includes(selectedTech.toLowerCase())) return false;

      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesId = cve.cveId.toLowerCase().includes(query);
        const matchesName = cve.name.toLowerCase().includes(query);
        const matchesTech = cve.affectedTech.toLowerCase().includes(query);
        const matchesDesc = cve.description.toLowerCase().includes(query);
        const matchesCwe = cve.cweId.toLowerCase().includes(query);
        return matchesId || matchesName || matchesTech || matchesDesc || matchesCwe;
      }
      return true;
    });
  }, [searchQuery, selectedSeverity, selectedYear, onlyKev, selectedTech]);

  const enabledCount = useMemo(() => {
    return CVE_DATABASE.filter(c => activeTemplateIdSet.has(c.templateId || c.cveId.toLowerCase())).length;
  }, [activeTemplateIdSet]);

  const handleCopyYaml = (cve: CveEntry, yamlText: string) => {
    navigator.clipboard.writeText(yamlText);
    setCopiedYamlId(cve.cveId);
    setTimeout(() => setCopiedYamlId(null), 2000);
  };

  const handleOpenNvdModal = (cveId?: string) => {
    setNvdLookupCveId(cveId || '');
    setNvdModalOpen(true);
  };

  const handleSyncAllNvd = async () => {
    setSyncingAllNvd(true);
    setSyncFeedback(null);
    try {
      const res = await fetch('/api/nvd/sync-all', { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        setSyncFeedback(data.message || `Berhasil memperbarui ${data.updatedCount} skor CVSS dari NIST NVD.`);
      } else {
        setSyncFeedback(`Error: ${data.error || 'Gagal sinkronisasi dengan NIST NVD'}`);
      }
    } catch (err: any) {
      setSyncFeedback(`Error: ${err.message}`);
    } finally {
      setSyncingAllNvd(false);
      setTimeout(() => setSyncFeedback(null), 5000);
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-500/10 text-red-400 border-red-500/30';
      case 'high':
        return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
      case 'medium':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'low':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      default:
        return 'bg-slate-500/10 text-slate-400 border-slate-500/30';
    }
  };

  return (
    <div className="space-y-6" id="cve-database-root">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 bg-slate-900/80 border border-slate-800 rounded-xl">
        <div className="space-y-1">
          <div className="flex items-center gap-2 flex-wrap">
            <ShieldAlert className="w-6 h-6 text-cyan-400" />
            <h2 className="text-xl font-bold text-white tracking-wide">
              CVE Intelligence & Threat Database
            </h2>
            <span className="px-2.5 py-0.5 text-xs font-mono bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 rounded-full">
              {CVE_DATABASE.length} Curated CVEs
            </span>
            <span className="px-2.5 py-0.5 text-xs font-mono bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 rounded-full font-semibold">
              Kurun Waktu: 2020 – 2026
            </span>
          </div>
          <p className="text-sm text-slate-400">
            Database kerentanan CVE berisiko tinggi mencakup kurun waktu <strong className="text-slate-200">2020 hingga 2026</strong> (CISA KEV, RCE, Auth Bypass, Next.js, LLM/AI Exposure) siap pakai dengan template YAML Nuclei tervalidasi.
          </p>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <div className="text-right hidden sm:block">
            <div className="text-xs text-slate-400 font-mono">Status Aktif</div>
            <div className="text-sm font-bold text-emerald-400 font-mono">
              {enabledCount} / {CVE_DATABASE.length} Aktif
            </div>
          </div>
          <button
            id="btn-enable-all-cves"
            onClick={() => onEnableAllCves()}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-medium rounded-lg shadow-lg shadow-cyan-600/20 transition-all text-sm whitespace-nowrap cursor-pointer"
          >
            <Zap className="w-4 h-4" />
            Aktifkan Semua CVE ({CVE_DATABASE.length})
          </button>
        </div>
      </div>

      {/* NIST NVD 2.0 Live Intelligence Bar */}
      <div className="p-4 bg-slate-950/80 border border-cyan-500/30 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shrink-0">
            <Globe className="w-5 h-5" />
          </div>
          <div className="space-y-0.5">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-sm font-bold text-white">NIST NVD Live CVSS & Threat Intel API</span>
              <span className="px-2 py-0.5 text-[10px] font-mono bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 rounded-full flex items-center gap-1 font-semibold">
                <CheckCircle2 className="w-3 h-3" /> NVD API Key Aktif
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Query langsung ke database resmi NIST National Vulnerability Database untuk verifikasi skor CVSS v3.1 & impor CVE baru secara live.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5 shrink-0 flex-wrap">
          <button
            onClick={() => handleOpenNvdModal()}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 rounded-lg text-xs font-mono font-medium transition cursor-pointer"
          >
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            Cari / Inspeksi CVE Live di NIST
          </button>
          <button
            onClick={handleSyncAllNvd}
            disabled={syncingAllNvd}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-300 border border-slate-700 rounded-lg text-xs font-mono font-medium transition cursor-pointer"
            title="Sinkronisasi ulang skor CVSS database lokal dengan NIST NVD API"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${syncingAllNvd ? 'animate-spin text-cyan-400' : ''}`} />
            {syncingAllNvd ? 'Menyinkronkan...' : 'Sinkronkan CVSS'}
          </button>
        </div>
      </div>

      {syncFeedback && (
        <div className="p-3 rounded-lg bg-cyan-950/40 border border-cyan-800/60 text-cyan-300 text-xs font-mono flex items-center gap-2 animate-fadeIn">
          <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>{syncFeedback}</span>
        </div>
      )}

      {/* Filter Bar */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
        {/* Search */}
        <div className="md:col-span-5 relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            id="cve-search-input"
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Cari CVE ID, nama, teknologi (Apache, Spring, Confluence), CWE..."
            className="w-full pl-10 pr-4 py-2.5 bg-slate-900/90 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 text-sm focus:outline-none focus:border-cyan-500 font-mono transition-colors"
          />
        </div>

        {/* Year Filter */}
        <div className="md:col-span-2 relative">
          <select
            id="cve-year-filter"
            value={selectedYear}
            onChange={e => setSelectedYear(e.target.value)}
            className="w-full px-3.5 py-2.5 bg-slate-900/90 border border-slate-800 rounded-lg text-slate-300 text-sm focus:outline-none focus:border-cyan-500 transition-colors font-mono appearance-none cursor-pointer"
          >
            <option value="all">Semua Tahun (2020-2026)</option>
            {yearOptions.map(yr => (
              <option key={yr} value={yr}>
                Tahun {yr}
              </option>
            ))}
          </select>
        </div>

        {/* Severity Filter */}
        <div className="md:col-span-2 relative">
          <select
            id="cve-severity-filter"
            value={selectedSeverity}
            onChange={e => setSelectedSeverity(e.target.value)}
            className="w-full px-3.5 py-2.5 bg-slate-900/90 border border-slate-800 rounded-lg text-slate-300 text-sm focus:outline-none focus:border-cyan-500 transition-colors font-mono appearance-none cursor-pointer"
          >
            <option value="all">Semua Keparahan (All)</option>
            <option value="critical">Critical (CVSS 9.0 - 10.0)</option>
            <option value="high">High (CVSS 7.0 - 8.9)</option>
            <option value="medium">Medium (CVSS 4.0 - 6.9)</option>
          </select>
        </div>

        {/* Tech Stack Filter */}
        <div className="md:col-span-3 relative">
          <select
            id="cve-tech-filter"
            value={selectedTech}
            onChange={e => setSelectedTech(e.target.value)}
            className="w-full px-3.5 py-2.5 bg-slate-900/90 border border-slate-800 rounded-lg text-slate-300 text-sm focus:outline-none focus:border-cyan-500 transition-colors font-mono appearance-none cursor-pointer"
          >
            <option value="all">Semua Teknologi Stack</option>
            {techOptions.map(tech => (
              <option key={tech} value={tech}>
                {tech}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Quick Pills */}
      <div className="space-y-2">
        {/* Year Pills */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-500 font-mono flex items-center gap-1">
            <Tag className="w-3 h-3 text-cyan-400" />
            Tahun Rilis:
          </span>
          <button
            onClick={() => setSelectedYear('all')}
            className={`px-2.5 py-1 rounded-md border font-mono transition-all cursor-pointer ${
              selectedYear === 'all'
                ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300 font-bold'
                : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            Semua (2020-2026)
          </button>
          {yearOptions.map(yr => (
            <button
              key={yr}
              onClick={() => setSelectedYear(selectedYear === yr ? 'all' : yr)}
              className={`px-2.5 py-1 rounded-md border font-mono transition-all cursor-pointer ${
                selectedYear === yr
                  ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300 font-bold'
                  : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              {yr}
            </button>
          ))}
        </div>

        {/* Category & Tech Pills */}
        <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
          <span className="text-slate-500 font-mono">Filter Cepat:</span>
          <button
            onClick={() => setOnlyKev(!onlyKev)}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-md border font-mono transition-all cursor-pointer ${
              onlyKev
                ? 'bg-amber-500/20 border-amber-500/50 text-amber-300 shadow-sm shadow-amber-500/20'
                : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
            }`}
          >
            <Flame className="w-3.5 h-3.5 text-amber-400" />
            CISA KEV Saja
          </button>

          {['Apache', 'Spring', 'PHP', 'Atlassian', 'Citrix', 'F5', 'Jenkins', 'MinIO', 'Palo Alto', 'Next.js'].map(t => (
            <button
              key={t}
              onClick={() => setSelectedTech(selectedTech === t ? 'all' : t)}
              className={`px-2.5 py-1 rounded-md border font-mono transition-all cursor-pointer ${
                selectedTech === t
                  ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300 font-bold'
                  : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              {t}
            </button>
          ))}

          {(searchQuery || selectedSeverity !== 'all' || selectedYear !== 'all' || onlyKev || selectedTech !== 'all') && (
            <button
              onClick={() => {
                setSearchQuery('');
                setSelectedSeverity('all');
                setSelectedYear('all');
                setOnlyKev(false);
                setSelectedTech('all');
              }}
              className="ml-auto text-slate-500 hover:text-slate-300 underline font-mono"
            >
              Reset Filter
            </button>
          )}
        </div>
      </div>

      {/* CVE Grid List */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredCves.map(cve => {
          const tplId = cve.templateId || cve.cveId.toLowerCase();
          const isEnabled = activeTemplateIdSet.has(tplId);

          return (
            <div
              key={cve.cveId}
              id={`cve-card-${cve.cveId.toLowerCase()}`}
              className={`flex flex-col justify-between p-4.5 rounded-xl border transition-all ${
                isEnabled
                  ? 'bg-slate-900/90 border-cyan-500/40 shadow-sm shadow-cyan-500/5'
                  : 'bg-slate-900/50 border-slate-800/80 hover:border-slate-700'
              }`}
            >
              <div className="space-y-3">
                {/* Card Top */}
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-sm font-bold text-white tracking-wide">
                        {cve.cveId}
                      </span>
                      {cve.isKev && (
                        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                          <Flame className="w-3 h-3" /> CISA KEV
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-slate-400 font-medium line-clamp-1 mt-0.5">
                      {cve.affectedTech}
                    </div>
                  </div>

                  <div className="flex flex-col items-end">
                    <span
                      className={`px-2 py-0.5 rounded border text-[11px] font-mono uppercase font-semibold ${getSeverityBadge(
                        cve.severity
                      )}`}
                    >
                      {cve.severity} {cve.cvssScore.toFixed(1)}
                    </span>
                    <span className="text-[10px] font-mono text-emerald-400 mt-0.5">
                      {cve.accuracyRate}% Akurasi
                    </span>
                  </div>
                </div>

                {/* Name & Desc */}
                <div className="space-y-1">
                  <h3 className="text-sm font-semibold text-slate-200 line-clamp-1">
                    {cve.name}
                  </h3>
                  <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
                    {cve.description}
                  </p>
                </div>

                {/* Tags & CWE */}
                <div className="flex items-center gap-1.5 flex-wrap pt-1">
                  <span className="px-2 py-0.5 rounded bg-slate-800/80 text-slate-400 text-[10px] font-mono">
                    {cve.cweId}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-800/80 text-slate-400 text-[10px] font-mono">
                    {cve.owaspCategory.split('-')[0]}
                  </span>
                </div>
              </div>

              {/* Card Footer Actions */}
              <div className="flex items-center justify-between gap-2 pt-4 mt-3 border-t border-slate-800/80 text-xs">
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setActiveCveModal(cve)}
                    className="flex items-center gap-1 text-slate-400 hover:text-cyan-300 font-mono transition-colors cursor-pointer"
                  >
                    <Code2 className="w-3.5 h-3.5" />
                    YAML
                  </button>
                  <button
                    onClick={() => handleOpenNvdModal(cve.cveId)}
                    className="flex items-center gap-1 px-2 py-0.5 rounded bg-cyan-950/40 border border-cyan-800/50 text-cyan-300 hover:text-cyan-200 text-[11px] font-mono transition cursor-pointer"
                    title="Inspeksi Skor CVSS & Detail di NIST NVD Live"
                  >
                    <Sparkles className="w-3 h-3 text-cyan-400" />
                    NIST Live
                  </button>
                </div>

                <button
                  id={`btn-toggle-cve-${cve.cveId.toLowerCase()}`}
                  onClick={() => onToggleTemplate(tplId)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-mono text-xs font-medium transition-all cursor-pointer ${
                    isEnabled
                      ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/20'
                      : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700'
                  }`}
                >
                  {isEnabled ? (
                    <>
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      Aktif dalam Scan
                    </>
                  ) : (
                    <>
                      <Zap className="w-3.5 h-3.5 text-slate-400" />
                      Aktifkan
                    </>
                  )}
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {filteredCves.length === 0 && (
        <div className="p-12 text-center bg-slate-900/40 border border-slate-800 rounded-xl space-y-3">
          <AlertCircle className="w-8 h-8 text-slate-500 mx-auto" />
          <div className="text-slate-300 font-medium">Tidak ada CVE yang sesuai dengan filter</div>
          <p className="text-xs text-slate-500">
            Coba ubah kata kunci pencarian atau reset filter teknologi dan tingkat keparahan.
          </p>
        </div>
      )}

      {/* Detail Modal */}
      {activeCveModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
          <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-5 border-b border-slate-800 bg-slate-950/60">
              <div className="space-y-0.5">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-base font-bold text-cyan-400">
                    {activeCveModal.cveId}
                  </span>
                  {activeCveModal.isKev && (
                    <span className="px-2 py-0.5 text-[11px] font-mono bg-amber-500/10 text-amber-400 border border-amber-500/30 rounded">
                      CISA KEV
                    </span>
                  )}
                  <span
                    className={`px-2 py-0.5 rounded border text-[11px] font-mono uppercase font-semibold ${getSeverityBadge(
                      activeCveModal.severity
                    )}`}
                  >
                    CVSS {activeCveModal.cvssScore} ({activeCveModal.severity})
                  </span>
                </div>
                <div className="text-sm font-medium text-slate-200">
                  {activeCveModal.name}
                </div>
              </div>
              <button
                onClick={() => setActiveCveModal(null)}
                className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
              >
                ✕
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-5 overflow-y-auto space-y-4 text-xs font-mono">
              <div className="space-y-1">
                <span className="text-slate-400 font-bold">AFFECTED TECHNOLOGY:</span>
                <p className="text-slate-200 font-sans text-sm">{activeCveModal.affectedTech}</p>
              </div>

              <div className="space-y-1">
                <span className="text-slate-400 font-bold">DESCRIPTION:</span>
                <p className="text-slate-300 font-sans leading-relaxed text-xs">{activeCveModal.description}</p>
              </div>

              <div className="space-y-1">
                <span className="text-slate-400 font-bold">REMEDIATION GUIDANCE:</span>
                <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg text-slate-300 font-sans leading-relaxed">
                  {activeCveModal.remediation}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2 text-slate-400 text-[11px]">
                <div>
                  <span className="text-slate-500">CWE ID:</span> {activeCveModal.cweId}
                </div>
                <div>
                  <span className="text-slate-500">OWASP Category:</span> {activeCveModal.owaspCategory}
                </div>
                <div>
                  <span className="text-slate-500">Vector:</span> {activeCveModal.vector}
                </div>
                <div>
                  <span className="text-slate-500">Official Advisory:</span>{' '}
                  <a
                    href={activeCveModal.referenceUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="text-cyan-400 hover:underline inline-flex items-center gap-1"
                  >
                    NIST NVD <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>

              {/* YAML Snippet */}
              <div className="space-y-1.5 pt-2">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 font-bold">NUCLEI-COMPLIANT YAML TEMPLATE:</span>
                  <button
                    onClick={() => {
                      const item = CVE_DATABASE.find(c => c.cveId === activeCveModal.cveId);
                      if (item) handleCopyYaml(activeCveModal, item.yamlTemplate.rawYaml);
                    }}
                    className="flex items-center gap-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px] transition-colors cursor-pointer"
                  >
                    {copiedYamlId === activeCveModal.cveId ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-400" /> Disalin!
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" /> Salin YAML
                      </>
                    )}
                  </button>
                </div>
                <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-[11px] text-cyan-300/90 overflow-x-auto max-h-48 leading-tight">
                  {CVE_DATABASE.find(c => c.cveId === activeCveModal.cveId)?.yamlTemplate.rawYaml}
                </pre>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-4 border-t border-slate-800 bg-slate-950/40">
              <div className="flex items-center gap-3">
                <span className="text-xs text-slate-500 font-mono">
                  {activeTemplateIdSet.has(activeCveModal.templateId || activeCveModal.cveId.toLowerCase())
                    ? 'Status: Aktif dalam scanner'
                    : 'Status: Belum diaktifkan'}
                </span>
                <button
                  onClick={() => {
                    const cveId = activeCveModal.cveId;
                    setActiveCveModal(null);
                    handleOpenNvdModal(cveId);
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-950/40 border border-cyan-800/60 text-cyan-300 hover:text-cyan-200 text-xs font-mono transition cursor-pointer"
                >
                  <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                  Inspeksi NIST Live
                </button>
              </div>
              <button
                onClick={() => {
                  const tplId = activeCveModal.templateId || activeCveModal.cveId.toLowerCase();
                  onToggleTemplate(tplId);
                  setActiveCveModal(null);
                }}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-mono font-medium transition-colors cursor-pointer"
              >
                {activeTemplateIdSet.has(activeCveModal.templateId || activeCveModal.cveId.toLowerCase())
                  ? 'Nonaktifkan Template'
                  : 'Aktifkan Template Ini'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* NIST NVD Live Inspector Modal */}
      {nvdModalOpen && (
        <NvdLiveInspectorModal
          initialCveId={nvdLookupCveId}
          onClose={() => setNvdModalOpen(false)}
          onImportSuccess={cveId => {
            onEnableAllCves([cveId.toLowerCase()]);
          }}
        />
      )}
    </div>
  );
}
