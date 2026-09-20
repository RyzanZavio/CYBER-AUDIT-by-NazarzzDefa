import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Search,
  ExternalLink,
  Zap,
  CheckCircle2,
  AlertCircle,
  Copy,
  Check,
  RefreshCw,
  Sliders,
  Database,
  Code2,
  Sparkles,
  Info,
  X,
  Lock,
} from 'lucide-react';
import { VulnerabilitySeverity, YamlTemplate } from '../types';

export interface NvdCvssMetrics {
  version: string;
  baseScore: number;
  severity: VulnerabilitySeverity;
  vectorString: string;
  exploitabilityScore?: number;
  impactScore?: number;
  attackVector?: string;
  attackComplexity?: string;
  privilegesRequired?: string;
  userInteraction?: string;
  scope?: string;
  confidentialityImpact?: string;
  integrityImpact?: string;
  availabilityImpact?: string;
}

export interface NvdCveDetail {
  cveId: string;
  name: string;
  description: string;
  publishedDate: string;
  lastModifiedDate: string;
  vulnStatus: string;
  sourceIdentifier: string;
  cvss: NvdCvssMetrics;
  cweId: string;
  cweName?: string;
  owaspCategory: string;
  affectedTech: string;
  cpeConfigurations: string[];
  references: { url: string; source: string; tags?: string[] }[];
  isKev: boolean;
  generatedYamlTemplate?: YamlTemplate;
}

interface NvdLiveInspectorModalProps {
  initialCveId?: string;
  onClose: () => void;
  onImportSuccess?: (cveId: string) => void;
}

export function NvdLiveInspectorModal({
  initialCveId = '',
  onClose,
  onImportSuccess,
}: NvdLiveInspectorModalProps) {
  const [cveInput, setCveInput] = useState(initialCveId || 'CVE-2024-4577');
  const [loading, setLoading] = useState(false);
  const [cveDetail, setCveDetail] = useState<NvdCveDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);
  const [importSuccessMsg, setImportSuccessMsg] = useState<string | null>(null);
  const [copiedVector, setCopiedVector] = useState(false);
  const [activeTab, setActiveTab] = useState<'metrics' | 'yaml' | 'cpe' | 'references'>('metrics');
  const [nvdStatus, setNvdStatus] = useState<{
    connected: boolean;
    apiKeyActive: boolean;
    apiKeyMasked: string;
    rateLimitPer30s: number;
    message: string;
  } | null>(null);

  useEffect(() => {
    fetchNvdStatus();
    if (initialCveId) {
      handleLookup(initialCveId);
    }
  }, [initialCveId]);

  const fetchNvdStatus = async () => {
    try {
      const res = await fetch('/api/nvd/status');
      if (res.ok) {
        const data = await res.json();
        setNvdStatus(data);
      }
    } catch (_) {}
  };

  const handleLookup = async (idToQuery?: string) => {
    const target = (idToQuery || cveInput).trim().toUpperCase();
    if (!target) return;

    setLoading(true);
    setError(null);
    setImportSuccessMsg(null);

    try {
      const res = await fetch(`/api/nvd/lookup/${encodeURIComponent(target)}`);
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || `HTTP ${res.status}: Gagal mengambil data CVE dari NIST NVD`);
      }
      const data: NvdCveDetail = await res.json();
      setCveDetail(data);
    } catch (err: any) {
      setError(err.message || 'Terjadi kesalahan saat memproses permintaan ke NIST NVD.');
      setCveDetail(null);
    } finally {
      setLoading(false);
    }
  };

  const handleImportToDatabase = async () => {
    if (!cveDetail) return;
    setImporting(true);
    setImportSuccessMsg(null);
    setError(null);

    try {
      const res = await fetch('/api/nvd/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cveId: cveDetail.cveId }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || 'Gagal mengimpor CVE ke database lokal');
      }

      const data = await res.json();
      setImportSuccessMsg(data.message || `Berhasil menambahkan ${cveDetail.cveId} ke database scanner!`);
      if (onImportSuccess) {
        onImportSuccess(cveDetail.cveId);
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setImporting(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedVector(true);
    setTimeout(() => setCopiedVector(false), 2000);
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev?.toLowerCase()) {
      case 'critical':
        return 'bg-red-500/20 text-red-300 border-red-500/40';
      case 'high':
        return 'bg-orange-500/20 text-orange-300 border-orange-500/40';
      case 'medium':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'low':
        return 'bg-blue-500/20 text-blue-300 border-blue-500/40';
      default:
        return 'bg-slate-700/40 text-slate-300 border-slate-600';
    }
  };

  const getCvssBarColor = (score: number) => {
    if (score >= 9.0) return 'bg-red-500';
    if (score >= 7.0) return 'bg-orange-500';
    if (score >= 4.0) return 'bg-amber-500';
    return 'bg-blue-500';
  };

  return (
    <div
      id="nvd-live-inspector-modal"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn"
      onClick={onClose}
    >
      <div
        className="w-full max-w-4xl max-h-[90vh] bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl flex flex-col overflow-hidden text-slate-200"
        onClick={e => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-bold text-white font-mono">
                  NIST National Vulnerability Database (NVD) Live API
                </h3>
                <span className="px-2 py-0.5 text-xs font-mono rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> API Key Aktif
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Pencarian real-time skor CVSS v3.1, metrik exploitability, konfigurasi CPE, dan auto-generator template scanner.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* API Key Status Bar */}
        {nvdStatus && (
          <div className="px-6 py-2.5 bg-slate-950/90 border-b border-slate-800 flex items-center justify-between text-xs font-mono text-slate-300">
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1.5 text-emerald-400">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                NVD v2.0 REST Endpoint
              </span>
              <span className="text-slate-500">|</span>
              <span className="text-slate-400">
                Key: <strong className="text-slate-200">{nvdStatus.apiKeyMasked}</strong>
              </span>
              <span className="text-slate-500">|</span>
              <span className="text-cyan-400">Limit: {nvdStatus.rateLimitPer30s} req / 30s</span>
            </div>
            <span className="text-slate-400 hidden sm:inline">{nvdStatus.message}</span>
          </div>
        )}

        {/* Search Input Bar */}
        <div className="p-6 border-b border-slate-800 bg-slate-900/40">
          <form
            onSubmit={e => {
              e.preventDefault();
              handleLookup();
            }}
            className="flex flex-col sm:flex-row gap-3"
          >
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={cveInput}
                onChange={e => setCveInput(e.target.value)}
                placeholder="Masukkan CVE ID (contoh: CVE-2024-4577, CVE-2021-44228, CVE-2023-34362)..."
                className="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-700 rounded-xl text-white placeholder-slate-500 text-sm font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>
            <button
              type="submit"
              disabled={loading || !cveInput.trim()}
              className="flex items-center justify-center gap-2 px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium rounded-xl text-sm transition font-mono cursor-pointer shadow-lg shadow-cyan-600/20"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Mengambil Data...
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4" />
                  Cari di NIST NVD
                </>
              )}
            </button>
          </form>

          {/* Quick Example Pills */}
          <div className="flex flex-wrap items-center gap-2 mt-3 text-xs">
            <span className="text-slate-500 font-mono">Contoh Populer:</span>
            {[
              'CVE-2024-4577',
              'CVE-2024-21413',
              'CVE-2023-34362',
              'CVE-2021-44228',
              'CVE-2024-6387',
              'CVE-2024-27956',
            ].map(example => (
              <button
                key={example}
                onClick={() => {
                  setCveInput(example);
                  handleLookup(example);
                }}
                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 font-mono hover:text-cyan-300 transition cursor-pointer"
              >
                {example}
              </button>
            ))}
          </div>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {error && (
            <div className="p-4 rounded-xl bg-red-950/40 border border-red-800/60 text-red-300 flex items-start gap-3 text-sm">
              <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
              <div>
                <strong className="font-semibold block">Informasi Error NIST NVD:</strong>
                <span>{error}</span>
              </div>
            </div>
          )}

          {importSuccessMsg && (
            <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 flex items-start gap-3 text-sm">
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <strong className="font-semibold block">Berhasil Diimpor:</strong>
                <span>{importSuccessMsg}</span>
              </div>
            </div>
          )}

          {loading && !cveDetail && (
            <div className="py-16 text-center space-y-3">
              <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto" />
              <p className="text-sm font-mono text-slate-400">
                Menghubungi API NIST NVD (services.nvd.nist.gov) menggunakan API Key terotentikasi...
              </p>
            </div>
          )}

          {cveDetail && (
            <div className="space-y-6 animate-fadeIn">
              {/* Top Banner Card */}
              <div className="p-5 rounded-xl bg-slate-950/70 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className="text-2xl font-black font-mono text-white tracking-wide">
                      {cveDetail.cveId}
                    </span>
                    <span
                      className={`px-3 py-0.5 text-xs font-bold uppercase rounded-full border ${getSeverityBadge(
                        cveDetail.cvss.severity
                      )}`}
                    >
                      {cveDetail.cvss.severity} (CVSS {cveDetail.cvss.baseScore.toFixed(1)})
                    </span>
                    <span className="px-2.5 py-0.5 text-xs font-mono rounded bg-slate-800 border border-slate-700 text-slate-300">
                      Status: {cveDetail.vulnStatus}
                    </span>
                    {cveDetail.isKev && (
                      <span className="px-2.5 py-0.5 text-xs font-mono rounded bg-amber-500/20 border border-amber-500/40 text-amber-300 font-bold">
                        CISA KEV
                      </span>
                    )}
                  </div>
                  <h4 className="text-sm font-semibold text-slate-200">{cveDetail.name}</h4>
                  <div className="flex items-center gap-4 text-xs text-slate-400 font-mono">
                    <span>Dirilis: {cveDetail.publishedDate}</span>
                    <span>Diperbarui: {cveDetail.lastModifiedDate}</span>
                    <span>Sumber: {cveDetail.sourceIdentifier}</span>
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <button
                    onClick={handleImportToDatabase}
                    disabled={importing}
                    className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-medium rounded-xl text-sm transition shadow-lg shadow-emerald-600/20 cursor-pointer"
                  >
                    {importing ? (
                      <RefreshCw className="w-4 h-4 animate-spin" />
                    ) : (
                      <Database className="w-4 h-4" />
                    )}
                    Simpan & Aktifkan Template
                  </button>
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${cveDetail.cveId}`}
                    target="_blank"
                    rel="noreferrer"
                    className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded-xl border border-slate-700 transition"
                    title="Buka di Portal Resmi NIST NVD"
                  >
                    <ExternalLink className="w-4 h-4" />
                  </a>
                </div>
              </div>

              {/* Description */}
              <div className="p-4 rounded-xl bg-slate-950/40 border border-slate-800/80">
                <h5 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                  <Info className="w-3.5 h-3.5 text-cyan-400" />
                  Deskripsi Resmi NIST
                </h5>
                <p className="text-sm text-slate-300 leading-relaxed font-sans">{cveDetail.description}</p>
              </div>

              {/* Navigation Tabs */}
              <div className="flex border-b border-slate-800 gap-2">
                <button
                  onClick={() => setActiveTab('metrics')}
                  className={`pb-2 px-3 text-xs font-mono transition border-b-2 ${
                    activeTab === 'metrics'
                      ? 'border-cyan-400 text-cyan-300 font-bold'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Metrik CVSS v{cveDetail.cvss.version} Detail
                </button>
                <button
                  onClick={() => setActiveTab('yaml')}
                  className={`pb-2 px-3 text-xs font-mono transition border-b-2 flex items-center gap-1.5 ${
                    activeTab === 'yaml'
                      ? 'border-cyan-400 text-cyan-300 font-bold'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Code2 className="w-3.5 h-3.5" />
                  Template YAML Tergenerate
                </button>
                <button
                  onClick={() => setActiveTab('cpe')}
                  className={`pb-2 px-3 text-xs font-mono transition border-b-2 ${
                    activeTab === 'cpe'
                      ? 'border-cyan-400 text-cyan-300 font-bold'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Konfigurasi CPE ({cveDetail.cpeConfigurations.length})
                </button>
                <button
                  onClick={() => setActiveTab('references')}
                  className={`pb-2 px-3 text-xs font-mono transition border-b-2 ${
                    activeTab === 'references'
                      ? 'border-cyan-400 text-cyan-300 font-bold'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Referensi Eksternal ({cveDetail.references.length})
                </button>
              </div>

              {/* TAB 1: CVSS METRICS */}
              {activeTab === 'metrics' && (
                <div className="space-y-4">
                  {/* Score Breakdown Bar */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col justify-between">
                      <span className="text-xs font-mono text-slate-400">CVSS v{cveDetail.cvss.version} Base Score</span>
                      <div className="flex items-baseline gap-2 mt-2">
                        <span className="text-4xl font-black font-mono text-white">
                          {cveDetail.cvss.baseScore.toFixed(1)}
                        </span>
                        <span className="text-sm font-bold uppercase text-slate-400">
                          / 10.0 ({cveDetail.cvss.severity})
                        </span>
                      </div>
                      <div className="w-full bg-slate-800 h-2 rounded-full mt-3 overflow-hidden">
                        <div
                          className={`h-full ${getCvssBarColor(cveDetail.cvss.baseScore)}`}
                          style={{ width: `${(cveDetail.cvss.baseScore / 10) * 100}%` }}
                        ></div>
                      </div>
                    </div>

                    <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
                      <span className="text-xs font-mono text-slate-400">Exploitability & Impact</span>
                      <div className="mt-2 space-y-2">
                        <div className="flex justify-between text-xs">
                          <span className="text-slate-400">Exploitability Score:</span>
                          <span className="font-mono font-bold text-cyan-300">
                            {cveDetail.cvss.exploitabilityScore ?? 'N/A'}
                          </span>
                        </div>
                        <div className="flex justify-between text-xs">
                          <span className="text-slate-400">Impact Score:</span>
                          <span className="font-mono font-bold text-orange-300">
                            {cveDetail.cvss.impactScore ?? 'N/A'}
                          </span>
                        </div>
                        <div className="flex justify-between text-xs">
                          <span className="text-slate-400">Kelemahan (CWE):</span>
                          <span className="font-mono font-bold text-slate-200">{cveDetail.cweId}</span>
                        </div>
                      </div>
                    </div>

                    <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
                      <span className="text-xs font-mono text-slate-400">Klasifikasi OWASP & Tech</span>
                      <div className="mt-2 space-y-2">
                        <div className="text-xs">
                          <span className="text-slate-400 block">Kategori OWASP:</span>
                          <span className="font-semibold text-slate-200">{cveDetail.owaspCategory}</span>
                        </div>
                        <div className="text-xs">
                          <span className="text-slate-400 block">Teknologi Terdampak:</span>
                          <span className="font-mono text-cyan-300">{cveDetail.affectedTech}</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* CVSS Vector String */}
                  <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2 overflow-x-auto text-xs font-mono text-cyan-400">
                      <span className="text-slate-500">Vector:</span>
                      <code className="text-slate-200">{cveDetail.cvss.vectorString}</code>
                    </div>
                    <button
                      onClick={() => copyToClipboard(cveDetail.cvss.vectorString)}
                      className="p-1.5 text-slate-400 hover:text-white bg-slate-900 border border-slate-800 rounded-lg shrink-0 transition"
                      title="Salin CVSS Vector String"
                    >
                      {copiedVector ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>

                  {/* CVSS Vectors Matrix */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs font-mono">
                    <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-800">
                      <span className="text-slate-500 block">Attack Vector (AV)</span>
                      <span className="font-bold text-white">{cveDetail.cvss.attackVector || 'NETWORK'}</span>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-800">
                      <span className="text-slate-500 block">Attack Complexity (AC)</span>
                      <span className="font-bold text-white">{cveDetail.cvss.attackComplexity || 'LOW'}</span>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-800">
                      <span className="text-slate-500 block">Privileges Required (PR)</span>
                      <span className="font-bold text-white">{cveDetail.cvss.privilegesRequired || 'NONE'}</span>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-800">
                      <span className="text-slate-500 block">User Interaction (UI)</span>
                      <span className="font-bold text-white">{cveDetail.cvss.userInteraction || 'NONE'}</span>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-800">
                      <span className="text-slate-500 block">Confidentiality (C)</span>
                      <span className="font-bold text-white">{cveDetail.cvss.confidentialityImpact || 'HIGH'}</span>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-800">
                      <span className="text-slate-500 block">Integrity (I)</span>
                      <span className="font-bold text-white">{cveDetail.cvss.integrityImpact || 'HIGH'}</span>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-800">
                      <span className="text-slate-500 block">Availability (A)</span>
                      <span className="font-bold text-white">{cveDetail.cvss.availabilityImpact || 'HIGH'}</span>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-800">
                      <span className="text-slate-500 block">Scope (S)</span>
                      <span className="font-bold text-white">{cveDetail.cvss.scope || 'UNCHANGED'}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 2: YAML TEMPLATE */}
              {activeTab === 'yaml' && cveDetail.generatedYamlTemplate && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                    <span>Nuclei / OWASP YAML Scanner Template (Auto-Generated)</span>
                    <button
                      onClick={() => copyToClipboard(cveDetail.generatedYamlTemplate!.rawYaml)}
                      className="flex items-center gap-1.5 px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition"
                    >
                      <Copy className="w-3.5 h-3.5" />
                      Salin YAML
                    </button>
                  </div>
                  <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-cyan-300 font-mono text-xs overflow-x-auto leading-relaxed max-h-80">
                    {cveDetail.generatedYamlTemplate.rawYaml}
                  </pre>
                </div>
              )}

              {/* TAB 3: CPE CONFIGURATIONS */}
              {activeTab === 'cpe' && (
                <div className="space-y-2">
                  <span className="text-xs text-slate-400 font-mono block">
                    Common Platform Enumeration (CPE) terdaftar di NIST:
                  </span>
                  {cveDetail.cpeConfigurations.length === 0 ? (
                    <p className="text-xs text-slate-500 font-mono py-4">Tidak ada CPE spesifik yang terdaftar.</p>
                  ) : (
                    <div className="space-y-1.5 max-h-60 overflow-y-auto">
                      {cveDetail.cpeConfigurations.map((cpe, idx) => (
                        <div
                          key={idx}
                          className="p-2 rounded bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300"
                        >
                          {cpe}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* TAB 4: REFERENCES */}
              {activeTab === 'references' && (
                <div className="space-y-2">
                  <div className="space-y-1.5 max-h-60 overflow-y-auto">
                    {cveDetail.references.map((ref, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between gap-3 text-xs"
                      >
                        <div className="overflow-hidden">
                          <a
                            href={ref.url}
                            target="_blank"
                            rel="noreferrer"
                            className="font-mono text-cyan-400 hover:underline truncate block"
                          >
                            {ref.url}
                          </a>
                          <span className="text-slate-500 font-mono text-[10px]">
                            Sumber: {ref.source} {ref.tags && ref.tags.length > 0 && `(${ref.tags.join(', ')})`}
                          </span>
                        </div>
                        <ExternalLink className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3.5 bg-slate-950 border-t border-slate-800 flex items-center justify-between">
          <div className="text-xs text-slate-500 font-mono">
            Powered by National Vulnerability Database API 2.0 (NIST)
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded-lg text-xs font-mono transition"
          >
            Tutup
          </button>
        </div>
      </div>
    </div>
  );
}
