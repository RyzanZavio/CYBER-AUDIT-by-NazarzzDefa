import React, { useState } from 'react';
import {
  Package,
  Plus,
  Check,
  Power,
  Shield,
  Trash2,
  Download,
  Upload,
  ExternalLink,
  Layers,
  Sparkles,
  AlertCircle,
  FileCode,
  FolderDown,
} from 'lucide-react';
import { ExtensionManifest, YamlTemplate } from '../types';

interface ExtensionManagerProps {
  extensions: ExtensionManifest[];
  onToggleExtension: (id: string, enabled: boolean) => Promise<void>;
  onInstallExtension: (manifest: Partial<ExtensionManifest>) => Promise<void>;
  onDeleteExtension: (id: string) => Promise<void>;
  totalActiveTemplates: number;
}

export const ExtensionManager: React.FC<ExtensionManagerProps> = ({
  extensions,
  onToggleExtension,
  onInstallExtension,
  onDeleteExtension,
  totalActiveTemplates,
}) => {
  const [showInstallModal, setShowInstallModal] = useState(false);
  const [newExtName, setNewExtName] = useState('');
  const [newExtDesc, setNewExtDesc] = useState('');
  const [newExtAuthor, setNewExtAuthor] = useState('');
  const [newExtCategory, setNewExtCategory] = useState<'owasp' | 'burp' | 'nuclei' | 'custom'>('custom');
  const [newExtYaml, setNewExtYaml] = useState('');
  const [importedJson, setImportedJson] = useState('');
  const [installError, setInstallError] = useState<string | null>(null);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = event => {
      const content = event.target?.result as string;
      if (file.name.endsWith('.json')) {
        try {
          const parsed = JSON.parse(content);
          if (parsed.name && parsed.id) {
            setImportedJson(content);
            setNewExtName(parsed.name);
            setNewExtDesc(parsed.description || '');
            setNewExtAuthor(parsed.author || '');
          }
        } catch {
          setInstallError('Invalid JSON structure');
        }
      } else if (file.name.endsWith('.yaml') || file.name.endsWith('.yml')) {
        setNewExtYaml(content);
        if (!newExtName) {
          setNewExtName(file.name.replace(/\.(yaml|yml)$/, ' Extension'));
        }
      }
    };
    reader.readAsText(file);
  };

  const handleCreateExtension = async () => {
    setInstallError(null);
    try {
      if (importedJson) {
        const parsed = JSON.parse(importedJson);
        await onInstallExtension(parsed);
        setShowInstallModal(false);
        resetForm();
        return;
      }

      if (!newExtName.trim()) {
        setInstallError('Extension Name is required');
        return;
      }

      const extId = `ext-${newExtName.toLowerCase().replace(/[^a-z0-9]/g, '-')}-${Date.now().toString(36)}`;
      const templateId = `tpl-${extId}`;

      const templatesList: YamlTemplate[] = newExtYaml.trim()
        ? [
            {
              id: templateId,
              name: `${newExtName} Rule`,
              description: newExtDesc || 'Custom extension rule',
              severity: 'high',
              tags: [newExtCategory, 'extension'],
              author: newExtAuthor || 'DevSecOps Contributor',
              enabled: true,
              isBuiltin: false,
              rawYaml: newExtYaml,
            },
          ]
        : [];

      const manifest: ExtensionManifest = {
        id: extId,
        name: newExtName.trim(),
        version: '1.0.0',
        author: newExtAuthor.trim() || 'Internal Security Engineer',
        description: newExtDesc.trim() || 'Custom imported security rules pack',
        category: newExtCategory,
        installed: true,
        enabled: true,
        templatesCount: templatesList.length,
        templates: templatesList,
      };

      await onInstallExtension(manifest);
      setShowInstallModal(false);
      resetForm();
    } catch (err: any) {
      setInstallError(err.message || 'Failed to install extension');
    }
  };

  const resetForm = () => {
    setNewExtName('');
    setNewExtDesc('');
    setNewExtAuthor('');
    setNewExtYaml('');
    setImportedJson('');
    setInstallError(null);
  };

  const sampleYaml = `id: custom-subdomain-takeover-check
info:
  name: Subdomain Dangling CNAME Detector
  author: DevSecOps-Team
  severity: critical
  description: Detects dangling DNS pointers vulnerable to subdomain hijacking
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "NoSuchBucket"
          - "There is no app configured at that hostname"
          - "project not found"`;

  return (
    <div id="extension-manager-view" className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-2xl shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Package className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-semibold text-white">
              DevSecOps Extension Packs &amp; Custom Modules
            </h2>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
              MODULAR SECURITY REPO
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Extend your scanner with specialized vulnerability engines inspired by Burp BApp Store, Nuclei community templates, and OWASP testing modules.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right hidden sm:block">
            <div className="text-xs font-bold text-cyan-400 font-mono">
              {totalActiveTemplates} Active Rules
            </div>
            <div className="text-[10px] text-slate-500 font-mono">
              {extensions.filter(e => e.enabled).length} packs enabled
            </div>
          </div>

          <button
            id="install-ext-btn"
            onClick={() => setShowInstallModal(true)}
            className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-2 shadow-lg shadow-cyan-950 transition"
          >
            <Plus className="w-4 h-4" />
            <span>Install Extension</span>
          </button>
        </div>
      </div>

      {/* Extensions Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {extensions.map(ext => (
          <div
            key={ext.id}
            className={`p-5 rounded-2xl border transition flex flex-col justify-between ${
              ext.enabled
                ? 'bg-slate-900 border-slate-700 shadow-md'
                : 'bg-slate-900/50 border-slate-800/80 opacity-75'
            }`}
          >
            <div className="space-y-3">
              {/* Card top row */}
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-bold text-white">{ext.name}</h3>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">
                      v{ext.version}
                    </span>
                  </div>
                  <span className="text-[11px] text-slate-400 font-mono">by {ext.author}</span>
                </div>

                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold ${
                    ext.category === 'owasp'
                      ? 'bg-blue-950 text-blue-400 border border-blue-800'
                      : ext.category === 'burp'
                      ? 'bg-amber-950 text-amber-400 border border-amber-800'
                      : ext.category === 'nuclei'
                      ? 'bg-cyan-950 text-cyan-400 border border-cyan-800'
                      : 'bg-purple-950 text-purple-400 border border-purple-800'
                  }`}
                >
                  {ext.category}
                </span>
              </div>

              {/* Description */}
              <p className="text-xs text-slate-300 leading-relaxed">{ext.description}</p>

              {/* Rule count info */}
              <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                <span>
                  {ext.templates?.length || ext.templatesCount || 0} YAML Rules included
                </span>
              </div>
            </div>

            {/* Bottom Actions */}
            <div className="pt-4 border-t border-slate-800 mt-4 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => onToggleExtension(ext.id, !ext.enabled)}
                  className={`px-3 py-1.5 rounded-xl text-xs font-mono font-medium flex items-center gap-1.5 transition ${
                    ext.enabled
                      ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-800 hover:bg-emerald-900/80'
                      : 'bg-slate-800 text-slate-400 hover:bg-slate-700 hover:text-white'
                  }`}
                >
                  <Power className="w-3.5 h-3.5" />
                  <span>{ext.enabled ? 'ENABLED' : 'DISABLED'}</span>
                </button>
              </div>

              {ext.category === 'custom' && (
                <button
                  onClick={() => onDeleteExtension(ext.id)}
                  className="text-xs text-rose-400 hover:text-rose-300 p-1 font-mono flex items-center gap-1 transition"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Uninstall</span>
                </button>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Modal / Dialog to Install Custom Extension */}
      {showInstallModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Package className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-semibold text-white">
                  Install New Security Extension
                </h3>
              </div>
              <button
                onClick={() => {
                  setShowInstallModal(false);
                  resetForm();
                }}
                className="text-slate-500 hover:text-white text-xs font-mono"
              >
                [Close ESC]
              </button>
            </div>

            {installError && (
              <div className="p-3 rounded-xl bg-rose-950/50 border border-rose-800 text-rose-300 text-xs font-mono flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{installError}</span>
              </div>
            )}

            {/* Drag or upload .json or .yaml */}
            <div className="p-4 border border-dashed border-slate-800 hover:border-slate-700 rounded-xl text-center bg-slate-950/60 space-y-1">
              <Upload className="w-5 h-5 text-cyan-400 mx-auto" />
              <div className="text-xs text-slate-300">
                Import extension package from laptop or flash drive
              </div>
              <label className="inline-block cursor-pointer px-3 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 font-mono mt-1 border border-slate-700">
                Choose .json or .yaml file
                <input
                  type="file"
                  accept=".json,.yaml,.yml"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </label>
            </div>

            {/* Manual Extension Definition */}
            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-slate-300 font-medium">Extension Name</label>
                  <input
                    type="text"
                    value={newExtName}
                    onChange={e => setNewExtName(e.target.value)}
                    placeholder="e.g. Subdomain Takeover Pack"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-slate-300 font-medium">Category</label>
                  <select
                    value={newExtCategory}
                    onChange={e => setNewExtCategory(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="custom">Custom Extension</option>
                    <option value="owasp">OWASP Audit</option>
                    <option value="burp">Burp Active Fuzzing</option>
                    <option value="nuclei">Nuclei Community</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-slate-300 font-medium">Description</label>
                <input
                  type="text"
                  value={newExtDesc}
                  onChange={e => setNewExtDesc(e.target.value)}
                  placeholder="Comprehensive detection for dangling CNAMEs, S3 buckets, etc."
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <label className="text-slate-300 font-medium">
                    YAML Security Rule Template (Nuclei syntax)
                  </label>
                  <button
                    type="button"
                    onClick={() => setNewExtYaml(sampleYaml)}
                    className="text-[10px] text-cyan-400 hover:text-cyan-300 font-mono underline"
                  >
                    Paste Sample YAML
                  </button>
                </div>
                <textarea
                  value={newExtYaml}
                  onChange={e => setNewExtYaml(e.target.value)}
                  rows={6}
                  placeholder={sampleYaml}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 font-mono text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => {
                  setShowInstallModal(false);
                  resetForm();
                }}
                className="px-4 py-2 rounded-xl text-xs text-slate-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleCreateExtension}
                className="px-5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-950"
              >
                Install &amp; Activate
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
