import React, { useState } from 'react';
import {
  Code,
  Plus,
  RotateCcw,
  Save,
  Trash2,
  Check,
  AlertCircle,
  FileCode,
  Layers,
  Sparkles,
  Search,
} from 'lucide-react';
import * as yaml from 'js-yaml';
import { VulnerabilitySeverity, YamlTemplate } from '../types';

interface TemplateManagerProps {
  templates: YamlTemplate[];
  onUpdateTemplate: (template: YamlTemplate) => Promise<void>;
  onDeleteTemplate: (id: string) => Promise<void>;
  onResetDefaults: () => Promise<void>;
}

export const TemplateManager: React.FC<TemplateManagerProps> = ({
  templates,
  onUpdateTemplate,
  onDeleteTemplate,
  onResetDefaults,
}) => {
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>(
    templates[0]?.id || 'owasp-security-headers'
  );
  const [editingYaml, setEditingYaml] = useState<string>(
    templates[0]?.rawYaml || ''
  );
  const [yamlError, setYamlError] = useState<string | null>(null);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [isCreatingNew, setIsCreatingNew] = useState(false);
  const [searchFilter, setSearchFilter] = useState('');

  const selectedTemplate = templates.find(t => t.id === selectedTemplateId);

  const handleSelectTemplate = (tpl: YamlTemplate) => {
    setSelectedTemplateId(tpl.id);
    setEditingYaml(tpl.rawYaml);
    setYamlError(null);
    setIsCreatingNew(false);
  };

  const handleToggleEnabled = async (tpl: YamlTemplate, e: React.MouseEvent) => {
    e.stopPropagation();
    await onUpdateTemplate({ ...tpl, enabled: !tpl.enabled });
  };

  const handleYamlChange = (value: string) => {
    setEditingYaml(value);
    setSaveSuccess(false);
    try {
      yaml.load(value);
      setYamlError(null);
    } catch (err: any) {
      setYamlError(err.message);
    }
  };

  const handleSave = async () => {
    try {
      const parsed: any = yaml.load(editingYaml);
      if (!parsed || !parsed.id) {
        setYamlError('Template YAML must include an "id" field.');
        return;
      }

      const tplSeverity = (parsed?.info?.severity || 'medium') as VulnerabilitySeverity;
      const tplName = parsed?.info?.name || parsed.id;
      const tplDesc = parsed?.info?.description || 'Custom security audit template';
      const tags = (parsed?.info?.tags || 'custom')
        .split(',')
        .map((s: string) => s.trim());

      const updated: YamlTemplate = {
        id: parsed.id,
        name: tplName,
        severity: tplSeverity,
        description: tplDesc,
        tags,
        enabled: true,
        isBuiltin: selectedTemplate?.isBuiltin && !isCreatingNew,
        rawYaml: editingYaml,
      };

      await onUpdateTemplate(updated);
      setSelectedTemplateId(updated.id);
      setIsCreatingNew(false);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 2500);
    } catch (err: any) {
      setYamlError(`Invalid YAML structure: ${err.message}`);
    }
  };

  const handleStartNewTemplate = () => {
    const newId = `custom-probe-${Date.now().toString(36)}`;
    const templateBoilerplate = `id: ${newId}
info:
  name: Custom Web Vulnerability Probe
  author: secops-team
  severity: medium
  description: Checks for custom misconfigurations or sensitive administrative endpoints.
  reference:
    - https://owasp.org/www-project-top-ten/
  tags: custom,audit,devsecops
  classification:
    cvss-score: 5.5
    cwe-id: CWE-200
    owasp-category: A05:2021-Security Misconfiguration

requests:
  - method: GET
    path:
      - "{{BaseURL}}/admin/health"
      - "{{BaseURL}}/api/debug"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "debug"
          - "secret"
        condition: or
`;
    setSelectedTemplateId(newId);
    setEditingYaml(templateBoilerplate);
    setIsCreatingNew(true);
    setYamlError(null);
  };

  const filteredTemplates = templates.filter(t => {
    const q = searchFilter.toLowerCase();
    return (
      t.name.toLowerCase().includes(q) ||
      t.id.toLowerCase().includes(q) ||
      t.tags.some(tag => tag.toLowerCase().includes(q))
    );
  });

  return (
    <div id="template-manager-container" className="space-y-6">
      {/* Top action header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-5 bg-slate-900 border border-slate-800 rounded-2xl shadow-xl">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <FileCode className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-semibold text-white">YAML Automation Templates</h2>
            <span className="px-2 py-0.5 text-xs font-mono rounded bg-slate-800 text-slate-300 border border-slate-700">
              Nuclei v3 & OWASP Engine
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Define declarative security rules with HTTP requests, status codes, and multi-part matchers.
          </p>
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <button
            id="new-template-btn"
            onClick={handleStartNewTemplate}
            className="flex-1 sm:flex-initial inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-white shadow-md transition"
          >
            <Plus className="w-4 h-4" />
            <span>New YAML Template</span>
          </button>
          <button
            id="reset-templates-btn"
            onClick={onResetDefaults}
            title="Reset to OWASP/Nuclei built-in templates"
            className="p-2 rounded-xl text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Main split view: Template list on left, Editor on right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left column: Template Directory */}
        <div className="lg:col-span-4 space-y-3">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-slate-500" />
            <input
              type="text"
              value={searchFilter}
              onChange={e => setSearchFilter(e.target.value)}
              placeholder="Search templates or tags..."
              className="w-full pl-9 pr-3 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="space-y-2 max-h-[580px] overflow-y-auto pr-1 scrollbar-thin scrollbar-thumb-slate-800">
            {filteredTemplates.map(tpl => {
              const isSelected = tpl.id === selectedTemplateId && !isCreatingNew;
              const severityColor =
                tpl.severity === 'critical'
                  ? 'text-rose-400'
                  : tpl.severity === 'high'
                  ? 'text-orange-400'
                  : tpl.severity === 'medium'
                  ? 'text-amber-400'
                  : 'text-blue-400';

              return (
                <div
                  key={tpl.id}
                  onClick={() => handleSelectTemplate(tpl)}
                  className={`p-3 rounded-xl border cursor-pointer transition select-none flex flex-col gap-1.5 ${
                    isSelected
                      ? 'bg-slate-800/90 border-cyan-500 shadow-md'
                      : 'bg-slate-900/70 border-slate-800 hover:bg-slate-800/40'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-semibold text-white truncate max-w-[200px]">
                      {tpl.name}
                    </span>
                    <input
                      type="checkbox"
                      checked={tpl.enabled}
                      onChange={e => handleToggleEnabled(tpl, e as any)}
                      title={tpl.enabled ? 'Enabled in audit' : 'Disabled'}
                      className="rounded bg-slate-950 border-slate-700 text-cyan-500 focus:ring-0 cursor-pointer"
                    />
                  </div>

                  <div className="flex items-center justify-between text-[11px]">
                    <span className={`font-mono font-semibold uppercase ${severityColor}`}>
                      {tpl.severity}
                    </span>
                    <span className="font-mono text-slate-500 text-[10px]">{tpl.id}</span>
                  </div>

                  <div className="flex flex-wrap gap-1 mt-0.5">
                    {tpl.tags.slice(0, 3).map((tag, tagIdx) => (
                      <span
                        key={tagIdx}
                        className="px-1.5 py-0.5 rounded bg-slate-950 text-slate-400 text-[9px] font-mono border border-slate-800"
                      >
                        #{tag}
                      </span>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right column: YAML Editor & Inspector */}
        <div className="lg:col-span-8 flex flex-col bg-slate-950 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl h-[620px]">
          {/* Editor Header */}
          <div className="flex items-center justify-between px-4 py-3 bg-slate-900 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Code className="w-4 h-4 text-cyan-400" />
              <span className="font-mono text-xs font-bold text-white">
                {isCreatingNew ? 'NEW_TEMPLATE.yaml' : `${selectedTemplateId}.yaml`}
              </span>
              {selectedTemplate?.isBuiltin && !isCreatingNew && (
                <span className="px-1.5 py-0.2 rounded text-[9px] bg-slate-800 text-slate-400 border border-slate-700 font-mono">
                  BUILTIN
                </span>
              )}
            </div>

            <div className="flex items-center gap-2">
              {saveSuccess && (
                <span className="text-xs text-emerald-400 flex items-center gap-1 font-mono">
                  <Check className="w-3.5 h-3.5" /> Saved!
                </span>
              )}

              {selectedTemplate && !selectedTemplate.isBuiltin && !isCreatingNew && (
                <button
                  onClick={() => onDeleteTemplate(selectedTemplate.id)}
                  title="Delete custom template"
                  className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-rose-400 transition"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              )}

              <button
                id="save-yaml-template-btn"
                onClick={handleSave}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-white shadow transition"
              >
                <Save className="w-3.5 h-3.5" />
                <span>Save Template</span>
              </button>
            </div>
          </div>

          {/* Validation Warning if YAML syntax error */}
          {yamlError && (
            <div className="px-4 py-2 bg-rose-950/70 border-b border-rose-800 text-rose-300 text-xs flex items-center gap-2 font-mono">
              <AlertCircle className="w-4 h-4 flex-shrink-0 text-rose-400" />
              <span className="truncate">{yamlError}</span>
            </div>
          )}

          {/* Code Area */}
          <div className="flex-1 p-3 bg-slate-950 font-mono text-xs overflow-hidden flex flex-col">
            <textarea
              id="yaml-editor-textarea"
              value={editingYaml}
              onChange={e => handleYamlChange(e.target.value)}
              spellCheck={false}
              className="w-full flex-1 p-3 bg-transparent text-slate-200 resize-none focus:outline-none font-mono text-xs leading-relaxed selection:bg-cyan-900/60"
            />
          </div>

          {/* Editor Footer / Info Guide */}
          <div className="px-4 py-2 bg-slate-900/90 border-t border-slate-800 flex items-center justify-between text-[11px] font-mono text-slate-500">
            <span>Supported: GET, POST, matchers: status, word, regex, header, negative</span>
            <span>Nuclei Compatible Syntax</span>
          </div>
        </div>
      </div>
    </div>
  );
};
