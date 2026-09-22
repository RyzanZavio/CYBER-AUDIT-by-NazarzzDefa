import * as yaml from 'js-yaml';
import { VulnerabilitySeverity, YamlTemplate } from '../types';

export interface ParsedTemplateMeta {
  id: string;
  name: string;
  severity: VulnerabilitySeverity;
  description: string;
  tags: string[];
  author?: string;
  remediation?: string;
  references?: string[];
  cvssScore?: number;
  cvssVector?: string;
  cweId?: string;
  owaspCategory?: string;
}

/**
 * Extracts normalized metadata from a Nuclei/OWASP style raw YAML template string.
 * Guarantees that outer fields always stay synchronized with internal YAML fields.
 */
export function extractMetadataFromYaml(rawYaml: string, defaultId?: string): ParsedTemplateMeta {
  const parsed = yaml.load(rawYaml) as any;
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Invalid YAML: content must be an object.');
  }

  const rawId = String(parsed.id || defaultId || 'custom-template').trim();
  const id =
    rawId
      .toLowerCase()
      .replace(/[^a-z0-9_-]/g, '-')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '')
      .slice(0, 80) || 'custom-template';
  const info = parsed.info || {};
  const name = typeof info.name === 'string' ? info.name.trim() : id;
  
  const rawSev = typeof info.severity === 'string' ? info.severity.toLowerCase().trim() : 'medium';
  const severity: VulnerabilitySeverity = ['critical', 'high', 'medium', 'low', 'info'].includes(rawSev)
    ? (rawSev as VulnerabilitySeverity)
    : 'medium';

  const description = typeof info.description === 'string' ? info.description.trim() : 'Custom security audit template';
  
  let tags: string[] = [];
  if (Array.isArray(info.tags)) {
    tags = info.tags.map((t: any) => String(t).trim()).filter(Boolean);
  } else if (typeof info.tags === 'string') {
    tags = info.tags.split(',').map((t: string) => t.trim()).filter(Boolean);
  } else {
    tags = ['custom'];
  }

  const author = typeof info.author === 'string' ? info.author.trim() : undefined;
  const remediation = typeof info.remediation === 'string' ? info.remediation.trim() : undefined;
  let references: string[] = [];
  if (Array.isArray(info.reference)) {
    references = info.reference.map((r: any) => String(r).trim()).filter(Boolean);
  } else if (typeof info.reference === 'string') {
    references = [info.reference.trim()].filter(Boolean);
  }

  const classification = info.classification || {};
  const rawCvss = classification['cvss-score'];
  const cvssScore =
    typeof rawCvss === 'number' && !isNaN(rawCvss) && rawCvss >= 0 && rawCvss <= 10
      ? rawCvss
      : typeof rawCvss === 'string' && !isNaN(parseFloat(rawCvss))
      ? Math.min(10, Math.max(0, parseFloat(rawCvss)))
      : undefined;
  const cvssVector = typeof classification['cvss-vector'] === 'string' ? classification['cvss-vector'].trim() : undefined;
  const cweId = typeof classification['cwe-id'] === 'string' ? classification['cwe-id'].trim().toUpperCase() : undefined;
  const owaspCategory = typeof classification['owasp-category'] === 'string' ? classification['owasp-category'].trim() : undefined;

  return {
    id,
    name,
    severity,
    description,
    tags,
    author,
    remediation,
    references,
    cvssScore,
    cvssVector,
    cweId,
    owaspCategory,
  };
}

/**
 * Normalizes a YamlTemplate object ensuring outer properties match the YAML content.
 * Retains all classification, CVSS, CWE, OWASP, remediation, and reference metadata.
 */
export function syncTemplateWithYaml(template: Partial<YamlTemplate> & { rawYaml: string }): YamlTemplate {
  try {
    const meta = extractMetadataFromYaml(template.rawYaml, template.id);
    return {
      id: meta.id,
      name: meta.name,
      severity: meta.severity,
      description: meta.description,
      tags: meta.tags,
      author: meta.author,
      remediation: meta.remediation ?? template.remediation,
      references: meta.references && meta.references.length > 0 ? meta.references : template.references,
      cvssScore: meta.cvssScore ?? template.cvssScore,
      cvssVector: meta.cvssVector ?? template.cvssVector,
      cweId: meta.cweId ?? template.cweId,
      owaspCategory: meta.owaspCategory ?? template.owaspCategory,
      enabled: template.enabled ?? true,
      isBuiltin: template.isBuiltin ?? false,
      rawYaml: template.rawYaml,
    };
  } catch {
    return {
      id: template.id || 'custom-template',
      name: template.name || template.id || 'Custom Template',
      severity: template.severity || 'medium',
      description: template.description || 'Custom security audit template',
      tags: template.tags || ['custom'],
      author: template.author || 'analyst',
      remediation: template.remediation,
      references: template.references,
      cvssScore: template.cvssScore,
      cvssVector: template.cvssVector,
      cweId: template.cweId,
      owaspCategory: template.owaspCategory,
      enabled: template.enabled ?? true,
      isBuiltin: template.isBuiltin ?? false,
      rawYaml: template.rawYaml,
    };
  }
}

/**
 * Validates template YAML syntax strictly and returns the extracted metadata,
 * or throws an informative Error if parsing fails.
 */
export function validateTemplateYaml(rawYaml: string, defaultId?: string): ParsedTemplateMeta {
  if (!rawYaml || typeof rawYaml !== 'string' || rawYaml.trim().length === 0) {
    throw new Error('Template YAML content cannot be empty.');
  }
  return extractMetadataFromYaml(rawYaml, defaultId);
}
