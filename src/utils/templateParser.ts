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

  const id = parsed.id || defaultId || 'custom-template';
  const info = parsed.info || {};
  const name = info.name || id;
  const severity = (info.severity || 'medium').toLowerCase() as VulnerabilitySeverity;
  const description = info.description || 'Custom security audit template';
  
  let tags: string[] = [];
  if (Array.isArray(info.tags)) {
    tags = info.tags.map((t: any) => String(t).trim()).filter(Boolean);
  } else if (typeof info.tags === 'string') {
    tags = info.tags.split(',').map((t: string) => t.trim()).filter(Boolean);
  } else {
    tags = ['custom'];
  }

  const author = info.author;
  const remediation = info.remediation;
  let references: string[] = [];
  if (Array.isArray(info.reference)) {
    references = info.reference.map((r: any) => String(r).trim());
  } else if (typeof info.reference === 'string') {
    references = [info.reference.trim()];
  }

  const classification = info.classification || {};
  const cvssScore = typeof classification['cvss-score'] === 'number' 
    ? classification['cvss-score'] 
    : undefined;
  const cvssVector = classification['cvss-vector'];
  const cweId = classification['cwe-id'];
  const owaspCategory = classification['owasp-category'];

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
 * Falls back gracefully to existing outer properties if YAML parsing fails temporarily.
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
      enabled: template.enabled ?? true,
      isBuiltin: template.isBuiltin ?? false,
      rawYaml: template.rawYaml,
    };
  }
}
