export type VulnerabilitySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface FindingRequest {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
}

export interface FindingResponse {
  statusCode: number;
  headers?: Record<string, string>;
  bodySnippet?: string;
  responseTimeMs?: number;
}

export interface VulnerabilityFinding {
  id: string;
  templateId: string;
  name: string;
  severity: VulnerabilitySeverity;
  cvssScore: number;
  cweId: string;
  owaspCategory: string;
  description: string;
  url: string;
  matchedAt: string;
  evidence: string;
  request?: FindingRequest;
  response?: FindingResponse;
  remediation: string;
  references: string[];
  timestamp: string;
}

export interface YamlTemplate {
  id: string;
  rawYaml: string;
  name: string;
  severity: VulnerabilitySeverity;
  description: string;
  tags: string[];
  enabled: boolean;
  isBuiltin?: boolean;
  author?: string;
}

export interface ScanPayloadInfo {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  statusCode?: number;
  responseTimeMs?: number;
  matched?: boolean;
  evidence?: string;
  matchersCondition?: string;
}

export interface ScanLog {
  id?: string;
  timestamp: string;
  level: 'info' | 'warn' | 'crit' | 'pass';
  message: string;
  templateId?: string;
  templateName?: string;
  severity?: VulnerabilitySeverity;
  payload?: ScanPayloadInfo;
}

export interface ScanResult {
  id: string;
  targetUrl: string;
  startTime: string;
  endTime?: string;
  durationMs?: number;
  status: 'running' | 'completed' | 'failed';
  findings: VulnerabilityFinding[];
  templatesExecuted: number;
  requestsSent: number;
  logs: ScanLog[];
  accuracyScore?: number;
  accuracyLevel?: string;
  detectedTechnologies?: string[];
  cveMatchedCount?: number;
}

export interface WebhookConfig {
  type: 'discord' | 'slack';
  url: string;
  enabled: boolean;
  minSeverity: VulnerabilitySeverity;
  channelName?: string;
}

export interface ScheduleConfig {
  enabled: boolean;
  timeString: string; // e.g. "02:00"
  cronExpression: string; // e.g. "0 2 * * *"
  targetUrl: string;
  selectedTemplateIds: string[];
  notifyWebhook: boolean;
  lastRun?: string;
  nextRun?: string;
  status: 'idle' | 'running' | 'error';
  lastStatus?: string;
}

export interface ProxyConfig {
  enabled: boolean;
  url: string; // e.g. "http://127.0.0.1:8080" (Burp Suite) or "socks5://127.0.0.1:9050" (Tor)
  username?: string;
  password?: string;
  insecureSkipVerify?: boolean; // ignore self-signed upstream certs (Burp CA)
  customUserAgent?: string;
}

export interface ExtensionManifest {
  id: string;
  name: string;
  version: string;
  author: string;
  description: string;
  category: 'owasp' | 'cve' | 'burp' | 'cloud' | 'recon' | 'custom' | 'nuclei';
  installed: boolean;
  enabled: boolean;
  templatesCount: number;
  templates: YamlTemplate[];
  repositoryUrl?: string;
  downloadUrl?: string;
}

export interface BatchScanTarget {
  id: string;
  host: string;
  fullUrl: string;
  status: 'pending' | 'scanning' | 'completed' | 'failed';
  findingsCount: number;
  durationMs?: number;
  error?: string;
}

export interface BatchScanSummary {
  id: string;
  fileName?: string;
  totalTargets: number;
  completedTargets: number;
  failedTargets: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  status: 'idle' | 'running' | 'completed' | 'paused' | 'cancelled';
  startTime: string;
  endTime?: string;
  targets: BatchScanTarget[];
  resultsByTarget: Record<string, ScanResult>;
}

export type ThemePreset =
  | 'cyber-slate'
  | 'matrix'
  | 'oled-black'
  | 'red-team'
  | 'synthwave'
  | 'amber-terminal'
  | 'light-lab';

export type AccentColor = 'cyan' | 'emerald' | 'amber' | 'crimson' | 'violet' | 'sky';

export type FontFamilyChoice = 'sans' | 'mono' | 'retro';

export type UiDensity = 'compact' | 'normal' | 'spacious';

export interface VisualSettings {
  theme: ThemePreset;
  accent: AccentColor;
  fontFamily: FontFamilyChoice;
  density: UiDensity;
  fontSizeScale: number; // 90, 100, 110, 120
  enableScanlines: boolean;
  scanlineIntensity: number; // 1 to 5
  enableNeonGlow: boolean;
  enableBackgroundGrid: boolean;
  enableSoundFx: boolean;
  soundVolume: number; // 0 to 100
  reducedMotion: boolean;
}

export interface CveEntry {
  cveId: string;
  name: string;
  cvssScore: number;
  severity: VulnerabilitySeverity;
  cweId: string;
  owaspCategory: string;
  affectedTech: string;
  description: string;
  vector: string;
  remediation: string;
  referenceUrl: string;
  publishedDate: string;
  isKev?: boolean; // CISA Known Exploited Vulnerability
  accuracyRate: number; // e.g. 99.2%
  templateId?: string;
  detectionAvailable: boolean;
}

export interface CveAccuracyConfig {
  enableAntiFalsePositive: boolean;
  enableTechFingerprinting: boolean;
  minConfidenceThreshold: number;
  autoPrioritizeKev: boolean;
}


