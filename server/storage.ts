import fs from 'fs';
import path from 'path';
import {
  CveEntry,
  ExtensionManifest,
  ProxyConfig,
  ScanResult,
  ScheduleConfig,
  WebhookConfig,
  YamlTemplate,
} from '../src/types';
import { DEFAULT_TEMPLATES } from '../src/data/defaultTemplates';
import { DEFAULT_EXTENSIONS } from '../src/data/defaultExtensions';
import { CVE_DATABASE, CveDatabaseItem } from '../src/data/cveDatabase';
import { syncTemplateWithYaml, validateTemplateYaml } from '../src/utils/templateParser';

export interface StorageStats {
  engine: 'Local Flat-File JSON Database';
  dataDirectory: string;
  isInitialized: boolean;
  templatesCount: number;
  cvesCount: number;
  extensionsCount: number;
  scanHistoryCount: number;
  files: {
    name: string;
    path: string;
    sizeBytes: number;
    lastModified: string;
  }[];
  lastSavedAt: string;
}

export class LocalStorageDatabase {
  private dataDir: string;
  private templatesFile: string;
  private cvesFile: string;
  private extensionsFile: string;
  private settingsFile: string;
  private scansFile: string;

  // In-memory synced state for ultra-fast zero-latency reads
  private templates: YamlTemplate[] = [];
  private cves: CveDatabaseItem[] = [];
  private extensions: ExtensionManifest[] = [];
  private webhookConfig: WebhookConfig = {
    type: 'discord',
    url: '',
    enabled: false,
    minSeverity: 'medium',
    channelName: '#security-alerts',
  };
  private proxyConfig: ProxyConfig = {
    enabled: false,
    url: 'http://127.0.0.1:8080',
    insecureSkipVerify: true,
    customUserAgent: 'Mozilla/5.0 (compatible; DevSecOps-Auditor/2.4; +https://owasp.org)',
  };
  private scheduleConfig: ScheduleConfig = {
    enabled: true,
    timeString: '02:00',
    cronExpression: '0 2 * * *',
    targetUrl: 'https://example.com',
    allowInternal: false,
    selectedTemplateIds: [
      'owasp-security-headers',
      'exposed-env-credentials',
      'cors-misconfiguration',
      'cookie-security-flags',
      'server-version-disclosure',
    ],
    notifyWebhook: true,
    status: 'idle',
    lastStatus: 'Initialized daily scan at 02:00 AM UTC',
  };
  private scanHistory: ScanResult[] = [];
  private lastScanResult: ScanResult | null = null;
  private lastSavedTimestamp: string = new Date().toISOString();
  private isReady = false;

  // Mutex lock to serialize atomic disk writes and prevent race conditions
  private writeQueue: Promise<any> = Promise.resolve();

  constructor(customDataDir?: string) {
    this.dataDir = customDataDir || path.join(process.cwd(), 'data');
    this.templatesFile = path.join(this.dataDir, 'templates.json');
    this.cvesFile = path.join(this.dataDir, 'cves.json');
    this.extensionsFile = path.join(this.dataDir, 'extensions.json');
    this.settingsFile = path.join(this.dataDir, 'settings.json');
    this.scansFile = path.join(this.dataDir, 'scans.json');
  }

  /**
   * Initializes database directory, reads existing data from disk or seeds defaults if empty.
   */
  public async init(): Promise<void> {
    try {
      if (!fs.existsSync(this.dataDir)) {
        fs.mkdirSync(this.dataDir, { recursive: true });
        console.log(`[Database] Created persistent storage directory: ${this.dataDir}`);
      }

      await this.loadTemplates();
      await this.loadCves();
      await this.loadExtensions();
      await this.loadSettings();
      await this.loadScans();

      this.syncExtensionTemplatesInternal();
      this.isReady = true;

      console.log(
        `[Database] Successfully initialized local database: ${this.templates.length} templates, ${this.cves.length} CVEs, ${this.extensions.length} extensions loaded from disk.`
      );
    } catch (err: any) {
      console.error('[Database] Failed to initialize storage database:', err);
      // Fallback in-memory initialization
      this.templates = JSON.parse(JSON.stringify(DEFAULT_TEMPLATES));
      this.cves = JSON.parse(JSON.stringify(CVE_DATABASE));
      this.extensions = JSON.parse(JSON.stringify(DEFAULT_EXTENSIONS));
      this.isReady = true;
    }
  }

  // --- ATOMIC FILE HELPERS ---

  private async atomicWriteJson(filePath: string, data: any): Promise<void> {
    const nextWrite = this.writeQueue.catch(() => {}).then(async () => {
      const tempPath = `${filePath}.tmp.${Date.now()}.${Math.random().toString(36).substring(7)}`;
      try {
        const jsonString = JSON.stringify(data, null, 2);
        await fs.promises.writeFile(tempPath, jsonString, 'utf-8');
        await fs.promises.rename(tempPath, filePath);
        this.lastSavedTimestamp = new Date().toISOString();
      } catch (err) {
        if (fs.existsSync(tempPath)) {
          try {
            await fs.promises.unlink(tempPath);
          } catch (_) {}
        }
        console.error(`[Database] Error writing to ${filePath}:`, err);
        throw err;
      }
    });
    this.writeQueue = nextWrite;
    return nextWrite;
  }

  private async readJsonFile<T>(
    filePath: string,
    defaultValue: T
  ): Promise<{ data: T; fileExisted: boolean; parseError: boolean }> {
    try {
      if (fs.existsSync(filePath)) {
        const raw = await fs.promises.readFile(filePath, 'utf-8');
        if (raw.trim().length === 0) {
          return { data: defaultValue, fileExisted: true, parseError: false };
        }
        const data = JSON.parse(raw) as T;
        return { data, fileExisted: true, parseError: false };
      }
    } catch (err: any) {
      console.error(`[Database] CRITICAL: JSON parse failure reading ${filePath}:`, err.message);
      return { data: defaultValue, fileExisted: true, parseError: true };
    }
    return { data: defaultValue, fileExisted: false, parseError: false };
  }

  // --- TEMPLATES PERSISTENCE ---

  private async loadTemplates(): Promise<void> {
    const res = await this.readJsonFile<YamlTemplate[]>(this.templatesFile, []);

    if (res.parseError) {
      // Quarantine corrupted file to prevent silent data destruction!
      const corruptPath = `${this.templatesFile}.corrupt.${Date.now()}.bak`;
      try {
        await fs.promises.copyFile(this.templatesFile, corruptPath);
        console.error(`[Database] Quarantined corrupted templates file to ${corruptPath}. Reseeding defaults.`);
      } catch (cpErr: any) {
        console.error(`[Database] Failed to quarantine corrupt ${this.templatesFile}:`, cpErr.message);
      }
    } else if (res.fileExisted) {
      const stored = res.data;
      // Retroactive synchronization: re-sync all stored templates with their YAML source of truth
      // This immediately restores remediation, references, cvssScore, cvssVector, cweId, owaspCategory, and tags
      const syncedStored: YamlTemplate[] = stored.map(tpl => syncTemplateWithYaml(tpl));
      const storedMap = new Map<string, YamlTemplate>(syncedStored.map(t => [t.id, t]));

      for (const defaultTpl of DEFAULT_TEMPLATES) {
        if (!storedMap.has(defaultTpl.id)) {
          syncedStored.push(syncTemplateWithYaml(defaultTpl));
        }
      }
      this.templates = syncedStored;
      // Atomically persist retroactively synced templates to disk
      await this.atomicWriteJson(this.templatesFile, this.templates);
      return;
    }

    // Seed defaults only on initial setup or corrupt quarantine recovery
    this.templates = DEFAULT_TEMPLATES.map(t => syncTemplateWithYaml(t));
    await this.atomicWriteJson(this.templatesFile, this.templates);
    console.log(`[Database] Seeded ${this.templates.length} default YAML templates to ${this.templatesFile}`);
  }

  public getTemplates(): YamlTemplate[] {
    return [...this.templates];
  }

  public getTemplateById(id: string): YamlTemplate | undefined {
    return this.templates.find(t => t.id === id);
  }

  public async saveTemplate(templateInput: Partial<YamlTemplate> & { rawYaml: string }): Promise<YamlTemplate> {
    // Fail loudly: strictly validate YAML syntax and required fields before saving
    validateTemplateYaml(templateInput.rawYaml, templateInput.id);

    const synced = syncTemplateWithYaml(templateInput);

    // Collision handling: If this is a new template (no explicit original ID provided),
    // and the generated sanitized ID already exists, append a numeric suffix to prevent
    // silent overwriting of unrelated templates.
    if (!templateInput.id) {
      let candidateId = synced.id;
      let counter = 1;
      while (this.templates.some(t => t.id === candidateId)) {
        candidateId = `${synced.id}-${counter++}`;
      }
      synced.id = candidateId;
    }

    const existingIndex = this.templates.findIndex(t => t.id === synced.id);

    if (existingIndex >= 0) {
      this.templates[existingIndex] = {
        ...this.templates[existingIndex],
        ...synced,
        isBuiltin: this.templates[existingIndex].isBuiltin,
      };
    } else {
      this.templates.push({
        ...synced,
        isBuiltin: false,
      });
    }

    await this.atomicWriteJson(this.templatesFile, this.templates);
    return synced;
  }

  public async bulkSaveTemplates(newTemplates: YamlTemplate[]): Promise<YamlTemplate[]> {
    for (const tpl of newTemplates) {
      const synced = syncTemplateWithYaml(tpl);
      const idx = this.templates.findIndex(t => t.id === synced.id);
      if (idx >= 0) {
        this.templates[idx] = { ...this.templates[idx], ...synced };
      } else {
        this.templates.push(synced);
      }
    }
    await this.atomicWriteJson(this.templatesFile, this.templates);
    return this.getTemplates();
  }

  public async deleteTemplate(id: string): Promise<boolean> {
    const prevLength = this.templates.length;
    this.templates = this.templates.filter(t => t.id !== id);
    const deleted = this.templates.length < prevLength;
    if (deleted) {
      await this.atomicWriteJson(this.templatesFile, this.templates);
    }
    return deleted;
  }

  public async resetTemplates(): Promise<YamlTemplate[]> {
    this.templates = DEFAULT_TEMPLATES.map(t => syncTemplateWithYaml(t));
    this.syncExtensionTemplatesInternal();
    await this.atomicWriteJson(this.templatesFile, this.templates);
    console.log(`[Database] Reset templates to factory defaults.`);
    return this.getTemplates();
  }

  public async setTemplateEnabled(id: string, enabled: boolean): Promise<YamlTemplate | undefined> {
    const tpl = this.templates.find(t => t.id === id);
    if (tpl) {
      tpl.enabled = enabled;
      await this.atomicWriteJson(this.templatesFile, this.templates);
    }
    return tpl;
  }

  // --- CVE DATABASE PERSISTENCE ---

  private async loadCves(): Promise<void> {
    const res = await this.readJsonFile<CveDatabaseItem[]>(this.cvesFile, []);

    if (res.parseError) {
      const corruptPath = `${this.cvesFile}.corrupt.${Date.now()}.bak`;
      try {
        await fs.promises.copyFile(this.cvesFile, corruptPath);
        console.error(`[Database] Quarantined corrupted CVE file to ${corruptPath}. Reseeding defaults.`);
      } catch (cpErr: any) {
        console.error(`[Database] Failed to quarantine corrupt ${this.cvesFile}:`, cpErr.message);
      }
    } else if (res.fileExisted) {
      const stored = res.data;
      const storedMap = new Map<string, CveDatabaseItem>(stored.map(c => [c.cveId.toLowerCase(), c]));
      for (const builtinCve of CVE_DATABASE) {
        if (!storedMap.has(builtinCve.cveId.toLowerCase())) {
          stored.push(builtinCve);
        }
      }
      this.cves = stored;
      return;
    }

    // Seed defaults
    this.cves = JSON.parse(JSON.stringify(CVE_DATABASE));
    await this.atomicWriteJson(this.cvesFile, this.cves);
    console.log(`[Database] Seeded ${this.cves.length} curated CVE entries to ${this.cvesFile}`);
  }

  public getCves(filter?: {
    query?: string;
    severity?: string;
    isKev?: boolean;
    tech?: string;
    year?: string;
  }): CveDatabaseItem[] {
    let list = [...this.cves];

    if (!filter) return list;

    if (filter.query && filter.query.trim()) {
      const lower = filter.query.toLowerCase();
      list = list.filter(
        c =>
          c.cveId.toLowerCase().includes(lower) ||
          c.name.toLowerCase().includes(lower) ||
          c.affectedTech.toLowerCase().includes(lower) ||
          c.description.toLowerCase().includes(lower) ||
          c.cweId.toLowerCase().includes(lower)
      );
    }

    if (filter.severity && filter.severity !== 'all') {
      list = list.filter(c => c.severity === filter.severity);
    }

    if (filter.isKev) {
      list = list.filter(c => c.isKev);
    }

    if (filter.tech && filter.tech !== 'all') {
      const lowerTech = filter.tech.toLowerCase();
      list = list.filter(c => c.affectedTech.toLowerCase().includes(lowerTech));
    }

    if (filter.year && filter.year !== 'all') {
      list = list.filter(c => c.cveId.toUpperCase().includes(`CVE-${filter.year}-`));
    }

    return list;
  }

  public getCveById(cveId: string): CveDatabaseItem | undefined {
    return this.cves.find(c => c.cveId.toLowerCase() === cveId.toLowerCase() || c.templateId === cveId);
  }

  public async saveCve(cveItem: CveDatabaseItem): Promise<CveDatabaseItem> {
    const existingIdx = this.cves.findIndex(c => c.cveId.toLowerCase() === cveItem.cveId.toLowerCase());
    if (existingIdx >= 0) {
      this.cves[existingIdx] = { ...this.cves[existingIdx], ...cveItem };
    } else {
      this.cves.push(cveItem);
    }
    await this.atomicWriteJson(this.cvesFile, this.cves);
    return cveItem;
  }

  public async enableCveTemplates(options: {
    cveIds?: string[];
    enableAll?: boolean;
  }): Promise<{ addedCount: number; activatedCount: number; totalTemplates: number }> {
    const resolveTemplateFromCve = (c: CveDatabaseItem): YamlTemplate | undefined => {
      if (c.yamlTemplate) return c.yamlTemplate;
      if ((c as any).rawYaml) {
        return syncTemplateWithYaml({
          id: c.templateId || c.cveId.toLowerCase().replace(/[^a-z0-9-]/g, '-'),
          rawYaml: (c as any).rawYaml,
          name: c.name,
          severity: c.severity,
          description: c.description,
          enabled: true,
        });
      }
      return undefined;
    };

    let toAdd: YamlTemplate[] = [];

    if (options.enableAll) {
      toAdd = this.cves.map(c => resolveTemplateFromCve(c)).filter(Boolean) as YamlTemplate[];
    } else if (Array.isArray(options.cveIds)) {
      toAdd = this.cves
        .filter(c => options.cveIds!.includes(c.cveId) || (c.templateId && options.cveIds!.includes(c.templateId)))
        .map(c => resolveTemplateFromCve(c))
        .filter(Boolean) as YamlTemplate[];
    }

    let addedCount = 0;
    let activatedCount = 0;

    for (const tpl of toAdd) {
      const existingIdx = this.templates.findIndex(t => t.id === tpl.id);
      if (existingIdx >= 0) {
        this.templates[existingIdx].enabled = true;
        activatedCount++;
      } else {
        this.templates.push({ ...tpl, enabled: true });
        addedCount++;
        activatedCount++;
      }
    }

    if (activatedCount > 0 || addedCount > 0) {
      await this.atomicWriteJson(this.templatesFile, this.templates);
    }

    return {
      addedCount,
      activatedCount,
      totalTemplates: this.templates.length,
    };
  }

  public async resetCves(): Promise<CveDatabaseItem[]> {
    this.cves = JSON.parse(JSON.stringify(CVE_DATABASE));
    await this.atomicWriteJson(this.cvesFile, this.cves);
    return this.cves;
  }

  // --- EXTENSIONS PERSISTENCE ---

  private async loadExtensions(): Promise<void> {
    const res = await this.readJsonFile<ExtensionManifest[]>(this.extensionsFile, []);

    if (res.parseError) {
      const corruptPath = `${this.extensionsFile}.corrupt.${Date.now()}.bak`;
      try {
        await fs.promises.copyFile(this.extensionsFile, corruptPath);
        console.error(`[Database] Quarantined corrupted extensions file to ${corruptPath}. Reseeding defaults.`);
      } catch (cpErr: any) {
        console.error(`[Database] Failed to quarantine corrupt ${this.extensionsFile}:`, cpErr.message);
      }
    } else if (res.fileExisted) {
      const stored = res.data;
      const storedMap = new Map<string, ExtensionManifest>(stored.map(e => [e.id, e]));
      for (const defaultExt of DEFAULT_EXTENSIONS) {
        if (!storedMap.has(defaultExt.id)) {
          stored.push(defaultExt);
        }
      }
      this.extensions = stored;
      return;
    }

    this.extensions = JSON.parse(JSON.stringify(DEFAULT_EXTENSIONS));
    await this.atomicWriteJson(this.extensionsFile, this.extensions);
    console.log(`[Database] Seeded ${this.extensions.length} extensions to ${this.extensionsFile}`);
  }

  public getExtensions(): ExtensionManifest[] {
    return [...this.extensions];
  }

  public async saveExtension(manifest: ExtensionManifest): Promise<ExtensionManifest> {
    const existingIndex = this.extensions.findIndex(e => e.id === manifest.id);
    if (existingIndex >= 0) {
      this.extensions[existingIndex] = manifest;
    } else {
      this.extensions.push(manifest);
    }
    this.syncExtensionTemplatesInternal();
    await this.atomicWriteJson(this.extensionsFile, this.extensions);
    await this.atomicWriteJson(this.templatesFile, this.templates);
    return manifest;
  }

  public async toggleExtension(id: string, enabled: boolean): Promise<ExtensionManifest | undefined> {
    const ext = this.extensions.find(e => e.id === id);
    if (ext) {
      ext.enabled = enabled;
      if (enabled) ext.installed = true;
      this.syncExtensionTemplatesInternal();
      await this.atomicWriteJson(this.extensionsFile, this.extensions);
      await this.atomicWriteJson(this.templatesFile, this.templates);
    }
    return ext;
  }

  public async deleteExtension(id: string): Promise<boolean> {
    const prev = this.extensions.length;
    this.extensions = this.extensions.filter(e => e.id !== id);
    const deleted = this.extensions.length < prev;
    if (deleted) {
      this.syncExtensionTemplatesInternal();
      await this.atomicWriteJson(this.extensionsFile, this.extensions);
      await this.atomicWriteJson(this.templatesFile, this.templates);
    }
    return deleted;
  }

  private syncExtensionTemplatesInternal() {
    // 1. Gather all templates from ACTIVE (installed & enabled) extensions
    const activeExtTemplates: YamlTemplate[] = [];
    for (const ext of this.extensions) {
      if (ext.installed && ext.enabled && Array.isArray(ext.templates)) {
        for (const tpl of ext.templates) {
          activeExtTemplates.push({ ...tpl, isBuiltin: false });
        }
      }
    }

    // 2. Collect IDs of all templates that belong to ANY extension (active or inactive)
    const allExtensionTemplateIds = new Set<string>();
    for (const ext of this.extensions) {
      if (Array.isArray(ext.templates)) {
        for (const tpl of ext.templates) {
          allExtensionTemplateIds.add(tpl.id);
        }
      }
    }

    // 3. Keep existing user-custom and NVD-imported templates (not builtin and not from any extension)
    const userCustomTemplates = this.templates.filter(
      t =>
        !DEFAULT_TEMPLATES.some(dt => dt.id === t.id) &&
        !allExtensionTemplateIds.has(t.id)
    );

    // 4. Map existing state (like user-modified 'enabled' toggle) for built-in and existing templates
    const existingTemplateMap = new Map<string, YamlTemplate>(
      this.templates.map(t => [t.id, t])
    );

    const reconstructedTemplates: YamlTemplate[] = [];

    // Add builtins (preserving customized enabled/severity settings if modified)
    for (const dt of DEFAULT_TEMPLATES) {
      const existing = existingTemplateMap.get(dt.id);
      reconstructedTemplates.push(existing ? { ...dt, enabled: existing.enabled } : { ...dt });
    }

    // Add user custom / NVD imported templates
    for (const custom of userCustomTemplates) {
      reconstructedTemplates.push(custom);
    }

    // Add ONLY active extension templates (so disabled or uninstalled extension templates are completely pruned!)
    for (const extTpl of activeExtTemplates) {
      const existing = existingTemplateMap.get(extTpl.id);
      reconstructedTemplates.push(
        existing ? { ...extTpl, enabled: existing.enabled } : { ...extTpl }
      );
    }

    this.templates = reconstructedTemplates;
  }

  // --- SETTINGS PERSISTENCE (WEBHOOK, PROXY, SCHEDULER) ---

  private async loadSettings(): Promise<void> {
    const res = await this.readJsonFile<{
      webhook?: WebhookConfig;
      proxy?: ProxyConfig;
      schedule?: ScheduleConfig;
    }>(this.settingsFile, {});

    if (res.parseError) {
      const corruptPath = `${this.settingsFile}.corrupt.${Date.now()}.bak`;
      try {
        await fs.promises.copyFile(this.settingsFile, corruptPath);
        console.error(`[Database] Quarantined corrupted settings file to ${corruptPath}. Reseeding defaults.`);
      } catch (_) {}
    } else if (res.fileExisted) {
      if (res.data.webhook) this.webhookConfig = { ...this.webhookConfig, ...res.data.webhook };
      if (res.data.proxy) this.proxyConfig = { ...this.proxyConfig, ...res.data.proxy };
      if (res.data.schedule) this.scheduleConfig = { ...this.scheduleConfig, ...res.data.schedule };
      return;
    }

    await this.persistSettings();
  }

  private async persistSettings(): Promise<void> {
    await this.atomicWriteJson(this.settingsFile, {
      webhook: this.webhookConfig,
      proxy: this.proxyConfig,
      schedule: this.scheduleConfig,
      savedAt: new Date().toISOString(),
    });
  }

  public getWebhookConfig(): WebhookConfig {
    return { ...this.webhookConfig };
  }

  public async saveWebhookConfig(config: Partial<WebhookConfig>): Promise<WebhookConfig> {
    this.webhookConfig = { ...this.webhookConfig, ...config };
    await this.persistSettings();
    return this.getWebhookConfig();
  }

  public getProxyConfig(): ProxyConfig {
    return { ...this.proxyConfig };
  }

  public async saveProxyConfig(config: Partial<ProxyConfig>): Promise<ProxyConfig> {
    this.proxyConfig = { ...this.proxyConfig, ...config };
    await this.persistSettings();
    return this.getProxyConfig();
  }

  public getScheduleConfig(): ScheduleConfig {
    return { ...this.scheduleConfig };
  }

  public async saveScheduleConfig(config: Partial<ScheduleConfig>): Promise<ScheduleConfig> {
    this.scheduleConfig = { ...this.scheduleConfig, ...config };
    await this.persistSettings();
    return this.getScheduleConfig();
  }

  // --- SCANS & HISTORY PERSISTENCE ---

  private async loadScans(): Promise<void> {
    const res = await this.readJsonFile<ScanResult[]>(this.scansFile, []);

    if (res.parseError) {
      const corruptPath = `${this.scansFile}.corrupt.${Date.now()}.bak`;
      try {
        await fs.promises.copyFile(this.scansFile, corruptPath);
        console.error(`[Database] Quarantined corrupted scans file to ${corruptPath}. Starting empty scan history.`);
      } catch (_) {}
    } else if (res.fileExisted) {
      this.scanHistory = res.data || [];
      if (this.scanHistory.length > 0) {
        this.lastScanResult = this.scanHistory[this.scanHistory.length - 1];
      }
      return;
    }

    await this.atomicWriteJson(this.scansFile, []);
  }

  public getLastScanResult(): ScanResult | null {
    return this.lastScanResult;
  }

  public getScanHistory(limit = 20): ScanResult[] {
    return this.scanHistory.slice(-limit);
  }

  public async saveScanResult(result: ScanResult): Promise<void> {
    this.lastScanResult = result;
    this.scanHistory.push(result);
    // Keep max 50 recent scans
    if (this.scanHistory.length > 50) {
      this.scanHistory = this.scanHistory.slice(-50);
    }
    await this.atomicWriteJson(this.scansFile, this.scanHistory);
  }

  public async clearScanHistory(): Promise<void> {
    this.scanHistory = [];
    this.lastScanResult = null;
    await this.atomicWriteJson(this.scansFile, []);
  }

  // --- DATABASE DIAGNOSTICS & STATS ---

  public getStorageStats(): StorageStats {
    const fileNames = ['templates.json', 'cves.json', 'extensions.json', 'settings.json', 'scans.json'];
    const files = fileNames.map(name => {
      const fullPath = path.join(this.dataDir, name);
      let sizeBytes = 0;
      let lastModified = 'N/A';
      try {
        if (fs.existsSync(fullPath)) {
          const stats = fs.statSync(fullPath);
          sizeBytes = stats.size;
          lastModified = stats.mtime.toISOString();
        }
      } catch (_) {}
      return {
        name,
        path: fullPath,
        sizeBytes,
        lastModified,
      };
    });

    return {
      engine: 'Local Flat-File JSON Database',
      dataDirectory: this.dataDir,
      isInitialized: this.isReady,
      templatesCount: this.templates.length,
      cvesCount: this.cves.length,
      extensionsCount: this.extensions.length,
      scanHistoryCount: this.scanHistory.length,
      files,
      lastSavedAt: this.lastSavedTimestamp,
    };
  }

  public async createBackup(): Promise<{ backupPath: string; timestamp: string }> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupDir = path.join(this.dataDir, 'backups');
    if (!fs.existsSync(backupDir)) {
      fs.mkdirSync(backupDir, { recursive: true });
    }

    const backupFile = path.join(backupDir, `backup-${timestamp}.json`);

    // Redact sensitive credentials (proxy password, webhook secret tokens) before archiving to backup files
    const sanitizedProxy: ProxyConfig = {
      ...this.proxyConfig,
      password: this.proxyConfig.password ? '[REDACTED_PROXY_PASSWORD]' : '',
      url: this.proxyConfig.url
        ? this.proxyConfig.url.replace(/:\/\/([^:]+):([^@]+)@/, '://$1:[REDACTED]@')
        : '',
    };

    const sanitizedWebhook: WebhookConfig = {
      ...this.webhookConfig,
      url: this.webhookConfig.url
        ? this.webhookConfig.url
            .replace(/(discord\.com\/api\/webhooks\/\d+\/)([a-zA-Z0-9_-]+)/, '$1[REDACTED_WEBHOOK_TOKEN]')
            .replace(/(hooks\.slack\.com\/services\/[^\/]+\/[^\/]+\/)([a-zA-Z0-9_-]+)/, '$1[REDACTED_SLACK_TOKEN]')
        : '',
    };

    const payload = {
      timestamp: new Date().toISOString(),
      templates: this.templates,
      cves: this.cves,
      extensions: this.extensions,
      settings: {
        webhook: sanitizedWebhook,
        proxy: sanitizedProxy,
        schedule: this.scheduleConfig,
      },
      scanHistory: this.scanHistory,
    };

    await fs.promises.writeFile(backupFile, JSON.stringify(payload, null, 2), 'utf-8');
    return { backupPath: backupFile, timestamp };
  }
}

// Global Singleton Instance for Server Runtime
export const db = new LocalStorageDatabase();
