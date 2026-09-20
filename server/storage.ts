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
import { syncTemplateWithYaml } from '../src/utils/templateParser';

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
    targetUrl: 'http://localhost:3000',
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
    this.writeQueue = this.writeQueue.then(async () => {
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
    return this.writeQueue;
  }

  private async readJsonFile<T>(filePath: string, defaultValue: T): Promise<T> {
    try {
      if (fs.existsSync(filePath)) {
        const raw = await fs.promises.readFile(filePath, 'utf-8');
        if (raw.trim().length > 0) {
          return JSON.parse(raw) as T;
        }
      }
    } catch (err) {
      console.warn(`[Database] Warning: Could not read ${filePath}, using fallback defaults:`, err);
    }
    return defaultValue;
  }

  // --- TEMPLATES PERSISTENCE ---

  private async loadTemplates(): Promise<void> {
    if (fs.existsSync(this.templatesFile)) {
      const stored = await this.readJsonFile<YamlTemplate[]>(this.templatesFile, []);
      if (stored && stored.length > 0) {
        // Merge stored templates with any newly introduced builtin default templates
        const storedMap = new Map<string, YamlTemplate>(stored.map(t => [t.id, t]));
        for (const defaultTpl of DEFAULT_TEMPLATES) {
          if (!storedMap.has(defaultTpl.id)) {
            stored.push(defaultTpl);
          }
        }
        this.templates = stored;
        return;
      }
    }

    // Seed defaults
    this.templates = JSON.parse(JSON.stringify(DEFAULT_TEMPLATES));
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
    const synced = syncTemplateWithYaml(templateInput);
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
      const idx = this.templates.findIndex(t => t.id === tpl.id);
      if (idx >= 0) {
        this.templates[idx] = { ...this.templates[idx], ...tpl };
      } else {
        this.templates.push(tpl);
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
    this.templates = JSON.parse(JSON.stringify(DEFAULT_TEMPLATES));
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
    if (fs.existsSync(this.cvesFile)) {
      const stored = await this.readJsonFile<CveDatabaseItem[]>(this.cvesFile, []);
      if (stored && stored.length > 0) {
        // Merge with codebase CVE items in case new CVEs (e.g. 2026/2025 additions) were introduced
        const storedMap = new Map<string, CveDatabaseItem>(stored.map(c => [c.cveId.toLowerCase(), c]));
        for (const builtinCve of CVE_DATABASE) {
          if (!storedMap.has(builtinCve.cveId.toLowerCase())) {
            stored.push(builtinCve);
          }
        }
        this.cves = stored;
        return;
      }
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
    let toAdd: YamlTemplate[] = [];

    if (options.enableAll) {
      toAdd = this.cves.map(c => c.yamlTemplate).filter(Boolean) as YamlTemplate[];
    } else if (Array.isArray(options.cveIds)) {
      toAdd = this.cves
        .filter(c => options.cveIds!.includes(c.cveId) || (c.templateId && options.cveIds!.includes(c.templateId)))
        .map(c => c.yamlTemplate)
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
    if (fs.existsSync(this.extensionsFile)) {
      const stored = await this.readJsonFile<ExtensionManifest[]>(this.extensionsFile, []);
      if (stored && stored.length > 0) {
        const storedMap = new Map<string, ExtensionManifest>(stored.map(e => [e.id, e]));
        for (const defaultExt of DEFAULT_EXTENSIONS) {
          if (!storedMap.has(defaultExt.id)) {
            stored.push(defaultExt);
          }
        }
        this.extensions = stored;
        return;
      }
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
    const activeExtTemplates: YamlTemplate[] = [];

    for (const ext of this.extensions) {
      if (ext.installed && ext.enabled && Array.isArray(ext.templates)) {
        for (const tpl of ext.templates) {
          activeExtTemplates.push({ ...tpl, isBuiltin: false });
        }
      }
    }

    // Merge without wiping out user custom templates
    const existingUserCustom = this.templates.filter(
      t =>
        !DEFAULT_TEMPLATES.some(dt => dt.id === t.id) &&
        !this.extensions.some(ext => ext.templates.some(et => et.id === t.id))
    );

    // Merge unique
    const mergedMap = new Map<string, YamlTemplate>();
    for (const tpl of this.templates) {
      mergedMap.set(tpl.id, tpl);
    }
    for (const tpl of activeExtTemplates) {
      if (!mergedMap.has(tpl.id)) {
        mergedMap.set(tpl.id, tpl);
      }
    }

    this.templates = Array.from(mergedMap.values());
  }

  // --- SETTINGS PERSISTENCE (WEBHOOK, PROXY, SCHEDULER) ---

  private async loadSettings(): Promise<void> {
    if (fs.existsSync(this.settingsFile)) {
      const stored = await this.readJsonFile<{
        webhook?: WebhookConfig;
        proxy?: ProxyConfig;
        schedule?: ScheduleConfig;
      }>(this.settingsFile, {});

      if (stored.webhook) this.webhookConfig = { ...this.webhookConfig, ...stored.webhook };
      if (stored.proxy) this.proxyConfig = { ...this.proxyConfig, ...stored.proxy };
      if (stored.schedule) this.scheduleConfig = { ...this.scheduleConfig, ...stored.schedule };
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
    if (fs.existsSync(this.scansFile)) {
      const stored = await this.readJsonFile<ScanResult[]>(this.scansFile, []);
      this.scanHistory = stored || [];
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
    const payload = {
      timestamp: new Date().toISOString(),
      templates: this.templates,
      cves: this.cves,
      extensions: this.extensions,
      settings: {
        webhook: this.webhookConfig,
        proxy: this.proxyConfig,
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
