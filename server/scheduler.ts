import cron, { ScheduledTask } from 'node-cron';
import { ScheduleConfig, ScanResult, WebhookConfig, YamlTemplate } from '../src/types';
import { executeVulnerabilityScan } from './scanner';
import { sendWebhookNotification } from './webhook';

let activeCronTask: ScheduledTask | null = null;

let currentSchedule: ScheduleConfig = {
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

let lastScheduledScanResult: ScanResult | null = null;

export function getScheduleState() {
  return {
    config: currentSchedule,
    lastResult: lastScheduledScanResult,
  };
}

export function initializeScheduler(
  getTemplates: () => YamlTemplate[],
  getWebhookConfig: () => WebhookConfig
) {
  if (currentSchedule.enabled) {
    scheduleDailyScan(currentSchedule, getTemplates, getWebhookConfig);
  }
}

export function updateSchedule(
  newConfig: Partial<ScheduleConfig>,
  getTemplates: () => YamlTemplate[],
  getWebhookConfig: () => WebhookConfig
) {
  currentSchedule = { ...currentSchedule, ...newConfig };

  // Convert timeString "HH:MM" to daily cron "MM HH * * *"
  if (newConfig.timeString) {
    const parts = newConfig.timeString.split(':');
    const hours = parseInt(parts[0] || '2', 10);
    const minutes = parseInt(parts[1] || '0', 10);
    currentSchedule.cronExpression = `${minutes} ${hours} * * *`;
  }

  // Calculate approximate next run timestamp
  const now = new Date();
  const [targetH, targetM] = (currentSchedule.timeString || '02:00').split(':').map(Number);
  const next = new Date(now);
  next.setHours(targetH, targetM, 0, 0);
  if (next <= now) {
    next.setDate(next.getDate() + 1);
  }
  currentSchedule.nextRun = next.toISOString();

  if (activeCronTask) {
    activeCronTask.stop();
    activeCronTask = null;
  }

  if (currentSchedule.enabled) {
    scheduleDailyScan(currentSchedule, getTemplates, getWebhookConfig);
    currentSchedule.status = 'idle';
    currentSchedule.lastStatus = `Daily automated scan scheduled at ${currentSchedule.timeString}`;
  } else {
    currentSchedule.status = 'idle';
    currentSchedule.lastStatus = 'Daily scheduled scan is currently paused';
  }

  return getScheduleState();
}

function scheduleDailyScan(
  config: ScheduleConfig,
  getTemplates: () => YamlTemplate[],
  getWebhookConfig: () => WebhookConfig
) {
  if (!cron.validate(config.cronExpression)) {
    console.warn(`[Scheduler] Invalid cron expression: ${config.cronExpression}`);
    return;
  }

  console.log(`[Scheduler] Registering daily scan cron: "${config.cronExpression}" for target ${config.targetUrl}`);

  activeCronTask = cron.schedule(config.cronExpression, async () => {
    console.log(`[Scheduler] Triggering scheduled daily security audit on ${config.targetUrl}`);
    config.status = 'running';
    config.lastRun = new Date().toISOString();

    try {
      const allTemplates = getTemplates();
      const activeTemplates = allTemplates.filter(t =>
        config.selectedTemplateIds.length > 0 ? config.selectedTemplateIds.includes(t.id) : t.enabled
      );

      const result = await executeVulnerabilityScan(config.targetUrl, activeTemplates, {
        timeoutMs: 8000,
        userAgent: 'DevSecOps-Daily-Automated-Auditor/2.4 (OWASP/Nuclei)',
      });

      lastScheduledScanResult = result;
      config.status = 'idle';
      config.lastStatus = `Completed with ${result.findings.length} findings (${new Date().toLocaleTimeString()})`;

      // Dispatch Webhook if enabled
      if (config.notifyWebhook) {
        const webhookConfig = getWebhookConfig();
        if (webhookConfig.enabled && webhookConfig.url) {
          console.log(`[Scheduler] Sending automated daily webhook notification to ${webhookConfig.type}...`);
          await sendWebhookNotification(webhookConfig, result);
        }
      }
    } catch (err: any) {
      console.error('[Scheduler] Daily automated audit failed:', err);
      config.status = 'error';
      config.lastStatus = `Execution error: ${err.message}`;
    }
  });
}
