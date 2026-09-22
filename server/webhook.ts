import { ScanResult, VulnerabilityFinding, WebhookConfig } from '../src/types';
import { validateTargetUrl } from './ssrf-validator';

export async function sendWebhookNotification(
  config: WebhookConfig,
  scan: ScanResult
): Promise<{ success: boolean; message: string; statusCode?: number }> {
  if (!config.url || !config.url.trim()) {
    return { success: false, message: 'Webhook URL is empty' };
  }

  // Defense-in-depth: Validate Webhook target against SSRF attacks (require HTTPS, forbid private/internal destinations)
  const validation = await validateTargetUrl(config.url.trim(), { requireHttps: true });
  if (!validation.isValid) {
    return {
      success: false,
      message: `Webhook destination blocked by SSRF policy: ${validation.error || 'Private/internal addresses prohibited'}`,
    };
  }

  const safeWebhookUrl = validation.normalizedUrl || config.url.trim();

  const critCount = scan.findings.filter(f => f.severity === 'critical').length;
  const highCount = scan.findings.filter(f => f.severity === 'high').length;
  const medCount = scan.findings.filter(f => f.severity === 'medium').length;
  const lowCount = scan.findings.filter(f => f.severity === 'low').length;
  const infoCount = scan.findings.filter(f => f.severity === 'info').length;

  const highestSeverity = critCount > 0
    ? 'critical'
    : highCount > 0
    ? 'high'
    : medCount > 0
    ? 'medium'
    : lowCount > 0
    ? 'low'
    : 'clean';

  // Severity color mapping for Discord (Hex to Decimal)
  const discordColor =
    highestSeverity === 'critical'
      ? 14748999 // #E11D47 (Crimson)
      : highestSeverity === 'high'
      ? 15357964 // #EA580C (Orange)
      : highestSeverity === 'medium'
      ? 14251782 // #D97706 (Amber)
      : highestSeverity === 'low'
      ? 2448363  // #2563EB (Blue)
      : 2470710; // #25B336 (Green Clean)

  const topFindingsText = scan.findings.slice(0, 5).map(f => {
    const badge = f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : f.severity === 'medium' ? '🟡' : '🔵';
    return `${badge} **[${f.severity.toUpperCase()}]** ${f.name} (${f.cweId || 'OWASP'})`;
  }).join('\n') || '✅ No vulnerabilities identified matching active filters.';

  try {
    let payload: any;

    if (config.type === 'discord') {
      payload = {
        username: 'DevSecOps Audit Bot',
        avatar_url: 'https://cdn-icons-png.flaticon.com/512/2092/2092663.png',
        content: `🚨 **Security Vulnerability Scan Alert** for \`${scan.targetUrl}\``,
        embeds: [
          {
            title: 'OWASP · Nuclei · Burp Suite Audit Summary',
            description: `Automated vulnerability audit completed on target host. Total templates tested: **${scan.templatesExecuted}**. Total requests: **${scan.requestsSent}**.`,
            color: discordColor,
            fields: [
              { name: '🎯 Target URL', value: `\`${scan.targetUrl}\``, inline: true },
              { name: '⏱️ Duration', value: `${((scan.durationMs || 1000) / 1000).toFixed(1)}s`, inline: true },
              { name: '📊 Total Findings', value: `${scan.findings.length} issue(s)`, inline: true },
              {
                name: '⚠️ Severity Breakdown',
                value: `🔴 Critical: **${critCount}**  |  🟠 High: **${highCount}**\n🟡 Medium: **${medCount}**  |  🔵 Low/Info: **${lowCount + infoCount}**`,
                inline: false,
              },
              {
                name: '🔍 Top Identified Vulnerabilities',
                value: topFindingsText,
                inline: false,
              },
            ],
            footer: {
              text: 'Cybersecurity Vulnerability Audit Scanner · Scheduled & On-Demand Alert',
            },
            timestamp: new Date().toISOString(),
          },
        ],
      };
    } else {
      // Slack Block Kit format
      payload = {
        text: `Cybersecurity Scan Alert: ${scan.findings.length} findings on ${scan.targetUrl}`,
        blocks: [
          {
            type: 'header',
            text: {
              type: 'plain_text',
              text: '🛡️ Vulnerability Audit Alert (OWASP / Nuclei)',
              emoji: true,
            },
          },
          {
            type: 'section',
            fields: [
              { type: 'mrkdwn', text: `*Target:*\n<${scan.targetUrl}|${scan.targetUrl}>` },
              { type: 'mrkdwn', text: `*Status:*\n${scan.status.toUpperCase()}` },
              { type: 'mrkdwn', text: `*Total Findings:*\n*${scan.findings.length}* issues` },
              { type: 'mrkdwn', text: `*Duration:*\n${((scan.durationMs || 1000) / 1000).toFixed(1)}s` },
            ],
          },
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*Severity Breakdown:*\n• 🔴 Critical: *${critCount}*\n• 🟠 High: *${highCount}*\n• 🟡 Medium: *${medCount}*\n• 🔵 Low/Info: *${lowCount + infoCount}*`,
            },
          },
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*Top Findings:*\n${topFindingsText}`,
            },
          },
        ],
      };
    }

    const res = await fetch(safeWebhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10000),
    });

    if (res.ok || res.status === 204) {
      return { success: true, message: `Notification successfully delivered to ${config.type.toUpperCase()}`, statusCode: res.status };
    } else {
      const errorText = await res.text().catch(() => '');
      return {
        success: false,
        message: `${config.type.toUpperCase()} returned HTTP ${res.status}: ${errorText.slice(0, 150)}`,
        statusCode: res.status,
      };
    }
  } catch (err: any) {
    return { success: false, message: `Failed to dispatch webhook: ${err?.message || 'Network error'}` };
  }
}
