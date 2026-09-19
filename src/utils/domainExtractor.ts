/**
 * Utility to extract, parse, clean, and deduplicate domains/subdomains from
 * files uploaded from laptops, flashdrives, or tools like Subfinder, Amass, Assetfinder, Findomain.
 */

export interface ParsedTargetItem {
  id: string;
  raw: string;
  hostname: string;
  normalizedUrl: string;
  isWildcard?: boolean;
}

export function extractDomainsFromText(fileContent: string): ParsedTargetItem[] {
  if (!fileContent || typeof fileContent !== 'string') return [];

  // Split by newlines, carriage returns, or commas/semicolons
  const lines = fileContent.split(/[\r\n,;]+/);
  const seen = new Set<string>();
  const results: ParsedTargetItem[] = [];

  // Regex to recognize domains / subdomains / IP addresses
  const domainRegex = /([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}/;
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d{1,5})?\b/;

  for (const rawLine of lines) {
    let clean = rawLine.trim();
    if (!clean || clean.startsWith('#') || clean.startsWith('//')) continue;

    // Strip out quotes, markdown, brackets, or CLI logging prefixes (e.g., [subfinder], [info])
    clean = clean.replace(/\[.*?\]/g, '').replace(/["'`]/g, '').trim();

    // Check if starts with http:// or https://
    let protocol = 'https://';
    if (clean.toLowerCase().startsWith('http://')) {
      protocol = 'http://';
      clean = clean.slice(7);
    } else if (clean.toLowerCase().startsWith('https://')) {
      protocol = 'https://';
      clean = clean.slice(8);
    }

    // Strip trailing paths or query params (e.g. sub.domain.com/path -> sub.domain.com)
    clean = clean.split('/')[0].split('?')[0].split('#')[0].trim();

    // Remove leading wildcard *. if present
    const isWildcard = clean.startsWith('*.');
    if (isWildcard) {
      clean = clean.slice(2);
    }

    // Match domain or IP
    const domainMatch = clean.match(domainRegex) || clean.match(ipRegex);
    if (!domainMatch) continue;

    const hostname = domainMatch[0].toLowerCase();

    // Discard localhost or non-routable strings
    if (hostname === 'localhost' || hostname === '0.0.0.0' || hostname === 'example.com') {
      // allow example.com for demos, but deduplicate
    }

    if (!seen.has(hostname)) {
      seen.add(hostname);
      results.push({
        id: `target-${seen.size}-${Date.now()}`,
        raw: rawLine.trim(),
        hostname,
        normalizedUrl: `${protocol}${hostname}`,
        isWildcard,
      });
    }
  }

  return results;
}
