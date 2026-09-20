import { URL } from 'url';

/**
 * SSRF & Target Validation Module
 * Defends against Server-Side Request Forgery (SSRF), cloud metadata exfiltration,
 * loopback port scanning, and internal network (RFC1918) abuse.
 */

// Cloud Metadata and link-local addresses
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal',
  '169.254.169.254', // AWS, GCP, Azure, DigitalOcean IMDS
  '100.100.100.200', // Alibaba Cloud IMDS
  '0.0.0.0',
  '127.0.0.1',
  '::1',
  '[::1]',
]);

export interface TargetValidationResult {
  isValid: boolean;
  normalizedUrl?: string;
  error?: string;
  isInternal?: boolean;
}

/**
 * Checks whether an IPv4 address string falls into private/loopback/link-local ranges.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  const parts = ip.split('.').map(p => parseInt(p, 10));
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
    return false;
  }

  const [a, b] = parts;

  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;
  // 0.0.0.0/8 (Current network)
  if (a === 0) return true;
  // 10.0.0.0/8 (RFC1918 Private)
  if (a === 10) return true;
  // 172.16.0.0/12 (RFC1918 Private: 172.16.0.0 - 172.31.255.255)
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.0.0/16 (RFC1918 Private)
  if (a === 192 && b === 168) return true;
  // 169.254.0.0/16 (Link-local / Cloud metadata)
  if (a === 169 && b === 254) return true;
  // 100.64.0.0/10 (Carrier-grade NAT)
  if (a === 100 && b >= 64 && b <= 127) return true;

  return false;
}

/**
 * Validates a target URL before outbound HTTP/HTTPS requests.
 */
export function validateTargetUrl(
  inputUrl: string,
  options: { allowInternal?: boolean; requireHttps?: boolean } = {}
): TargetValidationResult {
  if (!inputUrl || typeof inputUrl !== 'string') {
    return { isValid: false, error: 'Target URL is required and must be a string.' };
  }

  let raw = inputUrl.trim();
  if (!/^https?:\/\//i.test(raw)) {
    raw = `https://${raw}`;
  }

  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch (err: any) {
    return { isValid: false, error: `Invalid URL format: ${err.message}` };
  }

  // Only allow http and https protocols
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      isValid: false,
      error: `Disallowed protocol "${parsed.protocol}". Only HTTP and HTTPS are permitted.`,
    };
  }

  if (options.requireHttps && parsed.protocol !== 'https:') {
    return {
      isValid: false,
      error: 'HTTPS protocol is strictly required for this endpoint.',
    };
  }

  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');

  // Check against static blocked hostnames
  if (BLOCKED_HOSTNAMES.has(hostname) || hostname.endsWith('.localhost')) {
    if (!options.allowInternal) {
      return {
        isValid: false,
        error: `SSRF Protection: Access to localhost/internal metadata host "${hostname}" is blocked.`,
        isInternal: true,
      };
    }
  }

  // Check IPv4 address against private ranges
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    if (isPrivateOrReservedIp(hostname) && !options.allowInternal) {
      return {
        isValid: false,
        error: `SSRF Protection: Outbound requests to private/link-local IP "${hostname}" (RFC1918/IMDS) are forbidden.`,
        isInternal: true,
      };
    }
  }

  // Check IPv6 loopback / unique local
  if (hostname === '::1' || hostname === '0:0:0:0:0:0:0:1' || hostname.startsWith('fe80:') || hostname.startsWith('fc00:')) {
    if (!options.allowInternal) {
      return {
        isValid: false,
        error: `SSRF Protection: Outbound requests to IPv6 local address "${hostname}" are forbidden.`,
        isInternal: true,
      };
    }
  }

  return {
    isValid: true,
    normalizedUrl: parsed.origin + (parsed.pathname === '/' ? '' : parsed.pathname),
    isInternal: false,
  };
}
