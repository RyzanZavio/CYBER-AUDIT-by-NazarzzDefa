import dns from 'dns';
import net from 'net';
import { URL } from 'url';

/**
 * SSRF & Target Validation Module
 * Defends against Server-Side Request Forgery (SSRF), cloud metadata exfiltration,
 * DNS rebinding, loopback port scanning, and internal network (RFC1918) abuse.
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
  resolvedIps?: string[];
}

/**
 * Checks whether an IPv4 or IPv6 address string falls into private/loopback/link-local ranges.
 * If rawIp is not an IP address (e.g. domain name), returns false.
 */
export function isPrivateOrReservedIp(rawIp: string): boolean {
  let ip = rawIp.toLowerCase().trim();
  // Handle IPv4-mapped IPv6 (::ffff:192.168.1.1)
  if (ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }

  const ipFamily = net.isIP(ip);
  if (ipFamily === 0) {
    // Not an IP address (e.g. domain name hostname)
    return false;
  }

  // IPv4 check
  if (ipFamily === 4) {
    const parts = ip.split('.').map(p => parseInt(p, 10));
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
      return true; // Malformed IPv4 literal treated as unsafe
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
    // 255.255.255.255 (Broadcast)
    if (a === 255 && b === 255) return true;

    return false;
  }

  // IPv6 check
  if (ipFamily === 6) {
    if (ip === '::1' || ip === '::' || ip === '0:0:0:0:0:0:0:1' || ip === '0:0:0:0:0:0:0:0') return true;
    // Link-local: fe80::/10
    if (/^fe[89ab]/i.test(ip)) return true;
    // Unique local address: fc00::/7 (fc00 - fdff)
    if (/^f[cd]/i.test(ip)) return true;
  }

  return false;
}

/**
 * Validates a target URL before outbound HTTP/HTTPS requests.
 * Performs syntactic validation and asynchronous DNS resolution to defend against DNS rebinding.
 */
export async function validateTargetUrl(
  inputUrl: string,
  options: { allowInternal?: boolean; requireHttps?: boolean } = {}
): Promise<TargetValidationResult> {
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

  // allowInternal can only be honored if explicitly configured via server environment
  const isInternalAllowed = !!options.allowInternal && process.env.ALLOW_INTERNAL_SCAN === 'true';

  // Check against static blocked hostnames
  if (BLOCKED_HOSTNAMES.has(hostname) || hostname.endsWith('.localhost')) {
    if (!isInternalAllowed) {
      return {
        isValid: false,
        error: `SSRF Protection: Access to localhost/internal metadata host "${hostname}" is blocked.`,
        isInternal: true,
      };
    }
  }

  // Check static IP literals
  if (net.isIP(hostname)) {
    if (isPrivateOrReservedIp(hostname) && !isInternalAllowed) {
      return {
        isValid: false,
        error: `SSRF Protection: Outbound requests to private/link-local IP "${hostname}" (RFC1918/IMDS) are forbidden.`,
        isInternal: true,
      };
    }
  }

  // Asynchronous DNS Resolution to prevent DNS Rebinding / spoofed domain bypass
  let resolvedIps: string[] = [];
  try {
    const lookupResults = await dns.promises.lookup(hostname, { all: true });
    resolvedIps = lookupResults.map(r => r.address);
    for (const record of lookupResults) {
      if (isPrivateOrReservedIp(record.address) && !isInternalAllowed) {
        return {
          isValid: false,
          error: `SSRF Protection: Hostname "${hostname}" resolves to private/internal IP address "${record.address}". Requests to RFC1918/Loopback/IMDS addresses are blocked.`,
          isInternal: true,
          resolvedIps,
        };
      }
    }
  } catch (dnsErr: any) {
    return {
      isValid: false,
      error: `SSRF Protection: Failed to resolve hostname "${hostname}" in DNS: ${dnsErr.message}`,
    };
  }

  // Preserve query parameters (?id=5) and search string while normalizing path
  const normalizedPath = parsed.pathname === '/' && !parsed.search ? '' : parsed.pathname;
  const normalizedUrl = `${parsed.origin}${normalizedPath}${parsed.search}`;

  return {
    isValid: true,
    normalizedUrl,
    isInternal: false,
    resolvedIps,
  };
}
