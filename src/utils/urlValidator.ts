/**
 * Robust URL Validation & Sanitization Utility
 * Strictly enforces HTTP/HTTPS protocols using the WHATWG URL constructor,
 * and neutralizes malicious inputs (command injection, shell metacharacters,
 * control characters, CRLF injection, null bytes) before targets reach the scanning engine.
 */

export interface UrlValidationResult {
  isValid: boolean;
  normalizedUrl?: string;
  error?: string;
  protocol?: 'http:' | 'https:';
  hostname?: string;
  port?: string;
  pathname?: string;
}

// Shell injection operators, delimiters, and control sequences that have no legitimate place in a target URL
const DANGEROUS_SHELL_INJECTION_PATTERN = /[;`$&|><"'{}\0\r\n\t\x00-\x1f\x7f]/;
// Common URL-encoded command injection & control sequences (%00 null byte, %0a LF, %0d CR, %26 &, %3b ;, %7c |, %60 `, %22 ", %27 ')
const URL_ENCODED_CONTROL_PATTERN = /%(?:00|0a|0d|26|3b|7c|60|22|27)/i;

/**
 * Validates and sanitizes a target URL using the standard WHATWG URL constructor.
 * - Strictly enforces HTTP / HTTPS protocols.
 * - Mitigates command injection and shell escape attacks.
 * - Rejects null bytes, CRLF, and unprintable control characters.
 * - Validates hostnames, ports, and structures.
 */
export function validateAndSanitizeTargetUrl(rawInput: unknown): UrlValidationResult {
  if (!rawInput || typeof rawInput !== 'string') {
    return {
      isValid: false,
      error: 'Target URL is required and must be a non-empty string.',
    };
  }

  const trimmed = rawInput.trim();
  if (!trimmed) {
    return {
      isValid: false,
      error: 'Target URL cannot be empty or solely whitespace.',
    };
  }

  // 1. Check for command injection characters and raw control characters
  if (DANGEROUS_SHELL_INJECTION_PATTERN.test(trimmed)) {
    return {
      isValid: false,
      error: 'Security Alert: Malicious characters (shell metacharacters, semicolons, backticks, pipe, or control characters) detected in target input.',
    };
  }

  // 2. Check for suspicious URL-encoded control characters (%00 null byte, %0a newline, etc.)
  if (URL_ENCODED_CONTROL_PATTERN.test(trimmed)) {
    return {
      isValid: false,
      error: 'Security Alert: Encoded control or injection sequence (null byte / CRLF / shell operator) detected in target input.',
    };
  }

  // 3. Prepend protocol if user entered domain or IP without scheme (e.g. "example.com" or "103.233.103.52")
  let urlToParse = trimmed;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(urlToParse)) {
    urlToParse = `https://${urlToParse}`;
  }

  // 4. Parse with WHATWG URL constructor
  let parsed: URL;
  try {
    parsed = new URL(urlToParse);
  } catch (err: any) {
    return {
      isValid: false,
      error: `Invalid URL format: Unable to parse URL structure (${err?.message || 'Syntax Error'}).`,
    };
  }

  // 5. Strictly enforce http: and https: protocols only
  const protocol = parsed.protocol.toLowerCase();
  if (protocol !== 'http:' && protocol !== 'https:') {
    return {
      isValid: false,
      error: `Protocol "${protocol}" is strictly forbidden. The vulnerability scanner only permits standard web targets using "http:" or "https:".`,
    };
  }

  // 6. Validate Hostname
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!hostname) {
    return {
      isValid: false,
      error: 'Target URL must include a valid, non-empty host domain or IP address.',
    };
  }

  // Reject hostnames with invalid characters, spaces, or shell trickery
  if (/[\s;`$|&<>"'\\/]/.test(hostname)) {
    return {
      isValid: false,
      error: 'Target hostname contains illegal characters or whitespace.',
    };
  }

  // Disallow userinfo (e.g., http://user:pass@host) to prevent authentication confusion or credential stuffing
  if (parsed.username || parsed.password) {
    return {
      isValid: false,
      error: 'Credentials (username/password) embedded in target URLs are rejected for security.',
    };
  }

  // Validate port range if specified
  if (parsed.port) {
    const portNum = Number(parsed.port);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      return {
        isValid: false,
        error: `Invalid port number "${parsed.port}". Port must be an integer between 1 and 65535.`,
      };
    }
  }

  // Construct normalized clean target URL (without hash fragments or dangerous trailing elements)
  const cleanPath = parsed.pathname === '/' ? '' : parsed.pathname;
  const cleanSearch = parsed.search || '';
  const normalizedUrl = `${protocol}//${parsed.host}${cleanPath}${cleanSearch}`;

  return {
    isValid: true,
    normalizedUrl,
    protocol: protocol as 'http:' | 'https:',
    hostname,
    port: parsed.port || (protocol === 'https:' ? '443' : '80'),
    pathname: parsed.pathname,
  };
}
