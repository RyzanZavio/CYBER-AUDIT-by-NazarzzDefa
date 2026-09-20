import { YamlTemplate } from '../types';

export const DEFAULT_TEMPLATES: YamlTemplate[] = [
  {
    id: 'owasp-security-headers',
    name: 'Missing Defensive HTTP Security Headers',
    severity: 'low',
    description: 'Audits crucial defense-in-depth HTTP security headers (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options: nosniff, Strict-Transport-Security).',
    tags: ['owasp', 'headers', 'defense-in-depth', 'burp-passive', 'hardening'],
    enabled: true,
    isBuiltin: true,
    rawYaml: `id: owasp-security-headers
info:
  name: Missing Defensive HTTP Security Headers
  author: devsecops
  severity: low
  description: Verifies crucial defensive HTTP security headers to prevent Clickjacking, MIME-sniffing, SSL downgrade, and Cross-Site Scripting (XSS).
  reference:
    - https://owasp.org/www-project-secure-headers/
    - https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
  tags: owasp,headers,defense-in-depth,hardening
  classification:
    cvss-score: 3.1
    cwe-id: CWE-693
    owasp-category: A05:2021-Security Misconfiguration

requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: or
    matchers:
      - type: header
        part: header
        negative: true
        words:
          - "content-security-policy"
        condition: or
      - type: header
        part: header
        negative: true
        words:
          - "x-frame-options"
        condition: or
      - type: header
        part: header
        negative: true
        words:
          - "x-content-type-options"
        condition: or
      - type: header
        part: header
        negative: true
        words:
          - "strict-transport-security"
        condition: or
`,
  },
  {
    id: 'exposed-env-credentials',
    name: 'Exposed Environment (.env) Credentials',
    severity: 'critical',
    description: 'Scans for publicly accessible .env configuration files leaking database secrets, API tokens, and production private keys.',
    tags: ['exposure', 'credentials', 'critical', 'nuclei'],
    enabled: true,
    isBuiltin: true,
    rawYaml: `id: exposed-env-credentials
info:
  name: Exposed .env Configuration File
  author: nuclei-secops
  severity: critical
  description: Publicly exposed .env files may contain database credentials, AWS keys, JWT secrets, and private API keys.
  reference:
    - https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure
  tags: exposure,credentials,cve,critical
  classification:
    cvss-score: 9.1
    cwe-id: CWE-200
    owasp-category: A01:2021-Broken Access Control

requests:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/.env.production"
      - "{{BaseURL}}/.env.local"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "DB_PASSWORD"
          - "APP_KEY="
          - "DATABASE_URL="
          - "AWS_SECRET_ACCESS_KEY"
          - "SECRET_KEY="
        condition: or
`,
  },
  {
    id: 'exposed-git-repository',
    name: 'Exposed Git Repository (.git/HEAD)',
    severity: 'high',
    description: 'Detects exposed .git folders containing source code, commit histories, developer branches, and embedded credentials.',
    tags: ['git', 'exposure', 'source-code', 'nuclei'],
    enabled: true,
    isBuiltin: true,
    rawYaml: `id: exposed-git-repository
info:
  name: Git Repository Directory Exposure
  author: nuclei-secops
  severity: high
  description: Exposed .git/HEAD allows attackers to reconstruct the entire application source code repository.
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces
  tags: git,exposure,vulnerability
  classification:
    cvss-score: 7.5
    cwe-id: CWE-538
    owasp-category: A05:2021-Security Misconfiguration

requests:
  - method: GET
    path:
      - "{{BaseURL}}/.git/HEAD"
      - "{{BaseURL}}/.git/config"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "ref: refs/heads"
          - "[core]"
        condition: or
`,
  },
  {
    id: 'cors-misconfiguration',
    name: 'CORS Wildcard & Arbitrary Origin Audit',
    severity: 'medium',
    description: 'Audits Cross-Origin Resource Sharing (CORS) policy for wildcard origin reflection and credentials leakage.',
    tags: ['cors', 'burp-active', 'owasp'],
    enabled: true,
    isBuiltin: true,
    rawYaml: `id: cors-misconfiguration
info:
  name: Overly Permissive CORS Policy
  author: burp-scanner
  severity: medium
  description: Insecure CORS configuration with wildcard (*) or arbitrary reflected Origin header with credentials enabled allows cross-site data theft.
  reference:
    - https://portswigger.net/web-security/cors
  tags: cors,burp-active,data-theft
  classification:
    cvss-score: 5.3
    cwe-id: CWE-346
    owasp-category: A01:2021-Broken Access Control

requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    headers:
      Origin: "https://evil-attacker-domain.com"
    matchers-condition: and
    matchers:
      - type: header
        part: header
        words:
          - "access-control-allow-origin: *"
          - "access-control-allow-origin: https://evil-attacker-domain.com"
        condition: or
`,
  },
  {
    id: 'server-version-disclosure',
    name: 'Verbose Server & Tech Stack Fingerprint',
    severity: 'info',
    description: 'Detects detailed server banner headers (Server, X-Powered-By, X-AspNet-Version) revealing framework versions.',
    tags: ['fingerprint', 'information-disclosure', 'burp-passive'],
    enabled: true,
    isBuiltin: true,
    rawYaml: `id: server-version-disclosure
info:
  name: Detailed Server Banner Disclosure
  author: owasp-zap
  severity: info
  description: Web servers often disclose exact operating system and software package versions, facilitating reconnaissance for attackers.
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server
  tags: fingerprint,banner,disclosure
  classification:
    cvss-score: 0.0
    cwe-id: CWE-200
    owasp-category: A05:2021-Security Misconfiguration

requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: or
    matchers:
      - type: header
        part: header
        words:
          - "x-powered-by"
          - "x-aspnet-version"
          - "x-runtime"
        condition: or
`,
  },
  {
    id: 'robots-txt-disclosure',
    name: 'Robots.txt Sensitive Endpoint Information Leak',
    severity: 'info',
    description: 'Parses robots.txt to discover hidden administration paths, private backup folders, or staging directories.',
    tags: ['robots', 'recon', 'information-disclosure', 'owasp'],
    enabled: true,
    isBuiltin: true,
    rawYaml: `id: robots-txt-disclosure
info:
  name: Sensitive Disallow Paths in Robots.txt
  author: nuclei-secops
  severity: info
  description: Developers frequently place confidential paths into robots.txt to discourage search engine indexing, unintentionally publishing an attack surface.
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage
  tags: robots,recon,disclosure
  classification:
    cvss-score: 0.0
    cwe-id: CWE-200
    owasp-category: A05:2021-Security Misconfiguration

requests:
  - method: GET
    path:
      - "{{BaseURL}}/robots.txt"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "Disallow:"
          - "User-agent:"
        condition: and
`,
  },
  {
    id: 'cookie-security-flags',
    name: 'Insecure Session Cookie Flags (HttpOnly/Secure)',
    severity: 'low',
    description: 'Audits Set-Cookie headers for missing HttpOnly, Secure, and SameSite flags that protect session cookies.',
    tags: ['cookies', 'session', 'owasp', 'burp-passive'],
    enabled: true,
    isBuiltin: true,
    rawYaml: `id: cookie-security-flags
info:
  name: Insecure Session Cookie Flags
  author: burp-scanner
  severity: low
  description: Cookies lacking the HttpOnly flag can be stolen via Cross-Site Scripting (XSS). Cookies missing Secure flag can be intercepted over cleartext HTTP.
  reference:
    - https://owasp.org/www-community/controls/SecureFlag
    - https://owasp.org/www-community/HttpOnly
  tags: cookies,session,hijacking
  classification:
    cvss-score: 3.1
    cwe-id: CWE-614
    owasp-category: A07:2021-Identification and Authentication Failures

requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: and
    matchers:
      - type: header
        part: header
        words:
          - "set-cookie"
        condition: or
      - type: word
        part: header
        negative: true
        words:
          - "httponly"
          - "samesite"
        condition: and
`,
  },
  {
    id: 'sqli-error-signatures',
    name: 'Database Error Trace Signature Detection (SQLi Passive)',
    severity: 'high',
    description: 'Checks for database error trace disclosures (MySQL, PostgreSQL, Oracle, SQLite, SQL Server) leaked in application responses.',
    tags: ['sqli', 'injection', 'database', 'burp-active'],
    enabled: true,
    isBuiltin: true,
    rawYaml: `id: sqli-error-signatures
info:
  name: Database Error Disclosure
  author: nuclei-secops
  severity: high
  description: Unhandled database exceptions leak schema details, query structure, and confirm SQL injection points.
  reference:
    - https://owasp.org/www-community/attacks/SQL_Injection
  tags: sqli,injection,burp-active
  classification:
    cvss-score: 7.5
    cwe-id: CWE-89
    owasp-category: A03:2021-Injection

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?id=1%27%20OR%201=1--"
      - "{{BaseURL}}/?query=%27"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "You have an error in your SQL syntax"
          - "warning: mysql_"
          - "pg_query(): Query failed: ERROR"
          - "ORA-00933: SQL command not properly ended"
          - "SQLite/JDBCDriver"
          - "Unclosed quotation mark after the character string"
        condition: or
`,
  },
  {
    id: 'xss-reflection-passive',
    name: 'Unsanitized Reflected Parameter Canary (XSS)',
    severity: 'medium',
    description: 'Tests if user-supplied query parameters are reflected verbatim without HTML entity escaping into the DOM response.',
    tags: ['xss', 'injection', 'reflection', 'burp-active'],
    enabled: true,
    isBuiltin: true,
    rawYaml: `id: xss-reflection-passive
info:
  name: Reflected Input Parameter Without Sanitization
  author: burp-scanner
  severity: medium
  description: Parameters reflected without proper context-aware sanitization can lead to Cross-Site Scripting (XSS) and session hijacking.
  reference:
    - https://owasp.org/www-community/attacks/xss/
  tags: xss,injection,burp-active
  classification:
    cvss-score: 6.1
    cwe-id: CWE-79
    owasp-category: A03:2021-Injection

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?sec_audit_probe=%3Csecprobe%3E"
      - "{{BaseURL}}/?q=%3Csecprobe%3E"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "<secprobe>"
        condition: or
`,
  },
  {
    id: 'sensitive-backup-files',
    name: 'Exposed Database & Source Code Backup Dumps',
    severity: 'high',
    description: 'Probes for forgotten compressed backups (.zip, .sql, .tar.gz, .bak) left in web root directories.',
    tags: ['backup', 'dumps', 'high', 'nuclei'],
    enabled: true,
    isBuiltin: true,
    rawYaml: `id: sensitive-backup-files
info:
  name: Exposed Database Dump & Backup Archives
  author: nuclei-secops
  severity: high
  description: Public archive dumps allow attackers to extract database tables, configuration secrets, and proprietary source code.
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information
  tags: backup,exposure,high
  classification:
    cvss-score: 8.5
    cwe-id: CWE-530
    owasp-category: A05:2021-Security Misconfiguration

requests:
  - method: GET
    path:
      - "{{BaseURL}}/backup.sql"
      - "{{BaseURL}}/database.sql"
      - "{{BaseURL}}/backup.tar.gz"
      - "{{BaseURL}}/dump.sql"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "-- MySQL dump"
          - "INSERT INTO"
          - "CREATE TABLE"
          - "PostgreSQL database dump"
        condition: or
`,
  }
];
