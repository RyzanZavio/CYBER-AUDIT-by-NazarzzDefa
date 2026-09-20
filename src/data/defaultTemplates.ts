import { YamlTemplate } from '../types';
import { syncTemplateWithYaml } from '../utils/templateParser';

const RAW_DEFAULT_TEMPLATES: { id: string; rawYaml: string; isBuiltin: boolean }[] = [
  {
    id: 'owasp-security-headers',
    isBuiltin: true,
    rawYaml: `id: owasp-security-headers
info:
  name: Missing Defensive HTTP Security Headers
  author: devsecops-auditor
  severity: low
  description: "Audits crucial defense-in-depth HTTP security headers (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options: nosniff, Strict-Transport-Security) to prevent Clickjacking, MIME-sniffing, SSL downgrade, and XSS."
  reference:
    - https://owasp.org/www-project-secure-headers/
    - https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
  tags: owasp,headers,defense-in-depth,burp-passive,hardening
  classification:
    cvss-score: 3.1
    cvss-vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N
    cwe-id: CWE-693
    owasp-category: A05:2021-Security Misconfiguration
  remediation: |
    Add defensive HTTP security headers to your web server or reverse proxy (Nginx, Apache, Express, Caddy, Cloudflare):
    - Content-Security-Policy: default-src 'self'; script-src 'self' https:; object-src 'none';
    - X-Frame-Options: SAMEORIGIN
    - X-Content-Type-Options: nosniff
    - Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
    - Referrer-Policy: strict-origin-when-cross-origin
    - Permissions-Policy: camera=(), microphone=(), geolocation=()

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
    isBuiltin: true,
    rawYaml: `id: exposed-env-credentials
info:
  name: Exposed Environment (.env) Credentials
  author: nuclei-secops
  severity: critical
  description: Scans for publicly accessible .env configuration files leaking database secrets, API tokens, and production private keys.
  reference:
    - https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure
    - https://cwe.mitre.org/data/definitions/200.html
  tags: exposure,credentials,critical,nuclei
  classification:
    cvss-score: 9.1
    cvss-vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
    cwe-id: CWE-200
    owasp-category: A01:2021-Broken Access Control
  remediation: |
    Immediately block public HTTP access to .env* files in web server configuration and invalidate/rotate any database credentials, AWS keys, or API tokens exposed.
    In Nginx: location ~ /\\.env { deny all; return 404; }

requests:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/.env.production"
      - "{{BaseURL}}/.env.local"
      - "{{BaseURL}}/.env.backup"
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
          - "JWT_SECRET="
        condition: or
`,
  },
  {
    id: 'exposed-git-repository',
    isBuiltin: true,
    rawYaml: `id: exposed-git-repository
info:
  name: Exposed Git Repository (.git/HEAD)
  author: nuclei-secops
  severity: high
  description: Detects exposed .git folders containing source code, commit histories, developer branches, and embedded credentials.
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces
  tags: git,exposure,source-code,nuclei
  classification:
    cvss-score: 7.5
    cvss-vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
    cwe-id: CWE-538
    owasp-category: A05:2021-Security Misconfiguration
  remediation: |
    Deny web access to /.git/ directory and all its child files via web server rules.
    In Nginx: location ~ /\\.git { deny all; return 404; }
    In Apache: RedirectMatch 404 /\\.git

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
          - "repositoryformatversion"
        condition: or
`,
  },
  {
    id: 'cors-misconfiguration',
    isBuiltin: true,
    rawYaml: `id: cors-misconfiguration
info:
  name: CORS Wildcard & Arbitrary Origin Audit
  author: burp-scanner
  severity: medium
  description: Audits Cross-Origin Resource Sharing (CORS) policy for arbitrary origin reflection or insecure credentials exposure enabling cross-site data exfiltration.
  reference:
    - https://portswigger.net/web-security/cors
    - https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny
  tags: cors,burp-active,owasp
  classification:
    cvss-score: 5.3
    cvss-vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N
    cwe-id: CWE-346
    owasp-category: A01:2021-Broken Access Control
  remediation: |
    1. Avoid reflecting untrusted Origin headers into Access-Control-Allow-Origin dynamically.
    2. Maintain an explicit whitelist of trusted frontend domains.
    3. Never set Access-Control-Allow-Origin to '*' or 'null' when Access-Control-Allow-Credentials is true.

requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    headers:
      Origin: "https://evil-attacker-domain.com"
    matchers-condition: or
    matchers:
      - type: header
        part: header
        words:
          - "access-control-allow-origin: https://evil-attacker-domain.com"
          - "access-control-allow-origin: null"
        condition: or
      - type: header
        part: header
        words:
          - "access-control-allow-credentials: true"
          - "access-control-allow-origin: *"
        condition: and
`,
  },
  {
    id: 'server-version-disclosure',
    isBuiltin: true,
    rawYaml: `id: server-version-disclosure
info:
  name: Verbose Server & Tech Stack Fingerprint
  author: owasp-zap
  severity: info
  description: Detects detailed server banner headers (Server, X-Powered-By, X-AspNet-Version, X-Runtime) revealing exact framework or OS package versions.
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server
  tags: fingerprint,information-disclosure,burp-passive
  classification:
    cvss-score: 0.0
    cvss-vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N
    cwe-id: CWE-200
    owasp-category: A05:2021-Security Misconfiguration
  remediation: |
    Disable verbose server banners and framework fingerprint headers:
    - In Express.js: app.disable('x-powered-by');
    - In Nginx: server_tokens off;
    - In Apache: ServerTokens Prod; ServerSignature Off;
    - In PHP: expose_php = Off in php.ini

requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: or
    matchers:
      - type: header
        part: header
        words:
          - "x-powered-by:"
          - "x-aspnet-version:"
          - "x-runtime:"
          - "server: apache/"
          - "server: nginx/"
          - "server: microsoft-iis/"
          - "server: litespeed/"
          - "server: gunicorn/"
          - "server: uvicorn/"
          - "server: openresty/"
          - "server: cherokee/"
        condition: or
`,
  },
  {
    id: 'robots-txt-disclosure',
    isBuiltin: true,
    rawYaml: `id: robots-txt-disclosure
info:
  name: Robots.txt Sensitive Endpoint Information Leak
  author: nuclei-secops
  severity: info
  description: Parses robots.txt to discover hidden administration paths, private backup folders, or staging directories disclosed in Disallow rules.
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage
  tags: robots,recon,information-disclosure,owasp
  classification:
    cvss-score: 0.0
    cvss-vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N
    cwe-id: CWE-200
    owasp-category: A05:2021-Security Misconfiguration
  remediation: |
    Do not rely on robots.txt for access control. Restrict sensitive administrative, staging, and backup paths using proper authentication, authorization gates, and IP access lists rather than publishing their locations in public robots.txt files.

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
          - "Disallow: /admin"
          - "Disallow: /administrator"
          - "Disallow: /backup"
          - "Disallow: /staging"
          - "Disallow: /internal"
          - "Disallow: /config"
          - "Disallow: /secret"
          - "Disallow: /wp-admin"
          - "Disallow: /api/private"
          - "Disallow: /db"
          - "Disallow: /.git"
        condition: or
`,
  },
  {
    id: 'cookie-security-flags',
    isBuiltin: true,
    rawYaml: `id: cookie-security-flags
info:
  name: Insecure Session Cookie Flags (HttpOnly/Secure)
  author: burp-scanner
  severity: low
  description: Audits Set-Cookie headers for missing HttpOnly, Secure, and SameSite flags that protect session cookies against XSS and cleartext theft.
  reference:
    - https://owasp.org/www-community/controls/SecureFlag
    - https://owasp.org/www-community/HttpOnly
  tags: cookies,session,owasp,burp-passive
  classification:
    cvss-score: 3.1
    cvss-vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N
    cwe-id: CWE-614
    owasp-category: A07:2021-Identification and Authentication Failures
  remediation: |
    Enforce security attributes on all authentication and session cookies:
    - Set 'HttpOnly' to prevent JavaScript access via document.cookie (mitigates XSS cookie theft).
    - Set 'Secure' to ensure cookies are transmitted exclusively over encrypted HTTPS connections.
    - Set 'SameSite=Lax' or 'SameSite=Strict' to protect against Cross-Site Request Forgery (CSRF).

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
    isBuiltin: true,
    rawYaml: `id: sqli-error-signatures
info:
  name: Database Error Trace Signature Detection (SQLi Passive)
  author: nuclei-secops
  severity: high
  description: Checks for database error trace disclosures (MySQL, PostgreSQL, Oracle, SQLite, SQL Server) leaked in application responses upon submitting benign test tokens.
  reference:
    - https://owasp.org/www-community/attacks/SQL_Injection
    - https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
  tags: sqli,injection,database,burp-active
  classification:
    cvss-score: 7.5
    cvss-vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
    cwe-id: CWE-89
    owasp-category: A03:2021-Injection
  remediation: |
    1. Use parameterized queries (Prepared Statements) or an ORM with query parameter binding exclusively.
    2. Disable verbose database error reporting in production HTTP responses; log errors server-side with structured tracking IDs.
    3. Enforce the principle of least privilege on database connection credentials.

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?id=1%27%20OR%201=1--"
      - "{{BaseURL}}/?query=%27"
      - "{{BaseURL}}/?search=%27"
      - "{{BaseURL}}/?cat=1%27"
      - "{{BaseURL}}/?item=1%27"
      - "{{BaseURL}}/?filter=%27"
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
          - "syntax error at or near"
        condition: or
`,
  },
  {
    id: 'xss-reflection-passive',
    isBuiltin: true,
    rawYaml: `id: xss-reflection-passive
info:
  name: Unsanitized Reflected Parameter Canary (XSS)
  author: burp-scanner
  severity: medium
  description: Tests if user-supplied query parameters are reflected verbatim without HTML entity escaping into the DOM response.
  reference:
    - https://owasp.org/www-community/attacks/xss/
    - https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
  tags: xss,injection,reflection,burp-active
  classification:
    cvss-score: 6.1
    cvss-vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N
    cwe-id: CWE-79
    owasp-category: A03:2021-Injection
  remediation: |
    1. Apply context-aware output encoding (HTML entity escaping for DOM text content and attributes).
    2. Enforce a robust Content-Security-Policy (CSP) that blocks inline scripts (no 'unsafe-inline') and restricts script origins.
    3. Use modern frontend frameworks (React, Angular, Vue) which perform automatic context escaping by default.

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?sec_audit_probe=%3Csecprobe%3E"
      - "{{BaseURL}}/?q=%3Csecprobe%3E"
      - "{{BaseURL}}/?search=%3Csecprobe%3E"
      - "{{BaseURL}}/?query=%3Csecprobe%3E"
      - "{{BaseURL}}/?keyword=%3Csecprobe%3E"
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
    isBuiltin: true,
    rawYaml: `id: sensitive-backup-files
info:
  name: Exposed Database & Source Code Backup Dumps
  author: nuclei-secops
  severity: high
  description: Probes for forgotten compressed backups (.zip, .sql, .tar.gz, .bak) left in web root directories leaking source code or database records.
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information
  tags: backup,dumps,high,nuclei
  classification:
    cvss-score: 8.5
    cvss-vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
    cwe-id: CWE-530
    owasp-category: A05:2021-Security Misconfiguration
  remediation: |
    1. Immediately delete or move backup files (.sql, .tar.gz, .zip, .bak) outside the public web root directory.
    2. Add web server block rules denying access to archive and dump extensions:
       In Nginx: location ~* \\.(sql|tar|tar\\.gz|zip|bak|old|dump)$ { deny all; return 404; }
    3. Automate backups to secure, authenticated cloud object storage rather than local web directories.

requests:
  - method: GET
    path:
      - "{{BaseURL}}/backup.sql"
      - "{{BaseURL}}/database.sql"
      - "{{BaseURL}}/dump.sql"
      - "{{BaseURL}}/db.sql"
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
          - "SQLite format 3"
        condition: or
  - method: GET
    path:
      - "{{BaseURL}}/backup.tar.gz"
      - "{{BaseURL}}/backup.zip"
      - "{{BaseURL}}/site-backup.zip"
      - "{{BaseURL}}/database.tar.gz"
      - "{{BaseURL}}/backup.bak"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: content-type
        content-type:
          - "application/gzip"
          - "application/zip"
          - "application/x-tar"
          - "application/x-gzip"
          - "application/octet-stream"
          - "application/x-zip-compressed"
      - type: size
        min-size: 50
`,
  },
  {
    id: 'swagger-openapi-disclosure',
    isBuiltin: true,
    rawYaml: `id: swagger-openapi-disclosure
info:
  name: "Exposed Swagger UI & OpenAPI Specification"
  author: devsecops-auditor
  severity: medium
  description: "Detects exposed interactive Swagger UI or unauthenticated OpenAPI schema specifications disclosing API routes, parameter schemas, and hidden admin endpoints."
  reference:
    - https://owasp.org/www-project-api-security/
  tags: api,swagger,openapi,disclosure,owasp
  classification:
    cvss-score: 5.3
    cwe-id: CWE-200
    owasp-category: A01:2021-Broken Access Control
  remediation: "Disable or protect Swagger UI and OpenAPI JSON/YAML endpoints in production environments behind authentication."

requests:
  - method: GET
    path:
      - "{{BaseURL}}/swagger-ui.html"
      - "{{BaseURL}}/swagger-ui/index.html"
      - "{{BaseURL}}/v2/api-docs"
      - "{{BaseURL}}/v3/api-docs"
      - "{{BaseURL}}/openapi.json"
      - "{{BaseURL}}/swagger.json"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "swagger-ui"
          - "\"openapi\":"
          - "\"swagger\":"
          - "SwaggerUIBundle"
        condition: or
`,
  },
  {
    id: 'graphql-introspection-enabled',
    isBuiltin: true,
    rawYaml: `id: graphql-introspection-enabled
info:
  name: "GraphQL Schema Introspection Enabled"
  author: devsecops-auditor
  severity: medium
  description: "Checks if GraphQL endpoint allows unauthenticated __schema introspection query, allowing attackers to map all queries, mutations, and backend data models."
  reference:
    - https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
  tags: graphql,api,introspection,owasp
  classification:
    cvss-score: 5.3
    cwe-id: CWE-200
    owasp-category: A01:2021-Broken Access Control
  remediation: "Disable introspection query in production GraphQL servers (e.g., Apollo Server introspection: false)."

requests:
  - method: POST
    path:
      - "{{BaseURL}}/graphql"
      - "{{BaseURL}}/api/graphql"
      - "{{BaseURL}}/query"
    headers:
      Content-Type: "application/json"
    body: "{\\"query\\": \\"{ __schema { types { name } } }\\"}"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "\"__schema\""
          - "\"types\""
        condition: and
`,
  },
  {
    id: 'spring-boot-actuator-leak',
    isBuiltin: true,
    rawYaml: `id: spring-boot-actuator-leak
info:
  name: "Spring Boot Actuator Endpoints Unauthenticated Exposure"
  author: devsecops-auditor
  severity: high
  description: "Detects exposed Spring Boot Actuator endpoints (/actuator, /actuator/env, /actuator/heapdump, /actuator/beans) leaking environment credentials and memory structures."
  reference:
    - https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html
  tags: spring,actuator,java,high,owasp
  classification:
    cvss-score: 7.5
    cwe-id: CWE-200
    owasp-category: A05:2021-Security Misconfiguration
  remediation: "Configure management.endpoints.web.exposure.include=health,info and require Spring Security authentication for sensitive endpoints."

requests:
  - method: GET
    path:
      - "{{BaseURL}}/actuator"
      - "{{BaseURL}}/actuator/env"
      - "{{BaseURL}}/actuator/mappings"
      - "{{BaseURL}}/actuator/beans"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "_links"
          - "propertySources"
          - "contexts"
          - "actuator"
        condition: or
`,
  },
  {
    id: 'phpmyadmin-panel-exposure',
    isBuiltin: true,
    rawYaml: `id: phpmyadmin-panel-exposure
info:
  name: "Public phpMyAdmin Database Administration Panel"
  author: devsecops-auditor
  severity: medium
  description: "Detects publicly accessible phpMyAdmin database management portal, exposing the database server to brute-force attacks."
  reference:
    - https://www.phpmyadmin.net/
  tags: phpmyadmin,db,mysql,exposure,owasp
  classification:
    cvss-score: 5.3
    cwe-id: CWE-200
    owasp-category: A01:2021-Broken Access Control
  remediation: "Restrict phpMyAdmin access to internal VPN or whitelist trusted administrative IP addresses in web server config."

requests:
  - method: GET
    path:
      - "{{BaseURL}}/phpmyadmin/"
      - "{{BaseURL}}/pma/"
      - "{{BaseURL}}/phpMyAdmin/"
      - "{{BaseURL}}/mysql/"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "phpMyAdmin"
          - "pma_username"
          - "phpmyadmin.net"
        condition: or
`,
  },
  {
    id: 'laravel-debug-mode-leak',
    isBuiltin: true,
    rawYaml: `id: laravel-debug-mode-leak
info:
  name: "Laravel APP_DEBUG Mode Enabled"
  author: devsecops-auditor
  severity: high
  description: "Detects Laravel application with APP_DEBUG=true showing Ignition or Whoops error pages leaking database passwords, APP_KEY, and full stack traces."
  reference:
    - https://laravel.com/docs/configuration#environment-configuration
  tags: laravel,php,debug,secrets,owasp
  classification:
    cvss-score: 7.5
    cwe-id: CWE-200
    owasp-category: A05:2021-Security Misconfiguration
  remediation: "Set APP_DEBUG=false in production .env configuration."

requests:
  - method: GET
    path:
      - "{{BaseURL}}/_ignition/health-check"
      - "{{BaseURL}}/?probe_trigger_error_404_test=1"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
          - 500
      - type: word
        part: body
        words:
          - "Ignition"
          - "laravel_session"
          - "Environment & details"
          - "APP_KEY"
        condition: or
`,
  }
];

export const DEFAULT_TEMPLATES: YamlTemplate[] = RAW_DEFAULT_TEMPLATES.map(t => syncTemplateWithYaml(t));
