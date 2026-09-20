import { ExtensionManifest } from '../types';

export const DEFAULT_EXTENSIONS: ExtensionManifest[] = [
  {
    id: 'ext-owasp-api',
    name: 'OWASP API Security Top 10 Suite',
    version: '1.4.0',
    author: 'OWASP API Security Project',
    description: 'Specialized API auditing rules for REST & GraphQL endpoints, covering BOLA, Mass Assignment, and Unauthenticated Introspection.',
    category: 'owasp',
    installed: true,
    enabled: true,
    templatesCount: 2,
    repositoryUrl: 'https://github.com/OWASP/API-Security',
    templates: [
      {
        id: 'graphql-introspection-enabled',
        name: 'GraphQL Introspection Query Enabled',
        severity: 'medium',
        description: 'Detects whether production GraphQL endpoints expose the entire internal schema via __schema introspection.',
        tags: ['owasp-api', 'graphql', 'recon'],
        enabled: true,
        isBuiltin: false,
        rawYaml: `id: graphql-introspection-enabled
info:
  name: GraphQL Introspection Query Enabled
  author: DevSecOps-Auditor
  severity: medium
  description: Verifies if GraphQL endpoints leak full backend data structure via public schema introspection queries.
  classification:
    cvss-score: 5.3
    cwe-id: CWE-200
    owasp-category: A05:2021-Security Misconfiguration
requests:
  - method: POST
    path:
      - "{{BaseURL}}/graphql"
      - "{{BaseURL}}/api/graphql"
    headers:
      Content-Type: application/json
    body: '{"query": "{ __schema { types { name } } }"}'
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "__schema"
          - "types"
`,
      },
      {
        id: 'api-debug-endpoints',
        name: 'Exposed Interactive API Documentation / Actuator Probe',
        severity: 'low',
        description: 'Checks if interactive OpenAPI/Swagger UI or Spring Boot Actuator endpoints are exposed without authentication.',
        tags: ['owasp-api', 'swagger', 'exposure', 'defense'],
        enabled: true,
        isBuiltin: false,
        rawYaml: `id: api-debug-endpoints
info:
  name: Exposed Interactive API Documentation & Actuator Endpoints
  author: DevSecOps-Auditor
  severity: low
  description: Detects unauthenticated Swagger UI, OpenAPI JSON definitions, or Spring Boot Actuator endpoints.
  classification:
    cvss-score: 3.1
    cwe-id: CWE-200
    owasp-category: A05:2021-Security Misconfiguration
requests:
  - method: GET
    path:
      - "{{BaseURL}}/v2/api-docs"
      - "{{BaseURL}}/v3/api-docs"
      - "{{BaseURL}}/swagger-ui/index.html"
      - "{{BaseURL}}/swagger-ui.html"
      - "{{BaseURL}}/actuator/health"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - '"swagger":"2.0"'
          - '"openapi":"3.'
          - 'id="swagger-ui"'
          - 'swagger-ui-bundle.js'
          - '{"status":"UP"'
          - '"_links":{"self":'
        condition: or
`,
      },
    ],
  },
  {
    id: 'ext-burp-active',
    name: 'Burp Suite Active Injection & Fuzzing Pack',
    version: '2.1.2',
    author: 'PortSwigger Community Heuristics',
    description: 'Active canaries inspired by Burp Suite Professional Scanner for SSRF, Directory Traversal, and Command Injection indicators.',
    category: 'burp',
    installed: true,
    enabled: true,
    templatesCount: 2,
    repositoryUrl: 'https://portswigger.net/burp/vulnerability-scanner',
    templates: [
      {
        id: 'ssrf-cloud-metadata-probe',
        name: 'Cloud Instance Metadata Service (IMDS) Exposure',
        severity: 'critical',
        description: 'Tests if reverse proxy or endpoint forwards internal queries to cloud metadata (AWS/GCP/Azure 169.254.169.254).',
        tags: ['burp-active', 'ssrf', 'cloud'],
        enabled: true,
        isBuiltin: false,
        rawYaml: `id: ssrf-cloud-metadata-probe
info:
  name: Cloud Instance Metadata Service (IMDS) Exposure
  author: DevSecOps-Auditor
  severity: critical
  description: Detects Server-Side Request Forgery vectors reaching cloud metadata addresses.
  classification:
    cvss-score: 9.8
    cwe-id: CWE-918
    owasp-category: A10:2021-Server-Side Request Forgery (SSRF)
requests:
  - method: GET
    path:
      - "{{BaseURL}}/?url=http://169.254.169.254/latest/meta-data/"
      - "{{BaseURL}}/proxy?target=http://169.254.169.254/latest/meta-data/"
    matchers-condition: or
    matchers:
      - type: word
        part: body
        words:
          - "ami-id"
          - "instance-id"
          - "security-credentials"
`,
      },
      {
        id: 'directory-traversal-canary',
        name: 'Directory Traversal & Path Manipulation Canary',
        severity: 'high',
        description: 'Probes for Local File Inclusion (LFI) and path traversal using safe POSIX /etc/passwd patterns.',
        tags: ['burp-active', 'lfi', 'traversal'],
        enabled: true,
        isBuiltin: false,
        rawYaml: `id: directory-traversal-canary
info:
  name: Directory Traversal & Path Manipulation Canary
  author: DevSecOps-Auditor
  severity: high
  description: Checks if URL parameters allow escaping webroot into server system files.
  classification:
    cvss-score: 7.5
    cwe-id: CWE-22
    owasp-category: A01:2021-Broken Access Control
requests:
  - method: GET
    path:
      - "{{BaseURL}}/?file=../../../../etc/passwd"
      - "{{BaseURL}}/?page=../../../../etc/passwd"
      - "{{BaseURL}}/?path=../../../../etc/passwd"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: regex
        part: body
        regex:
          - "root:.*:0:0:"
`,
      },
    ],
  },
  {
    id: 'ext-subdomain-takeover',
    name: 'Subdomain Takeover & CNAME Heuristics',
    version: '1.2.0',
    author: 'EdOverflow & ProjectDiscovery Canaries',
    description: 'Detects dangling DNS records and orphan CNAME records pointing to unclaimed third-party cloud assets (GitHub, AWS S3, Heroku).',
    category: 'recon',
    installed: true,
    enabled: true,
    templatesCount: 1,
    repositoryUrl: 'https://github.com/EdOverflow/can-i-take-over-xyz',
    templates: [
      {
        id: 'subdomain-takeover-signatures',
        name: 'Dangling CNAME Cloud Service Fingerprint',
        severity: 'high',
        description: 'Identifies provider signatures indicating an orphan cloud bucket or app that can be registered by an attacker.',
        tags: ['takeover', 'dns', 'subfinder'],
        enabled: true,
        isBuiltin: false,
        rawYaml: `id: subdomain-takeover-signatures
info:
  name: Dangling CNAME Cloud Service Fingerprint
  author: DevSecOps-Auditor
  severity: high
  description: Checks for known provider error fingerprints indicating the target CNAME points to an unclaimed cloud resource.
  classification:
    cvss-score: 8.2
    cwe-id: CWE-284
    owasp-category: A05:2021-Security Misconfiguration
requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: or
    matchers:
      - type: word
        part: body
        words:
          - "There isn't a GitHub Pages site here"
          - "NoSuchBucket"
          - "The specified bucket does not exist"
          - "No such app"
          - "herokucdn.com"
          - "project not found"
          - "Fastly error: unknown domain"
`,
      },
    ],
  },
  {
    id: 'ext-jwt-security',
    name: 'JWT & Token Security Verifier',
    version: '1.0.5',
    author: 'DevSecOps Community',
    description: 'Probes authorization bearer token handling for algorithmic confusion and insecure session practices.',
    category: 'custom',
    installed: false,
    enabled: false,
    templatesCount: 1,
    repositoryUrl: 'https://jwt.io',
    templates: [
      {
        id: 'jwt-none-algorithm-probe',
        name: 'JWT Algorithm "none" Vulnerability Check',
        severity: 'critical',
        description: 'Tests if API endpoints accept unsigned JSON Web Tokens with alg=none in header.',
        tags: ['jwt', 'auth', 'tokens'],
        enabled: true,
        isBuiltin: false,
        rawYaml: `id: jwt-none-algorithm-probe
info:
  name: JWT Algorithm "none" Vulnerability Check
  author: DevSecOps-Auditor
  severity: critical
  description: Detects authentication bypass when alg=none is passed in JWT header.
  classification:
    cvss-score: 9.8
    cwe-id: CWE-287
    owasp-category: A07:2021-Identification and Authentication Failures
requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/user"
      - "{{BaseURL}}/api/me"
      - "{{BaseURL}}/api/v1/profile"
    headers:
      Authorization: "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImFkbWluIjp0cnVlfQ."
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "admin"
`,
      },
    ],
  },
];
