import { ExtensionManifest } from '../types';
import { syncTemplateWithYaml } from '../utils/templateParser';

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
      syncTemplateWithYaml({
        id: 'graphql-introspection-enabled',
        isBuiltin: false,
        rawYaml: `id: graphql-introspection-enabled
info:
  name: GraphQL Introspection Query Enabled
  author: devsecops-auditor
  severity: medium
  description: Verifies if production GraphQL endpoints leak full backend data structure and types via public schema introspection queries.
  reference:
    - https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL
  tags: owasp-api,graphql,recon,information-disclosure
  classification:
    cvss-score: 5.3
    cvss-vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
    cwe-id: CWE-200
    owasp-category: A05:2021-Security Misconfiguration
  remediation: |
    Disable GraphQL Schema Introspection in production environments.
    In Apollo Server: introspection: process.env.NODE_ENV !== 'production'
    In GraphQL Yoga: useDisableIntrospection() plugin

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
      }),
      syncTemplateWithYaml({
        id: 'api-debug-endpoints',
        isBuiltin: false,
        rawYaml: `id: api-debug-endpoints
info:
  name: Exposed Interactive API Documentation / Actuator Probe
  author: devsecops-auditor
  severity: low
  description: Checks if interactive OpenAPI/Swagger UI or Spring Boot Actuator health/metric endpoints are exposed without authentication.
  reference:
    - https://owasp.org/www-project-api-security/
  tags: owasp-api,swagger,exposure,defense
  classification:
    cvss-score: 3.1
    cvss-vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
    cwe-id: CWE-200
    owasp-category: A05:2021-Security Misconfiguration
  remediation: |
    Restrict public access to Swagger UI, OpenAPI JSON documentation, and Actuator health/metric endpoints using authentication middleware or internal network firewall rules.

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
      }),
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
      syncTemplateWithYaml({
        id: 'ssrf-cloud-metadata-probe',
        isBuiltin: false,
        rawYaml: `id: ssrf-cloud-metadata-probe
info:
  name: Cloud Instance Metadata Service (IMDS) Exposure
  author: devsecops-auditor
  severity: critical
  description: Tests if proxy parameters or URL handlers forward queries to internal cloud metadata addresses (AWS/GCP/Azure 169.254.169.254).
  reference:
    - https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
    - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
  tags: burp-active,ssrf,cloud,critical
  classification:
    cvss-score: 9.8
    cvss-vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N
    cwe-id: CWE-918
    owasp-category: A10:2021-Server-Side Request Forgery (SSRF)
  remediation: |
    1. Enforce strict outbound URL validation against private, loopback, and link-local IP blocks (RFC 1918, RFC 3927).
    2. Enforce IMDSv2 (Session token requirement) with hop limit = 1 on AWS EC2 instances.
    3. Disable unnecessary proxy forwarding endpoints or require strong API key authentication.

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
      }),
      syncTemplateWithYaml({
        id: 'directory-traversal-canary',
        isBuiltin: false,
        rawYaml: `id: directory-traversal-canary
info:
  name: Directory Traversal & Path Manipulation Canary
  author: devsecops-auditor
  severity: high
  description: Probes for Local File Inclusion (LFI) and path traversal using safe POSIX /etc/passwd patterns in URL parameters.
  reference:
    - https://owasp.org/www-community/attacks/Path_Traversal
  tags: burp-active,lfi,traversal,high
  classification:
    cvss-score: 7.5
    cvss-vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
    cwe-id: CWE-22
    owasp-category: A01:2021-Broken Access Control
  remediation: |
    1. Use path normalization with path.resolve() and verify the resolved path starts with the allowed base directory.
    2. Avoid passing raw user input directly to filesystem APIs (fs.readFile, open).
    3. Use an indirect map (IDs or keys) instead of actual file path parameters.

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?file=../../../../etc/passwd"
      - "{{BaseURL}}/?page=../../../../etc/passwd"
      - "{{BaseURL}}/?path=../../../../etc/passwd"
      - "{{BaseURL}}/?doc=../../../../etc/passwd"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "root:x:0:0:"
          - "daemon:"
          - "bin/bash"
          - "bin/sh"
        condition: or
`,
      }),
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
      syncTemplateWithYaml({
        id: 'subdomain-takeover-signatures',
        isBuiltin: false,
        rawYaml: `id: subdomain-takeover-signatures
info:
  name: Dangling CNAME Cloud Service Fingerprint
  author: devsecops-auditor
  severity: high
  description: Checks for known provider error fingerprints indicating the target CNAME points to an unclaimed cloud resource.
  reference:
    - https://github.com/EdOverflow/can-i-take-over-xyz
  tags: takeover,dns,subfinder,recon
  classification:
    cvss-score: 8.2
    cvss-vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
    cwe-id: CWE-284
    owasp-category: A05:2021-Security Misconfiguration
  remediation: |
    1. Delete dangling CNAME records from DNS zone files immediately when decommissioning cloud services.
    2. Claim or reclaim the associated cloud resource name (AWS S3 bucket, GitHub Pages repo, Heroku app) before modifying DNS.

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
      }),
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
      syncTemplateWithYaml({
        id: 'jwt-none-algorithm-probe',
        isBuiltin: false,
        rawYaml: `id: jwt-none-algorithm-probe
info:
  name: 'JWT Algorithm "none" Vulnerability Check'
  author: devsecops-auditor
  severity: critical
  description: Detects authentication bypass when alg=none is passed in JWT header without signature validation.
  reference:
    - https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
  tags: jwt,auth,tokens,critical
  classification:
    cvss-score: 9.8
    cvss-vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cwe-id: CWE-287
    owasp-category: A07:2021-Identification and Authentication Failures
  remediation: |
    1. Explicitly reject JWT tokens with alg="none" in token verification configuration.
    2. Enforce strict asymmetric (RS256/ES256) or symmetric (HS256) algorithm whitelisting in JWT parser.

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
      }),
    ],
  },
];
