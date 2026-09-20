#!/usr/bin/env python3
"""
Cybersecurity Vulnerability Audit Scanner - Standalone Python CLI & Engine
Supports both standard library (zero-dependency fallback) and requests/rich if installed.
Usage: python3 cyber_audit.py -u https://example.com -p high
"""

import argparse
import json
import os
import re
import ssl
import sys
import time
import uuid
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# Optional requests library
try:
    import requests
    import urllib3
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Optional rich library
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None

# ANSI Terminal Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

SEVERITY_COLORS = {
    "critical": RED + BOLD,
    "high": RED,
    "medium": YELLOW,
    "low": CYAN,
    "info": DIM,
}

BANNER = f"""{CYAN}{BOLD}
   ____      _               _             _ _ _   
  / ___|   _| |__   ___ _ __/ \  _   _  __| (_) |_ 
 | |  | | | | '_ \ / _ \ '__/ _ \| | | |/ _` | | __|
 | |__| |_| | |_) |  __/ | / ___ \ |_| | (_| | | |_ 
  \____\__, |_.__/ \___|_|/_/   \_\__,_|\__,_|_|\__|
       |___/  {RESET}{DIM}Vulnerability & Compliance Suite v2.4.0 (Hardened Engine){RESET}
"""

SECURITY_HEADERS = [
    {
        "name": "Content-Security-Policy",
        "key": "content-security-policy",
        "description": "Protects against Cross-Site Scripting (XSS) and data injection attacks.",
        "severity": "medium",
        "remediation": "Add 'Content-Security-Policy: default-src \\'self\\'; script-src \\'self\\' https:;' header.",
    },
    {
        "name": "X-Frame-Options",
        "key": "x-frame-options",
        "description": "Protects against Clickjacking attacks by forbidding iframe framing.",
        "severity": "medium",
        "remediation": "Add 'X-Frame-Options: SAMEORIGIN' header.",
    },
    {
        "name": "X-Content-Type-Options",
        "key": "x-content-type-options",
        "description": "Prevents MIME-sniffing attacks.",
        "severity": "low",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
    },
    {
        "name": "Strict-Transport-Security",
        "key": "strict-transport-security",
        "description": "Enforces HTTPS connections (HSTS).",
        "severity": "medium",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header.",
    },
    {
        "name": "Referrer-Policy",
        "key": "referrer-policy",
        "description": "Governs how much referrer information should be included with requests.",
        "severity": "low",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
    },
    {
        "name": "Permissions-Policy",
        "key": "permissions-policy",
        "description": "Restricts browser features like camera, microphone, and geolocation.",
        "severity": "low",
        "remediation": "Add 'Permissions-Policy: camera=(), microphone=(), geolocation=()' header.",
    },
]

PROBES = [
    {
        "id": "env-exposure",
        "name": "Environment Config (.env) Exposure",
        "path": "/.env",
        "severity": "critical",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-200",
        "category": "A05:2021-Security Misconfiguration",
        "indicators": ["DB_PASSWORD", "APP_KEY", "AWS_SECRET", "DATABASE_URL", "JWT_SECRET", "DB_HOST="],
        "remediation": "Block access to hidden files (.*) and move configuration files outside web root.",
    },
    {
        "id": "git-config-exposure",
        "name": "Git Repository Metadata Exposure (.git/config)",
        "path": "/.git/config",
        "severity": "high",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-538",
        "category": "A05:2021-Security Misconfiguration",
        "indicators": ["[core]", "[remote \"origin\"]", "repositoryformatversion"],
        "remediation": "Deny web server access to .git directories.",
    },
    {
        "id": "spring-boot-actuator",
        "name": "Exposed Spring Boot Actuator Endpoint",
        "path": "/actuator/env",
        "severity": "high",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-200",
        "category": "A01:2021-Broken Access Control",
        "indicators": ["activeProfiles", "propertySources", "spring.datasource"],
        "remediation": "Set management.endpoints.web.exposure.exclude=* or bind actuator to localhost.",
    },
    {
        "id": "swagger-api-docs",
        "name": "Swagger / OpenAPI UI Public Exposure",
        "path": "/swagger-ui.html",
        "severity": "info",
        "cvss": 0.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "cwe": "CWE-200",
        "category": "A05:2021-Security Misconfiguration",
        "indicators": ["swagger-ui", "openapi-doc", "Swagger UI", "swagger-ui-bundle"],
        "remediation": "Restrict API documentation to authenticated developers.",
    },
    {
        "id": "sensitive-backup-files",
        "name": "Exposed Database & Source Code Backup Dumps",
        "path": "/backup.sql",
        "severity": "high",
        "cvss": 8.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-530",
        "category": "A05:2021-Security Misconfiguration",
        "indicators": ["-- MySQL dump", "INSERT INTO", "CREATE TABLE", "PostgreSQL database dump", "SQLite format 3"],
        "remediation": "Delete public backup archives and configure web server to deny access to .sql, .tar.gz, .zip, and .bak files.",
    },
    {
        "id": "robots-txt-disclosure",
        "name": "Robots.txt Sensitive Endpoint Information Leak",
        "path": "/robots.txt",
        "severity": "info",
        "cvss": 0.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "cwe": "CWE-200",
        "category": "A05:2021-Security Misconfiguration",
        "indicators": [
            "Disallow: /admin", "Disallow: /backup", "Disallow: /staging",
            "Disallow: /internal", "Disallow: /config", "Disallow: /secret",
            "Disallow: /wp-admin", "Disallow: /db", "Disallow: /.git"
        ],
        "remediation": "Do not rely on robots.txt for security. Protect private administration endpoints using proper authorization gates.",
    },
]


def normalize_target(url: str) -> str:
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url.rstrip("/")


def is_soft_404(body: str, content_type: str = "") -> bool:
    """Heuristic soft-404 detector preventing false positive alerts on custom error pages."""
    lower = body.lower()
    
    if any(h in lower for h in [
        "<title>404", "<title>page not found", "<title>not found",
        "<title>halaman tidak ditemukan", "<h1>404", "<h1>page not found",
        "<h1>not found", "<h1>halaman tidak ditemukan", "<h2>404 not found</h2>"
    ]):
        return True

    if any(j in lower for j in [
        '"status":404', '"status": 404', '"error":"not found"',
        '"error": "not found"', '"message":"not found"', '"message": "not found"'
    ]):
        return True

    return False


def http_fetch(
    url: str,
    timeout: int = 8,
    verify_ssl: bool = True,
    proxy: Optional[str] = None
) -> Tuple[int, Dict[str, str], str, int]:
    """
    Robust universal HTTP fetcher with SSL verification and proxy support.
    Returns: (status_code, headers_dict_lower, body_text, latency_ms)
    """
    t0 = time.time()
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 DevSecOps-Auditor/2.4"

    if HAS_REQUESTS:
        session = requests.Session()
        session.headers.update({"User-Agent": user_agent})
        if proxy:
            session.proxies = {"http": proxy, "https": proxy}
        
        resp = session.get(url, timeout=timeout, allow_redirects=True, verify=verify_ssl)
        latency = int((time.time() - t0) * 1000)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status_code, headers, resp.text, latency

    # Fallback to standard library urllib
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    
    opener = urllib.request.build_opener(*handlers)
    
    try:
        with opener.open(req, timeout=timeout) as response:
            latency = int((time.time() - t0) * 1000)
            status = response.getcode()
            headers = {k.lower(): v for k, v in response.headers.items()}
            body = response.read().decode('utf-8', errors='ignore')
            return status, headers, body, latency
    except urllib.error.HTTPError as e:
        latency = int((time.time() - t0) * 1000)
        headers = {k.lower(): v for k, v in e.headers.items()} if hasattr(e, 'headers') else {}
        body = e.read().decode('utf-8', errors='ignore') if hasattr(e, 'read') else ''
        return e.code, headers, body, latency


def check_security_headers(
    target_url: str,
    timeout: int,
    verify_ssl: bool,
    proxy: Optional[str] = None
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        status, headers_lower, _, latency = http_fetch(target_url, timeout, verify_ssl, proxy)
    except ssl.SSLCertVerificationError as e:
        return None, f"TLS/SSL Certificate Verification Failed: {str(e)} (Use -k/--insecure for testing)"
    except Exception as e:
        err_msg = str(e)
        if "CERTIFICATE_VERIFY_FAILED" in err_msg or "certificate verify failed" in err_msg.lower():
            return None, f"TLS/SSL Certificate Verification Failed: {err_msg} (Use -k/--insecure for testing)"
        return None, f"Connection error: {err_msg}"

    missing_sub = []
    for sh in SECURITY_HEADERS:
        if sh["key"] not in headers_lower:
            missing_sub.append({
                "id": f"missing-{sh['key']}",
                "name": f"Missing {sh['name']}",
                "severity": sh["severity"],
                "evidence": f"Header '{sh['key']}' is absent from HTTP response."
            })

    if not missing_sub:
        return None, None

    has_med = any(s["severity"] == "medium" for s in missing_sub)
    parent_severity = "low" if len(missing_sub) < 3 else ("medium" if has_med else "low")
    cvss_score = 4.3 if parent_severity == "medium" else 2.6
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"
    evidence_summary = ", ".join([f"'{s['name'].replace('Missing ', '')}'" for s in missing_sub])

    finding = {
        "id": f"finding-headers-{uuid.uuid4().hex[:8]}",
        "templateId": "owasp-security-headers",
        "findingType": "aggregated",
        "name": "Missing OWASP HTTP Security Headers",
        "severity": parent_severity,
        "cvssScore": cvss_score,
        "cvssVector": cvss_vector,
        "cweId": "CWE-693",
        "owaspCategory": "A05:2021-Security Misconfiguration",
        "url": target_url,
        "matchedAt": target_url,
        "description": f"The target web server responds with status {status} but omits {len(missing_sub)} essential defense-in-depth security headers.",
        "evidence": f"Missing Headers ({len(missing_sub)}): {evidence_summary}\nResponse Latency: {latency}ms | Status: {status}",
        "subFindings": missing_sub,
        "remediation": "Configure your reverse proxy (Nginx, Apache, Cloudflare) to attach strict Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and Strict-Transport-Security headers.",
        "references": [
            "https://owasp.org/www-project-secure-headers/",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"
        ]
    }
    return finding, None


def audit_target(
    target_url: str,
    proxy: Optional[str] = None,
    timeout: int = 8,
    verify_ssl: bool = True
) -> Dict[str, Any]:
    findings = []
    diagnostics = []

    # 1. Check Security Headers
    sh_finding, sh_err = check_security_headers(target_url, timeout, verify_ssl, proxy)
    if sh_err:
        diagnostics.append({"probe": "root_headers", "status": "failed", "error": sh_err})
    elif sh_finding:
        findings.append(sh_finding)
        diagnostics.append({"probe": "root_headers", "status": "completed", "findings": 1})
    else:
        diagnostics.append({"probe": "root_headers", "status": "clean"})

    # 2. Check Probe Endpoints
    for probe in PROBES:
        probe_url = f"{target_url}{probe['path']}"
        try:
            status, headers, body, latency = http_fetch(probe_url, timeout, verify_ssl, proxy)
            
            if status == 200:
                content_type = headers.get("content-type", "")
                matched_ind = [ind for ind in probe["indicators"] if ind in body]
                
                if matched_ind and not is_soft_404(body, content_type):
                    findings.append({
                        "id": f"finding-{probe['id']}-{uuid.uuid4().hex[:8]}",
                        "templateId": probe["id"],
                        "findingType": "atomic",
                        "name": probe["name"],
                        "severity": probe["severity"],
                        "cvssScore": probe["cvss"],
                        "cvssVector": probe["cvss_vector"],
                        "cweId": probe["cwe"],
                        "owaspCategory": probe["category"],
                        "url": probe_url,
                        "matchedAt": probe_url,
                        "description": f"Exposed sensitive file/endpoint detected at '{probe['path']}' with HTTP 200 response.",
                        "evidence": f"Matched signatures: {', '.join(matched_ind)}\nHTTP Status: 200 OK | Body Length: {len(body)} chars",
                        "remediation": probe["remediation"],
                        "references": ["https://owasp.org/Top10/"]
                    })
                    diagnostics.append({"probe": probe["id"], "path": probe["path"], "status": "vulnerable"})
                else:
                    diagnostics.append({"probe": probe["id"], "path": probe["path"], "status": "clean"})
            else:
                diagnostics.append({"probe": probe["id"], "path": probe["path"], "status": "clean", "http_status": status})

        except Exception as e:
            diagnostics.append({"probe": probe["id"], "path": probe["path"], "status": "failed", "error": str(e)})

    return {
        "target": target_url,
        "findings": findings,
        "diagnostics": diagnostics,
        "scan_time": datetime.now(timezone.utc).isoformat()
    }


def print_finding_rich(finding: Dict[str, Any]):
    sev = finding["severity"].lower()
    sev_style = "bold red" if sev == "critical" else ("red" if sev == "high" else ("yellow" if sev == "medium" else "cyan"))
    
    title = f"[{sev.upper()}] {finding['name']}"
    content = f"[bold]URL:[/bold] {finding['matchedAt']}\n"
    content += f"[bold]CWE / OWASP:[/bold] {finding['cweId']} | {finding['owaspCategory']}\n"
    content += f"[bold]CVSS Score:[/bold] {finding['cvssScore']} ({finding.get('cvssVector', 'N/A')})\n"
    content += f"[bold]Evidence:[/bold]\n{finding['evidence']}\n\n"
    content += f"[green bold]Remediation:[/green bold] {finding['remediation']}"

    console.print(Panel(content, title=title, border_style=sev_style, expand=False))


def print_finding_plain(finding: Dict[str, Any]):
    sev = finding["severity"].lower()
    color = SEVERITY_COLORS.get(sev, RESET)
    badge = f"{color}[{sev.upper()}]{RESET}"
    type_tag = f"{MAGENTA}[AGGREGATED]{RESET}" if finding.get("findingType") == "aggregated" else f"{CYAN}[ATOMIC]{RESET}"

    print(f"\n{badge} {type_tag} {BOLD}{finding['name']}{RESET}")
    print(f"  {DIM}URL:{RESET}        {finding['matchedAt']}")
    print(f"  {DIM}CWE / OWASP:{RESET} {finding['cweId']} | {finding['owaspCategory']}")
    print(f"  {DIM}CVSS Score:{RESET}  {finding['cvssScore']} ({finding.get('cvssVector', 'N/A')})")
    print(f"  {DIM}Description:{RESET} {finding['description']}")
    
    if finding.get("subFindings"):
        print(f"  {YELLOW}Sub-Checks ({len(finding['subFindings'])} items):{RESET}")
        for sub in finding["subFindings"]:
            print(f"    - {sub['name']}: {DIM}{sub['evidence']}{RESET}")
            
    print(f"  {GREEN}Remediation:{RESET} {finding['remediation']}")


def main():
    parser = argparse.ArgumentParser(
        description="Cybersecurity Vulnerability Audit Scanner CLI & Engine",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  python3 cyber_audit.py -u https://example.com
  python3 cyber_audit.py -u https://example.com -p high -x http://127.0.0.1:8080 -k
  python3 cyber_audit.py -l subdomains.txt -o report.json
        """
    )
    parser.add_argument("-u", "--url", help="Target URL to scan (e.g. https://example.com)")
    parser.add_argument("-l", "--list", help="Path to file containing list of target URLs/subdomains (one per line)")
    parser.add_argument("-p", "--severity", choices=["critical", "high", "medium", "low", "info", "all"], default="all", help="Minimum severity threshold to display (default: all)")
    parser.add_argument("-x", "--proxy", help="Upstream HTTP/SOCKS5 proxy (e.g. http://127.0.0.1:8080 for Burp Suite)")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable SSL certificate verification (opt-in for self-signed certs)")
    parser.add_argument("-o", "--output", help="Save output results to JSON file (e.g. report.json)")
    parser.add_argument("-t", "--timeout", type=int, default=8, help="HTTP request timeout in seconds (default: 8)")
    parser.add_argument("--silent", action="store_true", help="Silent mode (suppress banner)")

    args = parser.parse_args()

    verify_ssl = not args.insecure
    if not verify_ssl and HAS_REQUESTS:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not args.silent:
        print(BANNER)
        if not verify_ssl:
            print(f"{YELLOW}[!] Notice: TLS certificate validation is disabled (--insecure active).{RESET}\n")

    if not args.url and not args.list:
        parser.print_help()
        sys.exit(1)

    targets = []
    if args.url:
        targets.append(normalize_target(args.url))
    if args.list:
        if not os.path.exists(args.list):
            print(f"{RED}[!] Error: File '{args.list}' not found.{RESET}")
            sys.exit(1)
        with open(args.list, "r") as f:
            for line in f:
                clean = line.strip()
                if clean and not clean.startswith("#"):
                    targets.append(normalize_target(clean))

    print(f"{CYAN}[*] Loaded {len(targets)} target(s). Starting security audit...{RESET}")
    if args.proxy:
        print(f"{YELLOW}[*] Routing traffic through proxy: {args.proxy}{RESET}")

    all_results = []
    total_findings_count = 0
    total_failed_probes = 0

    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    min_level = sev_order.get(args.severity, -1)

    for idx, target in enumerate(targets, 1):
        print(f"\n{BOLD}[{idx}/{len(targets)}] Probing: {target}{RESET}")
        audit_res = audit_target(target, proxy=args.proxy, timeout=args.timeout, verify_ssl=verify_ssl)
        findings = audit_res["findings"]
        diagnostics = audit_res["diagnostics"]

        failed = [d for d in diagnostics if d.get("status") == "failed"]
        if failed:
            total_failed_probes += len(failed)
            for f_diag in failed:
                print(f"  {YELLOW}[!] Probe Warning ({f_diag['probe']}): {f_diag.get('error')}{RESET}")

        filtered = []
        for f in findings:
            f_level = sev_order.get(f["severity"].lower(), 0)
            if args.severity == "all" or f_level >= min_level:
                filtered.append(f)
                if HAS_RICH and console:
                    print_finding_rich(f)
                else:
                    print_finding_plain(f)

        total_findings_count += len(filtered)
        all_results.append({
            "target": target,
            "scan_time": audit_res["scan_time"],
            "findings_count": len(filtered),
            "findings": filtered,
            "diagnostics": diagnostics
        })

    print(f"\n{BOLD}══════════════════════════════════════════════════{RESET}")
    print(f"{GREEN}[✓] Scan Completed!{RESET} Total findings identified: {BOLD}{total_findings_count}{RESET}")
    if total_failed_probes > 0:
        print(f"{YELLOW}[!] Diagnostic: {total_failed_probes} probe requests failed due to timeout/SSL/connection errors.{RESET}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"{CYAN}[i] Results exported successfully to: {args.output}{RESET}")


if __name__ == "__main__":
    main()
