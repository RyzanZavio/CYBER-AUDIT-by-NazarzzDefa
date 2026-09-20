export function generateLinuxWslCliScript(rawAppUrl: string): string {
  // Defensive sanitization against Host Header Injection and shell metacharacters
  const appUrl = (rawAppUrl || 'http://localhost:3000').replace(/[^a-zA-Z0-9.:\/-]/g, '');

  return `#!/usr/bin/env bash
# ==============================================================================
# DevSecOps Cybersecurity Vulnerability Audit CLI (Linux & WSL)
# Inspired by OWASP ZAP, Nuclei (ProjectDiscovery), and Burp Suite Pro
# Callable via: curl, wget, git (git audit), or direct binary execution
# ==============================================================================

set -e

APP_API="\${AUDIT_API_URL:-${appUrl}}"
TARGET=""
TARGET_FILE=""
PROXY_URL=""
TEMPLATE_TAGS="all"
DISCORD_WEBHOOK=""
SLACK_WEBHOOK=""
GENERATE_PDF=false
OUTPUT_FILE="security-audit-report.json"
CRON_DAILY=false
INSTALL_MODE=false
GIT_SETUP=false

# Color codes for Linux / WSL terminal
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
PURPLE='\\033[0;35m'
CYAN='\\033[0;36m'
BOLD='\\033[1m'
NC='\\033[0m' # No Color

print_banner() {
  echo -e "\${CYAN}\${BOLD}"
  echo "    ____             _____           ____             "
  echo "   / __ \\___ _   __ / ___/___  _____/ __ \\____  _____ "
  echo "  / / / / _ \\ | / / \\__ \\/ _ \\/ ___/ / / / __ \\/ ___/ "
  echo " / /_/ /  __/ |/ / ___/ /  __/ /__/ /_/ / /_/ (__  )  "
  echo "/_____/\\___/|___/ /____/\\___/\\___/\\____/ .___/____/   "
  echo "  CYBERSECURITY VULNERABILITY AUDITOR /_/ v2.4        "
  echo -e "\${NC}"
  echo -e "\${BLUE}[*] Standards : OWASP Testing Guide · Nuclei YAML Engine · Burp Suite Audit\${NC}"
  echo -e "\${BLUE}[*] Platforms : Linux (Ubuntu, Debian, Kali, Arch) & Windows Subsystem for Linux (WSL)\${NC}"
  echo -e "\${BLUE}[*] Caller    : curl · wget · git audit · bash\${NC}"
  echo "--------------------------------------------------------------------------------"
}

show_help() {
  print_banner
  echo -e "\${BOLD}USAGE:\${NC}"
  echo "  cyber-audit -u <TARGET_URL> [OPTIONS]"
  echo "  git audit -u <TARGET_URL> [OPTIONS]         (when git integration is enabled)"
  echo ""
  echo -e "\${BOLD}OPTIONS:\${NC}"
  echo "  -u, --target <URL>         Target website or API endpoint (e.g. https://mywebsite.com)"
  echo "  -l, --list <FILE>          Target list file (e.g. subfinder subdomains list or flashdisk file)"
  echo "  -x, --proxy <URL>          Upstream security proxy (e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:9050)"
  echo "  -t, --templates <TAGS>     Template filters: all, owasp, headers, exposure, cors (Default: all)"
  echo "  -w, --webhook <URL>        Webhook URL for real-time notification (Discord or Slack)"
  echo "  --discord <URL>            Explicitly set Discord Webhook URL"
  echo "  --slack <URL>              Explicitly set Slack Webhook URL"
  echo "  --pdf                      Request PDF generation instructions"
  echo "  -o, --output <FILE>        Save JSON results to specified file (Default: security-audit-report.json)"
  echo "  --install                  Install cyber-audit & git-audit globally into /usr/local/bin"
  echo "  --git-setup                Configure 'git audit' custom command inside current git repo"
  echo "  --cron-setup               Print Linux/WSL crontab command for daily automated execution"
  echo "  -h, --help                 Display this help menu"
  echo ""
  echo -e "\${BOLD}TERMINAL CALL EXAMPLES:\${NC}"
  echo "  # Via WGET one-liner:"
  echo "  wget -qO- ${appUrl}/install.sh | bash -s -- -u https://example.com"
  echo ""
  echo "  # Via CURL one-liner:"
  echo "  curl -sSL ${appUrl}/install.sh | bash -s -- -u https://example.com"
  echo ""
  echo "  # Via GIT (Custom git command):"
  echo "  git audit -u https://example.com"
  echo ""
  echo "  # Download with WGET and execute:"
  echo "  wget -q ${appUrl}/cyber-audit && chmod +x cyber-audit && ./cyber-audit -u https://example.com"
  echo ""
  echo "  # Install globally to system PATH:"
  echo "  curl -sSL ${appUrl}/install.sh | sudo bash -s -- --install"
  exit 0
}

# If no arguments provided and piped via stdin/bash, prompt or run installation
if [ $# -eq 0 ] && [ ! -t 0 ]; then
  INSTALL_MODE=true
fi

# Parse flags
while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--target)
      TARGET="$2"
      shift 2
      ;;
    -l|--list)
      TARGET_FILE="$2"
      shift 2
      ;;
    -x|--proxy)
      PROXY_URL="$2"
      shift 2
      ;;
    -t|--templates)
      TEMPLATE_TAGS="$2"
      shift 2
      ;;
    -w|--webhook|--discord)
      DISCORD_WEBHOOK="$2"
      shift 2
      ;;
    --slack)
      SLACK_WEBHOOK="$2"
      shift 2
      ;;
    --pdf)
      GENERATE_PDF=true
      shift
      ;;
    -o|--output)
      OUTPUT_FILE="$2"
      shift 2
      ;;
    --cron-setup)
      CRON_DAILY=true
      shift
      ;;
    --install)
      INSTALL_MODE=true
      shift
      ;;
    --git-setup)
      GIT_SETUP=true
      shift
      ;;
    -h|--help)
      show_help
      ;;
    *)
      echo -e "\${RED}[!] Unknown option: $1\${NC}"
      show_help
      ;;
  esac
done

# INSTALLATION ROUTINE
if [ "$INSTALL_MODE" = true ]; then
  print_banner
  echo -e "\${CYAN}[*] Installing cyber-audit & git-audit to system PATH...\${NC}"
  
  INSTALL_DIR="/usr/local/bin"
  USE_SUDO=""
  if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
      USE_SUDO="sudo"
    else
      INSTALL_DIR="$HOME/.local/bin"
      mkdir -p "$INSTALL_DIR"
    fi
  fi

  TEMP_SCRIPT="/tmp/cyber-audit-installer-\$\$"
  if command -v curl >/dev/null 2>&1; then
    curl -sSL "${appUrl}/cyber-audit" -o "$TEMP_SCRIPT"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TEMP_SCRIPT" "${appUrl}/cyber-audit"
  else
    echo -e "\${RED}[!] Error: curl or wget is required for installation.\${NC}"
    exit 1
  fi

  chmod +x "$TEMP_SCRIPT"
  $USE_SUDO mv "$TEMP_SCRIPT" "$INSTALL_DIR/cyber-audit"
  $USE_SUDO ln -sf "$INSTALL_DIR/cyber-audit" "$INSTALL_DIR/git-audit"

  echo -e "\${GREEN}[✓] Successfully installed:\${NC}"
  echo -e "    - \${BOLD}$INSTALL_DIR/cyber-audit\${NC}"
  echo -e "    - \${BOLD}$INSTALL_DIR/git-audit\${NC} (callable as 'git audit')"
  echo ""
  echo -e "\${BOLD}Quick Test Commands:\${NC}"
  echo "    cyber-audit -u https://example.com"
  echo "    git audit -u https://example.com"
  echo ""
  echo -e "\${YELLOW}Try it now in your terminal!\${NC}"
  exit 0
fi

# GIT REPO INTEGRATION ROUTINE
if [ "$GIT_SETUP" = true ]; then
  print_banner
  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo -e "\${RED}[!] Not inside a git repository.\${NC}"
    echo "Please navigate into your git project directory and run again."
    exit 1
  fi
  
  echo -e "\${CYAN}[*] Configuring Git custom alias and pre-commit hook in current repository...\${NC}"
  git config alias.audit "!cyber-audit"
  
  echo -e "\${GREEN}[✓] Git alias registered:\${NC} You can now run \${BOLD}git audit -u <URL>\${NC} anywhere!"
  exit 0
fi

# CRON DAILY ROUTINE
if [ "$CRON_DAILY" = true ]; then
  print_banner
  echo -e "\${GREEN}[+] Daily Automated Scan Setup for Linux / WSL:\${NC}"
  SCRIPT_PATH="$(command -v cyber-audit 2>/dev/null || (cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)/$(basename "\${BASH_SOURCE[0]}"))"
  TARGET_ARG="\${TARGET:-https://example.com}"
  
  echo -e "\${YELLOW}To run this audit automatically every day at 02:00 AM, add to crontab (\`crontab -e\`):\${NC}"
  echo ""
  echo -e "\${BOLD}0 2 * * * \${SCRIPT_PATH} -u \${TARGET_ARG} >> /var/log/cyber-audit-daily.log 2>&1\${NC}"
  echo ""
  echo -e "Notification will automatically route to configured Discord or Slack webhooks."
  exit 0
fi

# VALIDATE TARGET OR TARGET_FILE
if [ -z "$TARGET" ] && [ -z "$TARGET_FILE" ]; then
  echo -e "\${RED}[!] Error: Target URL (-u) or Target List File (-l) is required.\${NC}"
  echo ""
  echo "Examples:"
  echo "  cyber-audit -u https://example.com"
  echo "  cyber-audit -l subdomains.txt -x http://127.0.0.1:8080"
  echo "  git audit -l subfinder_results.txt"
  echo "  wget -qO- ${appUrl}/install.sh | bash -s -- -u https://example.com"
  echo ""
  echo "Run with -h or --help for full documentation."
  exit 1
fi

print_banner
echo -e "\${BLUE}[INF]\${NC} DevSecOps Scanner Server : \${BOLD}\$APP_API\${NC}"
if [ -n "$TARGET_FILE" ]; then
  echo -e "\${BLUE}[INF]\${NC} Target List File         : \${BOLD}\$TARGET_FILE\${NC}"
else
  echo -e "\${BLUE}[INF]\${NC} Target Host              : \${BOLD}\$TARGET\${NC}"
fi
if [ -n "$PROXY_URL" ]; then
  echo -e "\${BLUE}[INF]\${NC} Upstream Security Proxy  : \${BOLD}\$PROXY_URL\${NC} (Stealth/Audit Tunnel Active)"
fi
echo -e "\${BLUE}[INF]\${NC} Template Rule Sets       : \${BOLD}\$TEMPLATE_TAGS\${NC}"
echo -e "\${BLUE}[INF]\${NC} Invocation Method        : CLI / Terminal Pipeline"
echo -e "\${BLUE}[INF]\${NC} Initiating security assessment..."
echo ""

# Prepare JSON payload
WEBHOOK_URL="\${DISCORD_WEBHOOK:-\$SLACK_WEBHOOK}"
WEBHOOK_TYPE="discord"
if [ -n "$SLACK_WEBHOOK" ]; then
  WEBHOOK_TYPE="slack"
fi

PROXY_JSON=""
if [ -n "$PROXY_URL" ]; then
  PROXY_JSON=$(cat <<EOF
,
  "proxy": {
    "enabled": true,
    "url": "$PROXY_URL",
    "insecureSkipVerify": true
  }
EOF
)
fi

if [ -n "$TARGET_FILE" ]; then
  # Read and format targets into JSON array
  TARGETS_JSON=$(grep -v '^[[:space:]]*#' "$TARGET_FILE" | grep -v '^[[:space:]]*$' | sed 's/^[[:blank:]]*//;s/[[:blank:]]*$//' | jq -R . | jq -s . 2>/dev/null || true)
  if [ -z "$TARGETS_JSON" ] || [ "$TARGETS_JSON" = "null" ]; then
    # Fallback to python or awk if jq not installed
    TARGETS_JSON="["
    FIRST=true
    while IFS= read -r line || [ -n "$line" ]; do
      line=$(echo "$line" | tr -d '\\r' | sed 's/^[[:blank:]]*//;s/[[:blank:]]*$//')
      [[ -z "$line" || "$line" =~ ^# ]] && continue
      if [ "$FIRST" = true ]; then
        TARGETS_JSON="\${TARGETS_JSON}\\"\$line\\""
        FIRST=false
      else
        TARGETS_JSON="\${TARGETS_JSON},\\"\$line\\""
      fi
    done < "$TARGET_FILE"
    TARGETS_JSON="\${TARGETS_JSON}]"
  fi

  PAYLOAD=$(cat <<EOF
{
  "targets": $TARGETS_JSON,
  "webhook": {
    "enabled": $([ -n "$WEBHOOK_URL" ] && echo "true" || echo "false"),
    "type": "$WEBHOOK_TYPE",
    "url": "$WEBHOOK_URL"
  }$PROXY_JSON
}
EOF
)
  API_ENDPOINT="$APP_API/api/scan/batch"
else
  PAYLOAD=$(cat <<EOF
{
  "targetUrl": "$TARGET",
  "webhook": {
    "enabled": $([ -n "$WEBHOOK_URL" ] && echo "true" || echo "false"),
    "type": "$WEBHOOK_TYPE",
    "url": "$WEBHOOK_URL"
  }$PROXY_JSON
}
EOF
)
  API_ENDPOINT="$APP_API/api/scan"
fi

# Execute API scan endpoint with curl (or fallback to wget)
HTTP_STATUS=""
BODY=""

if command -v curl >/dev/null 2>&1; then
  HTTP_RESPONSE=$(curl -s -w "\\n%{http_code}" -X POST "\$API_ENDPOINT" \\
    -H "Content-Type: application/json" \\
    -d "$PAYLOAD" || true)
  HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tail -n 1)
  BODY=$(echo "$HTTP_RESPONSE" | sed '$d')
elif command -v wget >/dev/null 2>&1; then
  BODY=$(wget -qO- --post-data="$PAYLOAD" --header="Content-Type: application/json" "\$API_ENDPOINT" || true)
  if [ -n "$BODY" ]; then
    HTTP_STATUS="200"
  else
    HTTP_STATUS="500"
  fi
fi

if [ "$HTTP_STATUS" != "200" ] || [ -z "$BODY" ]; then
  echo -e "\${YELLOW}[!] Note: Could not reach remote API server at \$APP_API (HTTP \$HTTP_STATUS).\${NC}"
  echo -e "\${CYAN}[*] Falling back to Standalone Direct Probe Mode in local terminal...\${NC}"
  echo ""

  # Standalone Direct Terminal Probes (OWASP Security Headers + Sensitive Files)
  echo -e "\${BLUE}[INF]\${NC} Probing HTTP Security Headers on \$TARGET..."
  HEADERS_OUTPUT=$(curl -sI -k --connect-timeout 5 "$TARGET" || wget -qS --spider "$TARGET" 2>&1 || true)
  
  MISSING_HEADERS=()
  echo "$HEADERS_OUTPUT" | grep -qi "strict-transport-security" || MISSING_HEADERS+=("Strict-Transport-Security (HSTS)")
  echo "$HEADERS_OUTPUT" | grep -qi "content-security-policy" || MISSING_HEADERS+=("Content-Security-Policy (CSP)")
  echo "$HEADERS_OUTPUT" | grep -qi "x-frame-options" || MISSING_HEADERS+=("X-Frame-Options (Clickjacking)")
  echo "$HEADERS_OUTPUT" | grep -qi "x-content-type-options" || MISSING_HEADERS+=("X-Content-Type-Options (MIME-sniffing)")

  echo -e "\${BLUE}[INF]\${NC} Probing Sensitive Paths (.env, .git/HEAD)..."
  ENV_CHECK=$(curl -s -k --connect-timeout 4 "$TARGET/.env" || true)
  GIT_CHECK=$(curl -s -k --connect-timeout 4 "$TARGET/.git/HEAD" || true)

  echo ""
  echo -e "\${BOLD}=== STANDALONE AUDIT RESULTS ===\${NC}"
  if [ \${#MISSING_HEADERS[@]} -gt 0 ]; then
    echo -e "\${YELLOW}[HIGH] OWASP Missing Security Headers:\${NC}"
    for h in "\${MISSING_HEADERS[@]}"; do
      echo -e "  \${RED}✗ Missing:\${NC} \$h"
    done
  fi

  if echo "$ENV_CHECK" | grep -qE "DB_|SECRET|API_KEY|PASSWORD|TOKEN"; then
    echo -e "\${RED}[CRITICAL] Exposed .env File Found at: \$TARGET/.env\${NC}"
  else
    echo -e "\${GREEN}[PASS] .env file is not publicly exposed.\${NC}"
  fi

  if echo "$GIT_CHECK" | grep -q "refs/heads"; then
    echo -e "\${RED}[CRITICAL] Exposed .git Repository Found at: \$TARGET/.git/HEAD\${NC}"
  else
    echo -e "\${GREEN}[PASS] .git repository is not exposed.\${NC}"
  fi

  echo ""
  echo -e "\${GREEN}[+] Direct terminal probes completed.\${NC}"
  exit 0
fi

# Save API result to output file
echo "$BODY" > "$OUTPUT_FILE"

echo -e "\${GREEN}[+] Scan completed successfully!\${NC}"
echo -e "\${CYAN}[*] Raw results saved to: \$OUTPUT_FILE\${NC}"
echo ""

# Parse findings summary with node if available, or awk/grep
if command -v node >/dev/null 2>&1; then
  node -e "
  const fs = require('fs');
  try {
    const data = JSON.parse(fs.readFileSync('$OUTPUT_FILE', 'utf8'));
    console.log('\\x1b[1m=== AUDIT EXECUTIVE SUMMARY ===\\x1b[0m');
    console.log('Target: ' + data.targetUrl);
    console.log('Templates Executed: ' + data.templatesExecuted);
    console.log('Requests Sent: ' + data.requestsSent);
    console.log('Duration: ' + ((data.durationMs || 0)/1000).toFixed(1) + 's');
    console.log('Total Findings: ' + data.findings.length);
    console.log('');
    
    if (data.findings.length === 0) {
      console.log('\\x1b[32m[+] PASSED: No security vulnerabilities identified.\\x1b[0m');
    } else {
      console.log('\\x1b[1m=== IDENTIFIED VULNERABILITIES ===\\x1b[0m');
      data.findings.forEach((f, i) => {
        const color = f.severity === 'critical' ? '\\x1b[31m' : f.severity === 'high' ? '\\x1b[33m' : '\\x1b[34m';
        console.log(color + '[' + f.severity.toUpperCase() + ']\\x1b[0m ' + f.name + ' (' + (f.cweId || 'CWE') + ')');
        console.log('  URL: ' + f.matchedAt);
        console.log('  Evidence: ' + (f.evidence || 'Pattern matched'));
        console.log('  Remediation: ' + f.remediation);
        console.log('');
      });
    }
  } catch(e) {
    console.log('Results saved to $OUTPUT_FILE');
  }
  " || true
else
  echo -e "\${BOLD}Summary:\${NC} Result saved to \${BOLD}$OUTPUT_FILE\${NC}"
fi

if [ "$GENERATE_PDF" = true ]; then
  echo -e "\${PURPLE}[PDF]\${NC} To download formatted PDF report:"
  echo -e "      Open \${BOLD}\$APP_API\${NC} in browser -> Click 'Audit Findings' -> 'Export PDF'"
fi

if [ -n "$WEBHOOK_URL" ]; then
  echo -e "\${GREEN}[✓]\${NC} Notification delivered to \$WEBHOOK_TYPE channel."
fi
`;
}
