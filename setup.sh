#!/usr/bin/env bash
# ==============================================================================
# One-Click Setup & Global CLI Installer
# Cybersecurity Vulnerability Audit Scanner
# Works on: Kali Linux, Parrot OS, Ubuntu, Debian, Arch, macOS, WSL2
# ==============================================================================

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${CYAN}${BOLD}"
echo "    ____             _____           ____             "
echo "   / __ \\___ _   __ / ___/___  _____/ __ \\____  _____ "
echo "  / / / / _ \\ | / / \\__ \\/ _ \\/ ___/ / / / __ \\/ ___/ "
echo " / /_/ /  __/ |/ / ___/ /  __/ /__/ /_/ / /_/ (__  )  "
echo "/_____/\\___/|___/ /____/\\___/\\___/\\____/ .___/____/   "
echo "      ONE-CLICK SETUP & GLOBAL CLI INSTALLER          "
echo -e "${NC}"
echo -e "${YELLOW}[*] Lokasi Project:${NC} $PROJECT_DIR"
echo ""

# 1. Install Dependencies (Supports Python pip, Bun, pnpm, and NPM)
echo -e "${CYAN}[1/3] Menginstal dependensi scanner...${NC}"
cd "$PROJECT_DIR"

# Python CLI dependencies
if command -v pip3 >/dev/null 2>&1; then
  echo -e "${YELLOW}[*] Memasang dependensi Python CLI (requirements.txt)...${NC}"
  pip3 install -r requirements.txt --quiet || pip3 install -r requirements.txt --user --quiet || true
elif command -v pip >/dev/null 2>&1; then
  pip install -r requirements.txt --quiet || true
fi

# Node.js / Bun Web GUI dependencies
if command -v bun >/dev/null 2>&1; then
  echo -e "${YELLOW}[*] Menggunakan Bun untuk instalasi kilat...${NC}"
  bun install
elif command -v pnpm >/dev/null 2>&1; then
  echo -e "${YELLOW}[*] Menggunakan pnpm...${NC}"
  pnpm install
elif command -v npm >/dev/null 2>&1; then
  echo -e "${YELLOW}[*] Menggunakan npm (--legacy-peer-deps)...${NC}"
  npm install --legacy-peer-deps
fi

echo -e "${GREEN}[✓] Dependensi berhasil terinstal!${NC}"
echo ""

# 2. Determine target binary path (/usr/local/bin or ~/.local/bin)
echo -e "${CYAN}[2/3] Memasang perintah global agar bisa dipanggil dari direktori mana saja...${NC}"

TARGET_BIN_DIR="/usr/local/bin"
USE_SUDO=""

if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    USE_SUDO="sudo"
  elif [ -w "/usr/local/bin" ]; then
    USE_SUDO=""
  else
    TARGET_BIN_DIR="$HOME/.local/bin"
    mkdir -p "$TARGET_BIN_DIR"
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
      export PATH="$HOME/.local/bin:$PATH"
      if [ -f "$HOME/.bashrc" ]; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
      fi
      if [ -f "$HOME/.zshrc" ]; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc"
      fi
    fi
  fi
fi

# 3. Create 'cyber-audit-web' launcher script
cat <<EOF > /tmp/cyber-audit-web
#!/usr/bin/env bash
# Menjalankan Web GUI Security Scanner dari direktori mana saja
cd "$PROJECT_DIR"
echo -e "${CYAN}${BOLD}[*] Menjalankan Cyber Security Scanner Web UI...${NC}"
echo -e "${GREEN}[*] Buka di browser: http://localhost:3000${NC}"
if command -v bun >/dev/null 2>&1; then
  bun run dev
else
  npm run dev
fi
EOF
chmod +x /tmp/cyber-audit-web
$USE_SUDO mv /tmp/cyber-audit-web "$TARGET_BIN_DIR/cyber-audit-web"
$USE_SUDO ln -sf "$TARGET_BIN_DIR/cyber-audit-web" "$TARGET_BIN_DIR/recon-web"

# 4. Create 'cyber-audit' CLI wrapper script (Runs Python CLI directly or falls back to API)
cat <<EOF > /tmp/cyber-audit
#!/usr/bin/env bash
PROJECT_DIR="$PROJECT_DIR"
if command -v python3 >/dev/null 2>&1 && [ -f "\$PROJECT_DIR/cyber_audit.py" ]; then
  python3 "\$PROJECT_DIR/cyber_audit.py" "\$@"
elif [ -f "\$PROJECT_DIR/server/cli-script.ts" ] && command -v npx >/dev/null 2>&1; then
  cd "\$PROJECT_DIR" && npx tsx server/cli-script.ts "\$@"
else
  APP_API="\${AUDIT_API_URL:-http://localhost:3000}"
  curl -sSL "\$APP_API/cyber-audit" | bash -s -- "\$@"
fi
EOF
chmod +x /tmp/cyber-audit
$USE_SUDO mv /tmp/cyber-audit "$TARGET_BIN_DIR/cyber-audit"
$USE_SUDO ln -sf "$TARGET_BIN_DIR/cyber-audit" "$TARGET_BIN_DIR/recon-audit"

echo -e "${GREEN}[✓] Perintah global berhasil dipasang di:${NC} $TARGET_BIN_DIR"
echo ""

# 5. Success Banner & Instructions
echo -e "${CYAN}[3/3] Selesai! Kamu sekarang bisa menggunakan perintah ini dari direktori mana pun:${NC}"
echo "------------------------------------------------------------------------"
echo -e "  1. Buka Web GUI Scanner:"
echo -e "     ${BOLD}${GREEN}cyber-audit-web${NC}"
echo ""
echo -e "  2. Scan target langsung via CLI (Python / Native):"
echo -e "     ${BOLD}${GREEN}cyber-audit -u https://target.com -p high${NC}"
echo "     atau: ${BOLD}${GREEN}python3 cyber_audit.py -u https://target.com${NC}"
echo ""
echo -e "  3. Scan file subdomain dengan Burp Suite proxy:"
echo -e "     ${BOLD}${GREEN}cyber-audit -l subdomains.txt -x http://127.0.0.1:8080 -o report.json${NC}"
echo "------------------------------------------------------------------------"
echo -e "${GREEN}${BOLD}Instalasi selesai dan siap digunakan!${NC}"
