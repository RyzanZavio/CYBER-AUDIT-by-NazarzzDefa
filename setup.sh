#!/usr/bin/env bash
# ==============================================================================
# One-Click Setup & Global CLI Installer
# ReconizeTools / DevSecOps Vulnerability Audit Scanner
# Works on: Parrot OS, Kali Linux, Ubuntu, Debian, Arch, WSL2
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

# 1. Install Node Dependencies with legacy-peer-deps to avoid ERESOLVE conflict
echo -e "${CYAN}[1/3] Menginstal dependensi (npm install --legacy-peer-deps)...${NC}"
cd "$PROJECT_DIR"

if command -v npm >/dev/null 2>&1; then
  npm install --legacy-peer-deps
elif command -v bun >/dev/null 2>&1; then
  bun install
else
  echo -e "${RED}[!] Error: Node.js / npm tidak ditemukan. Silakan pasang Node.js terlebih dahulu.${NC}"
  exit 1
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
    # Ensure ~/.local/bin is in PATH
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
npm run dev
EOF
chmod +x /tmp/cyber-audit-web
$USE_SUDO mv /tmp/cyber-audit-web "$TARGET_BIN_DIR/cyber-audit-web"
$USE_SUDO ln -sf "$TARGET_BIN_DIR/cyber-audit-web" "$TARGET_BIN_DIR/recon-web"

# 4. Create 'cyber-audit' CLI wrapper script
cat <<EOF > /tmp/cyber-audit
#!/usr/bin/env bash
# CLI Wrapper untuk memindai target secara langsung dari terminal mana pun
APP_API="\${AUDIT_API_URL:-http://localhost:3000}"
PROJECT_DIR="$PROJECT_DIR"

# Jika server belum menyala di localhost:3000, tawarkan auto-start atau jalankan via npx/tsx
if ! curl -s --max-time 1 "\$APP_API/api/health" >/dev/null 2>&1; then
  # Jalankan server secara otomatis di background jika belum aktif
  echo -e "${YELLOW}[!] Server lokal belum aktif, menyalakan background engine...${NC}"
  (cd "\$PROJECT_DIR" && npm run dev >/dev/null 2>&1) &
  SERVER_PID=\$!
  sleep 2
fi

# Download/jalankan CLI runner
curl -sSL "\$APP_API/cyber-audit" | bash -s -- "\$@"
EOF
chmod +x /tmp/cyber-audit
$USE_SUDO mv /tmp/cyber-audit "$TARGET_BIN_DIR/cyber-audit"
$USE_SUDO ln -sf "$TARGET_BIN_DIR/cyber-audit" "$TARGET_BIN_DIR/recon-audit"
$USE_SUDO ln -sf "$TARGET_BIN_DIR/cyber-audit" "$TARGET_BIN_DIR/git-audit"

echo -e "${GREEN}[✓] Perintah global berhasil dipasang di:${NC} $TARGET_BIN_DIR"
echo ""

# 5. Success Banner & Instructions
echo -e "${CYAN}[3/3] Selesai! Kamu sekarang bisa menggunakan perintah ini dari direktori mana pun (termasuk Home ~):${NC}"
echo "------------------------------------------------------------------------"
echo -e "  1. Buka Web GUI Scanner dari mana saja:"
echo -e "     ${BOLD}${GREEN}cyber-audit-web${NC}   (atau ${BOLD}recon-web${NC})"
echo ""
echo -e "  2. Scan target langsung dari terminal (di folder mana saja):"
echo -e "     ${BOLD}${GREEN}cyber-audit -u https://target.com${NC}"
echo ""
echo -e "  3. Scan file subdomain (misal hasil subfinder di folder aktif saat ini):"
echo -e "     ${BOLD}${GREEN}cyber-audit -l subdomains.txt -x http://127.0.0.1:8080${NC}"
echo ""
echo -e "  4. Cek menu bantuan:"
echo -e "     ${BOLD}${GREEN}cyber-audit --help${NC}"
echo "------------------------------------------------------------------------"
echo -e "${GREEN}${BOLD}Instalasi selesai dan siap dipakai!${NC}"
