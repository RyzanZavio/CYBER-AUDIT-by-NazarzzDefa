# ==============================================================================
# Cybersecurity Vulnerability Audit Scanner & CLI Suite - Makefile
# Streamlined installation and execution targets
# ==============================================================================

.PHONY: all install setup dev run scan test build lint clean help

SHELL := /usr/bin/env bash
PYTHON ?= python3
PIP ?= pip3
TARGET ?= https://smkn3kotabekasi.sch.id
SEVERITY ?= all
PROXY ?=

# Default target
all: install

help:
	@echo "========================================================================"
	@echo " Cybersecurity Vulnerability Audit Scanner - Makefile Quick Commands"
	@echo "========================================================================"
	@echo "  make install      - Install Python (requirements.txt) & Web dependencies"
	@echo "  make setup        - Run 1-Click setup script and install global CLI tools"
	@echo "  make dev / run    - Start the Web GUI scanner on http://localhost:3000"
	@echo "  make scan         - Execute CLI audit (e.g. make scan TARGET=https://target.com)"
	@echo "  make scan-burp    - Scan target through Burp Suite proxy (127.0.0.1:8080)"
	@echo "  make build        - Compile Web GUI & Server bundle for production"
	@echo "  make lint         - Run TypeScript type checks and validation"
	@echo "  make clean        - Remove temporary files, build caches, and logs"
	@echo "========================================================================"

install:
	@echo "[*] Step 1/2: Installing Python dependencies from requirements.txt..."
	@if command -v $(PIP) >/dev/null 2>&1; then \
		$(PIP) install -r requirements.txt || $(PIP) install -r requirements.txt --user; \
	elif command -v pip >/dev/null 2>&1; then \
		pip install -r requirements.txt || pip install -r requirements.txt --user; \
	else \
		echo "[!] Warning: pip/pip3 not found. Skipping Python dependencies."; \
	fi
	@echo "[*] Step 2/2: Installing Web GUI dependencies..."
	@if command -v bun >/dev/null 2>&1; then \
		echo "[*] Using Bun package manager..."; \
		bun install; \
	elif command -v pnpm >/dev/null 2>&1; then \
		echo "[*] Using pnpm package manager..."; \
		pnpm install; \
	elif command -v npm >/dev/null 2>&1; then \
		echo "[*] Using npm (--legacy-peer-deps)..."; \
		npm install --legacy-peer-deps; \
	fi
	@echo "[✓] All dependencies installed successfully!"

setup:
	@chmod +x setup.sh
	@./setup.sh

dev:
	@echo "[*] Starting Cyber Audit Web UI..."
	@if command -v bun >/dev/null 2>&1; then \
		bun run dev; \
	else \
		npm run dev; \
	fi

run: dev

scan:
	@echo "[*] Launching CLI audit against: $(TARGET)"
	@$(PYTHON) cyber_audit.py -u $(TARGET) -p $(SEVERITY) $(if $(PROXY),-x $(PROXY))

scan-burp:
	@echo "[*] Scanning $(TARGET) routed through Burp Suite proxy (127.0.0.1:8080)..."
	@$(PYTHON) cyber_audit.py -u $(TARGET) -p high -x http://127.0.0.1:8080

build:
	@echo "[*] Compiling application bundle..."
	@npm run build

lint:
	@echo "[*] Running linter & TypeScript typecheck..."
	@npm run lint

clean:
	@echo "[*] Cleaning build artifacts and cache..."
	@rm -rf dist .turbo *.tsbuildinfo __pycache__ .pytest_cache
	@echo "[✓] Clean completed."
