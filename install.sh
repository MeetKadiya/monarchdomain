#!/usr/bin/env bash
# install.sh - MonarchDomain installer for Debian/Ubuntu/Kali
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/usr/local/bin"
SCRIPT_NAME="monarchdomain"

echo "[*] Installing MonarchDomain..."

if [[ $EUID -ne 0 ]]; then
  echo "[!] This installer needs sudo to write to $INSTALL_DIR and apt-install packages."
  SUDO="sudo"
else
  SUDO=""
fi

echo "[*] Installing dependencies (curl, dnsutils, openssl, netcat-openbsd)..."
$SUDO apt-get update -qq
$SUDO apt-get install -y curl dnsutils openssl netcat-openbsd

if ! command -v httpx &>/dev/null; then
  echo "[i] Optional: httpx (ProjectDiscovery) not found. For --use-httpx support:"
  echo "    sudo apt install httpx-toolkit"
  echo "    (or: go install github.com/projectdiscovery/httpx/cmd/httpx@latest)"
fi

chmod +x "$REPO_DIR/monarchdomain.sh"
$SUDO ln -sf "$REPO_DIR/monarchdomain.sh" "$INSTALL_DIR/$SCRIPT_NAME"

echo "[+] Installed. Run it from anywhere with: $SCRIPT_NAME -d example.com"
echo "[+] Config file support: create ~/.monarchdomainrc to set defaults (THREADS, STEALTH, PROXY, ...)."
