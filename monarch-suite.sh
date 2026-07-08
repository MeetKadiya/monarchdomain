#!/usr/bin/env bash
# monarch-suite.sh - Optional convenience wrapper
#
# Chains MonarchDomain (subdomain discovery) into Shloka (vuln heuristics),
# if Shloka is installed/available on PATH. This script is independent -
# MonarchDomain works fully without it and without Shloka installed.
#
# Usage:
#   ./monarch-suite.sh -d example.com [-t threads] [-m stealth-level] [-f json]
#
set -uo pipefail

DOMAIN=""
THREADS=8
STEALTH="normal"
FORMAT="text"
OUT_DIR="suite-results"

usage() {
  cat << EOF
monarch-suite.sh - MonarchDomain -> Shloka pipeline

Usage: $0 -d <domain> [-t threads] [-m stealth] [-f text|json] [-o out_dir]

Requires: monarchdomain.sh on PATH (or in this directory) and, optionally,
shloka.sh on PATH (or in a sibling ../Shloka/ directory) for the vuln-scan stage.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d) DOMAIN="$2"; shift 2 ;;
    -t) THREADS="$2"; shift 2 ;;
    -m) STEALTH="$2"; shift 2 ;;
    -f) FORMAT="$2"; shift 2 ;;
    -o) OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

[[ -z "$DOMAIN" ]] && { echo "Error: -d DOMAIN required"; usage; exit 1; }

MONARCH_BIN="$(command -v monarchdomain || true)"
[[ -z "$MONARCH_BIN" && -x "./monarchdomain.sh" ]] && MONARCH_BIN="./monarchdomain.sh"
if [[ -z "$MONARCH_BIN" ]]; then
  echo "[!] monarchdomain not found on PATH or in current directory. Install it first (see MonarchDomain's install.sh)."
  exit 1
fi

SHLOKA_BIN="$(command -v shloka || true)"
[[ -z "$SHLOKA_BIN" && -x "../Shloka/shloka.sh" ]] && SHLOKA_BIN="../Shloka/shloka.sh"
[[ -z "$SHLOKA_BIN" && -x "./shloka.sh" ]] && SHLOKA_BIN="./shloka.sh"

mkdir -p "$OUT_DIR"
SUBS_FILE="$OUT_DIR/${DOMAIN}-subdomains.txt"

echo "[*] Step 1/2: enumerating live subdomains with MonarchDomain..."
"$MONARCH_BIN" -d "$DOMAIN" -s -l -m "$STEALTH" -o "$SUBS_FILE"

if [[ -z "$SHLOKA_BIN" ]]; then
  echo "[i] Shloka not found - skipping vuln-scan stage. Subdomains saved to: $SUBS_FILE"
  echo "[i] Install Shloka (github.com/<you>/shloka) to enable the second stage."
  exit 0
fi

echo "[*] Step 2/2: batch vulnerability scan with Shloka..."
"$SHLOKA_BIN" -D "$SUBS_FILE" -t "$THREADS" -f "$FORMAT" -o "$OUT_DIR/reports/"

echo "[+] Done. Subdomains: $SUBS_FILE | Reports: $OUT_DIR/reports/"
