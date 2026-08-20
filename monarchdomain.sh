#!/usr/bin/env bash
#
# MonarchDomain - Subdomain Enumeration & Recon Vulnerability Scanner
# Author: Meet_Kadiya
# License: MIT
#
# For AUTHORIZED security testing only (bug bounty programs / pentests you
# have explicit written permission for). See README.md.
#
set -uo pipefail
IFS=$'\n\t'

VERSION="1.3.0"

# ---------------------------------------------------------------------------
# Resolve the script's real directory (following symlinks, e.g. the one
# install.sh creates in /usr/local/bin) so bundled library files such as
# lib/html_report.sh can always be found relative to the actual repo,
# regardless of how monarchdomain is invoked.
# ---------------------------------------------------------------------------
function _resolve_script_dir() {
  local src="${BASH_SOURCE[0]}" dir
  while [[ -h "$src" ]]; do
    dir="$(cd -P "$(dirname "$src")" && pwd)"
    src="$(readlink "$src")"
    [[ "$src" != /* ]] && src="$dir/$src"
  done
  cd -P "$(dirname "$src")" && pwd
}
SCRIPT_DIR="$(_resolve_script_dir)"

# shellcheck disable=SC1091
[[ -f "$SCRIPT_DIR/lib/html_report.sh" ]] && source "$SCRIPT_DIR/lib/html_report.sh"
# shellcheck disable=SC1091
[[ -f "$SCRIPT_DIR/lib/endpoints.sh" ]] && source "$SCRIPT_DIR/lib/endpoints.sh"

trap 'echo -e "\n${YELLOW:-}[!] Interrupted by user. Progress saved - rerun with --resume to continue.${RESET:-}"; exit 130' INT

# ---------------------------------------------------------------------------
# Colors (auto-disabled when output is piped/redirected)
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
  RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
  BLUE=$'\033[34m'; CYAN=$'\033[36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; BOLD=""; RESET=""
fi

# ---------------------------------------------------------------------------
# Defaults (overridable via ~/.monarchdomainrc or ./.monarchdomainrc)
# ---------------------------------------------------------------------------
DOMAIN=""
MODE_SUBS_ONLY=0
MODE_VULN_ONLY=0
FILTER_LIVE=0
FILTER_WILDCARD=0
STEALTH="normal"        # normal | high | paranoid
THREADS=15
MAX_RETRIES=3
OUTPUT_FORMAT="text"    # text | json
OUTPUT_FILE=""
LOG_FILE=""
WORDLIST_FILE=""
EXCLUDE_FILE=""
SCOPE_FILE=""
STRICT_SCOPE=0
PROXY=""
QUIET=0
DELAY_MIN=1
DELAY_MAX=2
SOURCES="all"
RESUME=0
DIFF_MODE=0
USE_HTTPX=0
PORTS_SPEC=""
HTML_REPORT=0
REPORT_DIR=""
SCAN_DURATION_SECONDS=0

# Feature 3: HTTP URL & endpoint discovery (lib/endpoints.sh). Disabled by
# default - it issues additional GET requests against each live host, so
# it stays opt-in rather than bundled silently into every scan.
ENDPOINTS_ENABLED=0
ENDPOINTS_MAX=60
# shellcheck disable=SC2034  # read by lib/endpoints.sh across the source boundary (see tests/scope_test.sh's SC2034 note)
ENDPOINTS_TIMEOUT=10
# shellcheck disable=SC2034  # read by lib/endpoints.sh across the source boundary
ENDPOINTS_MAX_SITEMAP_DEPTH=2

USER_AGENTS=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
)

DEFAULT_WORDLIST=(www mail ftp webmail test smtp admin cpanel blog dev portal shop
  ns1 ns2 api staging stage vpn remote git gitlab jenkins jira confluence demo beta
  app apps mobile m secure store cdn static assets img images media files download
  downloads support help docs status monitor grafana kibana elastic db sql mysql
  redis cache auth sso login id accounts billing pay payments internal intranet
  old new uat qa preview sandbox ws websocket socket graphql rest v1 v2 console
  api-dev api-staging edge origin webdisk autodiscover autoconfig direct
  ftp2 mx mx1 mx2 smtp2 pop pop3 imap ns3 ns4 cloud lab test-api dashboard panel)

DEFAULT_PORTS=(21 22 25 80 443 3000 3306 5432 6379 8000 8080 8443 9200 27017)
declare -a COMMON_PORTS=("${DEFAULT_PORTS[@]}")

declare -a FINDINGS=()
declare -a subdomains=()

# Normalized per-host scan data (Feature 2: HTML reporting). Populated by
# vuln_scan(). Pipe-delimited, same convention as FINDINGS:
#   SCAN_HOSTS   : host|ip|live(0|1)|technology_or_waf
#   SCAN_PORTS   : host|port
#   SCAN_TLS     : host|days_until_expiry|not_after
#   SCAN_HEADERS : host|header_name|present|missing
declare -a SCAN_HOSTS=()
declare -a SCAN_PORTS=()
declare -a SCAN_TLS=()
declare -a SCAN_HEADERS=()

# Discovered URLs/endpoints (Feature 3: lib/endpoints.sh), populated by
# endpoints_discover_host() when --endpoints is given. Pipe-delimited,
# same convention as the arrays above:
#   SCAN_ENDPOINTS : url|type|source|status_code
declare -a SCAN_ENDPOINTS=()

# Scope enforcement state (populated by scope_load)
SCOPE_ENABLED=0
declare -a SCOPE_DOMAIN_ENTRIES=()    # bare domain -> matches itself + subdomains
declare -a SCOPE_WILDCARD_ENTRIES=()  # *.domain    -> matches subdomains only
declare -a SCOPE_IP_ENTRIES=()        # normalized IPv4/IPv6 literals
SCOPE_IN_COUNT=0
SCOPE_OUT_COUNT=0
SCOPE_BLOCKED_COUNT=0

CONFIG_LOADED=""
for cfg in "$HOME/.monarchdomainrc" "./.monarchdomainrc"; do
  if [[ -f "$cfg" ]]; then
    # shellcheck disable=SC1090
    source "$cfg"
    CONFIG_LOADED="$cfg"
  fi
done

# ---------------------------------------------------------------------------
# Logging / output helpers
# ---------------------------------------------------------------------------
function log_line() {
  local level="$1"; shift
  if [[ -n "$LOG_FILE" ]]; then
    printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*" >> "$LOG_FILE"
  fi
}

function info() { [[ $QUIET -eq 1 ]] || echo -e "$@"; }

function json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  printf '%s' "$s"
}

function usage() {
  cat << EOF
${BOLD}MonarchDomain v${VERSION}${RESET} - Subdomain Finder & Recon Vulnerability Scanner

Usage:
  $0 -d <domain> [options]

Core:
  -d, --domain DOMAIN     Target domain (required)
  -s, --subs-only         Only perform subdomain enumeration
  -v, --vuln-only         Only perform vulnerability scanning on -d itself
  -l, --live              Keep only live (HTTP/HTTPS responsive) subdomains
  -w, --wildcard          Keep only wildcard-DNS subdomains

Sources & brute force:
  -W, --wordlist FILE     Custom brute-force wordlist (one entry per line)
      --sources LIST      Comma list: crtsh,wayback,otx,rapiddns,all (default: all)

Performance & stealth:
  -t, --threads N         Parallel workers (default: $THREADS)
  -m, --stealth [LEVEL]   normal|high|paranoid (bare -m = high)
  -x, --proxy PROXY       Proxy for requests (http://, socks5://) - passed to curl
      --ports LIST        Custom ports for scanning, e.g. "80,443,8000-8010"
      --use-httpx         Use httpx (if installed) for faster/richer live-host probing

Scope control:
  -e, --exclude FILE      Skip any subdomain matching an entry in FILE (deny-list)
      --scope FILE        Only touch assets matching an entry in FILE (allow-list).
                           Enforced before DNS brute force, live checks, wildcard
                           checks, port scans and vulnerability scans. Supports
                           exact domains (also allows their subdomains), explicit
                           wildcards (*.example.com), and IPv4/IPv6 literals.
                           See "Authorized Scope" in README.md.
      --strict-scope       Refuse to run without --scope, and refuse to run if the
                           scope file resolves to zero valid entries. Use this for
                           unattended/CI runs where silent fail-open is unacceptable.

Continuity:
      --resume            Resume an interrupted run (reuses last results dir for domain)
      --diff              Compare this run's subdomains against the previous run and
                           report new/removed hosts (written to diff.txt)

Output:
  -o, --output FILE       Write results to FILE (default: results/<domain>/<timestamp>/)
  -f, --format FORMAT     text | json (default: text)
      --html-report        Also generate an offline HTML security report (report.html) - a
                           readable dashboard built from the same scan data as the text/JSON
                           output. Does not replace or alter either of them.
      --report-dir DIR     Directory for the HTML report (default: <results_dir>/monarch-report)
      --endpoints          Discover URLs/endpoints on each live host: robots.txt, sitemap.xml
                           (incl. sitemap indexes), HTML links/forms/scripts, JS path refs, and
                           a small fixed list of common API-doc/well-known paths. Safe, GET-only,
                           non-destructive - never submits forms, authenticates, or brute forces
                           paths. Every discovered URL is scope-checked before it is requested.
                           Disabled by default. See "Endpoint Discovery" in README.md.
      --no-endpoints       Explicitly disable endpoint discovery (useful to override a
                           .monarchdomainrc default of ENDPOINTS_ENABLED=1).
      --endpoints-max N    Max endpoint URLs actively requested per host (default: $ENDPOINTS_MAX)
  -L, --log FILE          Append timestamped run log to FILE
  -q, --quiet             Suppress live progress output

Misc:
  -h, --help              Show this help
      --version           Show version

Examples:
  $0 -d example.com
  $0 -d example.com -s -l -m high -t 30
  $0 -d example.com -W /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
  $0 -d example.com -f json -o report.json
  $0 -d example.com -x socks5://127.0.0.1:9050 -m paranoid
  $0 -d example.com --scope program-scope.txt -e excluded.txt
  $0 -d example.com --scope program-scope.txt --strict-scope
  $0 -d example.com --ports "80,443,8000-8010" --use-httpx
  $0 -d example.com --resume
  $0 -d example.com --diff
  $0 -d example.com --html-report
  $0 -d example.com --html-report --report-dir /tmp/monarch-report
  $0 -d example.com --endpoints
  $0 -d example.com --endpoints --endpoints-max 120 --scope program-scope.txt

Config file:
  ~/.monarchdomainrc or ./.monarchdomainrc can predefine any variable above
  (e.g. THREADS=25, STEALTH=high, PROXY=socks5://127.0.0.1:9050).
EOF
}

function parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) DOMAIN="$2"; shift 2 ;;
      -s|--subs-only) MODE_SUBS_ONLY=1; shift ;;
      -v|--vuln-only) MODE_VULN_ONLY=1; shift ;;
      -l|--live) FILTER_LIVE=1; shift ;;
      -w|--wildcard) FILTER_WILDCARD=1; shift ;;
      -W|--wordlist) WORDLIST_FILE="$2"; shift 2 ;;
      --sources) SOURCES="$2"; shift 2 ;;
      -t|--threads) THREADS="$2"; shift 2 ;;
      -m|--stealth)
        if [[ "${2:-}" =~ ^(normal|high|paranoid)$ ]]; then
          STEALTH="$2"; shift 2
        else
          STEALTH="high"; shift
        fi
        ;;
      -x|--proxy) PROXY="$2"; shift 2 ;;
      --ports) PORTS_SPEC="$2"; shift 2 ;;
      --use-httpx) USE_HTTPX=1; shift ;;
      -e|--exclude) EXCLUDE_FILE="$2"; shift 2 ;;
      --scope) SCOPE_FILE="$2"; shift 2 ;;
      --strict-scope) STRICT_SCOPE=1; shift ;;
      --resume) RESUME=1; shift ;;
      --diff) DIFF_MODE=1; shift ;;
      -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
      -f|--format) OUTPUT_FORMAT="$2"; shift 2 ;;
      --html-report) HTML_REPORT=1; shift ;;
      --report-dir) REPORT_DIR="$2"; shift 2 ;;
      --endpoints) ENDPOINTS_ENABLED=1; shift ;;
      --no-endpoints) ENDPOINTS_ENABLED=0; shift ;;
      --endpoints-max) ENDPOINTS_MAX="$2"; shift 2 ;;
      -L|--log) LOG_FILE="$2"; shift 2 ;;
      -q|--quiet) QUIET=1; shift ;;
      -h|--help) usage; exit 0 ;;
      --version) echo "MonarchDomain v${VERSION}"; exit 0 ;;
      *)
        echo -e "${RED}[Error]${RESET} Unknown option: $1"
        usage; exit 1
        ;;
    esac
  done
}

function validate_domain() {
  local d="$1"
  d="${d#http://}"; d="${d#https://}"; d="${d%%/*}"
  d="${d,,}"
  if [[ ! "$d" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$ ]]; then
    echo -e "${RED}[Error]${RESET} '$1' doesn't look like a valid domain." >&2
    return 1
  fi
  echo "$d"
}

function parse_ports_spec() {
  # Converts "80,443,8000-8010" into individual port numbers.
  local spec="$1" part start end p
  local -a out=()
  IFS=',' read -ra parts <<< "$spec"
  for part in "${parts[@]}"; do
    part="${part// /}"
    if [[ "$part" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      start="${BASH_REMATCH[1]}"; end="${BASH_REMATCH[2]}"
      if (( start > end )); then
        echo -e "${RED}[Error]${RESET} Invalid port range: $part" >&2
        return 1
      fi
      for (( p=start; p<=end; p++ )); do out+=("$p"); done
    elif [[ "$part" =~ ^[0-9]+$ ]]; then
      out+=("$part")
    elif [[ -n "$part" ]]; then
      echo -e "${RED}[Error]${RESET} Invalid port spec: $part" >&2
      return 1
    fi
  done
  printf '%s\n' "${out[@]}"
}

function check_dependencies() {
  local deps=(curl dig openssl) missing=()
  for d in "${deps[@]}"; do
    command -v "$d" &>/dev/null || missing+=("$d")
  done
  if (( ${#missing[@]} > 0 )); then
    echo -e "${RED}[Fatal]${RESET} Missing required tools: ${missing[*]}"
    echo "On Kali: sudo apt install ${missing[*]}"
    exit 1
  fi
  command -v nc &>/dev/null || echo -e "${YELLOW}[Warning]${RESET} 'nc' not found - port scanning will be skipped."
  if [[ $USE_HTTPX -eq 1 ]] && ! command -v httpx &>/dev/null; then
    echo -e "${YELLOW}[Warning]${RESET} --use-httpx given but 'httpx' not found (ProjectDiscovery httpx). Falling back to curl-based checks."
    echo "On Kali: sudo apt install httpx-toolkit  (or: go install github.com/projectdiscovery/httpx/cmd/httpx@latest)"
    USE_HTTPX=0
  fi
}

function effective_threads() {
  if [[ "$STEALTH" != "normal" ]]; then
    echo 1
  else
    echo "$THREADS"
  fi
}

function stealth_delay() {
  local min max
  case "$STEALTH" in
    paranoid) min=4; max=9 ;;
    high)     min=2; max=5 ;;
    *)        min=$DELAY_MIN; max=$DELAY_MAX ;;
  esac
  local d
  d=$(awk -v mn="$min" -v mx="$max" 'BEGIN{srand(); printf "%.2f", mn+rand()*(mx-mn)}')
  sleep "$d"
}

# ---------------------------------------------------------------------------
# HTTP fetch wrapper: random UA, optional proxy, retry with backoff,
# and specific handling for HTTP 429 (rate limiting) so we back off harder
# rather than hammering a source that's already telling us to slow down.
# ---------------------------------------------------------------------------
function curl_fetch() {
  local url="$1"; shift || true
  local ua="${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}"
  local proxy_args=()
  [[ -n "$PROXY" ]] && proxy_args=(--proxy "$PROXY")
  local attempt=0 out code
  while (( attempt < MAX_RETRIES )); do
    out=$(curl -sS -k -L --max-time 12 -A "$ua" "${proxy_args[@]}" "$@" \
          -w $'\n%{http_code}' "$url" 2>/dev/null) || out=""
    code="${out##*$'\n'}"
    out="${out%$'\n'*}"
    if [[ "$code" == "429" ]]; then
      local backoff=$(( (attempt + 1) * 5 ))
      log_line WARN "429 rate-limited on $url, backing off ${backoff}s"
      sleep "$backoff"
    elif [[ -n "$code" && "$code" != "000" ]]; then
      printf '%s' "$out"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep "$attempt"
  done
  return 1
}

# ---------------------------------------------------------------------------
# Passive subdomain sources
# ---------------------------------------------------------------------------
function src_crtsh() {
  local domain="$1"
  log_line INFO "crt.sh query for $domain"
  local result
  result=$(curl_fetch "https://crt.sh/?q=%25.$domain&output=json") || { log_line WARN "crt.sh failed"; return 0; }
  [[ -z "$result" || "$result" == "[]" ]] && return 0
  echo "$result" | grep -oP '"name_value":"\K[^"]+' | sed 's/\\n/\n/g'
  stealth_delay
}

function src_wayback() {
  local domain="$1"
  log_line INFO "Wayback CDX query for $domain"
  local result
  result=$(curl_fetch "http://web.archive.org/cdx/search/cdx?url=*.$domain&output=text&fl=original&collapse=urlkey") || { log_line WARN "wayback failed"; return 0; }
  [[ -z "$result" ]] && return 0
  echo "$result" | sed -E 's#^https?://##' | cut -d/ -f1 | sed 's/:.*//'
  stealth_delay
}

function src_rapiddns() {
  local domain="$1"
  log_line INFO "RapidDNS query for $domain"
  local result
  result=$(curl_fetch "https://rapiddns.io/subdomain/$domain?full=1") || { log_line WARN "rapiddns failed"; return 0; }
  [[ -z "$result" ]] && return 0
  echo "$result" | grep -oE "[a-zA-Z0-9._-]+\.${domain//./\\.}"
  stealth_delay
}

function src_otx() {
  local domain="$1"
  log_line INFO "OTX passive DNS query for $domain"
  local result
  result=$(curl_fetch "https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns") || { log_line WARN "otx failed"; return 0; }
  [[ -z "$result" ]] && return 0
  echo "$result" | grep -oP '"hostname":\s*"\K[^"]+'
  stealth_delay
}

# ---------------------------------------------------------------------------
# Checkpointing (for --resume)
# ---------------------------------------------------------------------------
function checkpoint_dir_for_domain() {
  local domain="$1"
  # Most recent results dir for this domain, if any.
  local base="results/$domain"
  [[ -d "$base" ]] || return 1
  find "$base" -maxdepth 1 -mindepth 1 -type d | sort | tail -n1
}

function checkpoint_mark_done() {
  local dir="$1" source_name="$2"
  echo "$source_name" >> "$dir/.completed_sources"
}

function checkpoint_is_done() {
  local dir="$1" source_name="$2"
  [[ -f "$dir/.completed_sources" ]] && grep -qxF "$source_name" "$dir/.completed_sources"
}

function checkpoint_append_subs() {
  local dir="$1"; shift
  printf '%s\n' "$@" >> "$dir/.partial_subdomains"
}

# ---------------------------------------------------------------------------
# Scope enforcement (Authorized Scope Enforcement)
#
# Design:
#   - SCOPE_DOMAIN_ENTRIES:   "example.com"   -> matches example.com AND any
#                              *.example.com subdomain.
#   - SCOPE_WILDCARD_ENTRIES: "*.example.com" -> matches subdomains only
#                              (example.com itself must be listed separately
#                              if it should also be in scope).
#   - SCOPE_IP_ENTRIES:       normalized IPv4/IPv6 literals, exact match only.
#
#   All comparisons are done on normalized values (lowercase, no scheme, no
#   trailing dot, no path/port) and use a "." boundary check for subdomain
#   matching so "example.com.evil.com" can never match a scope entry of
#   "example.com" (it does not end in ".example.com").
#
#   Anything that fails to normalize cleanly (malformed hostname, raw
#   non-ASCII/IDN label, empty string) is treated as OUT OF SCOPE. Scope
#   enforcement fails closed, never open.
# ---------------------------------------------------------------------------
function is_ipv4() {
  local ip="$1" o
  [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
    # Reject ambiguous leading-zero octets (e.g. 010) rather than guess
    # decimal-vs-octal intent - a classic scope-check bypass vector.
    [[ "$o" =~ ^0[0-9]+$ ]] && return 1
    (( 10#$o <= 255 )) || return 1
  done
  return 0
}

function is_ipv6() {
  local ip="$1"
  [[ "$ip" == *:* ]] || return 1
  [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] || return 1
  return 0
}

function normalize_ipv4() {
  local ip="$1" o1 o2 o3 o4
  IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
  printf '%d.%d.%d.%d' "$((10#$o1))" "$((10#$o2))" "$((10#$o3))" "$((10#$o4))"
}

function normalize_ipv6() {
  local ip="$1"
  if command -v python3 &>/dev/null; then
    local out
    out=$(python3 -c '
import ipaddress, sys
try:
    print(ipaddress.ip_address(sys.argv[1]).compressed)
except Exception:
    sys.exit(1)
' "$ip" 2>/dev/null)
    if [[ -n "$out" ]]; then
      printf '%s' "$out"
      return 0
    fi
  fi
  # Best-effort fallback when python3 is unavailable: lowercase only.
  # This is not full RFC 5952 canonicalization; install python3 for
  # fully reliable IPv6 scope comparisons.
  printf '%s' "${ip,,}"
}

function is_valid_hostname() {
  local h="$1"
  [[ "$h" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$ ]]
}

# Normalizes a target/scope-entry string for safe comparison.
# Prints the normalized value and returns 0 on success, or prints
# nothing and returns 1 if the input is malformed / cannot be
# safely normalized (fail closed).
function normalize_target() {
  local t="$1"
  t="${t#http://}"; t="${t#https://}"
  t="${t#*@}"                 # strip userinfo@ if present
  t="${t%%/*}"                 # strip path
  t="${t,,}"                   # lowercase
  while [[ "$t" == *. ]]; do t="${t%.}"; done   # strip trailing dot(s)

  # Bracketed IPv6 literal, optionally with :port -> [::1] or [::1]:8443
  if [[ "$t" == \[*\]* ]]; then
    t="${t#\[}"; t="${t%%\]*}"
    if is_ipv6 "$t"; then
      normalize_ipv6 "$t"
      return 0
    fi
    return 1
  fi

  if is_ipv4 "$t"; then
    normalize_ipv4 "$t"
    return 0
  fi
  if is_ipv6 "$t"; then
    normalize_ipv6 "$t"
    return 0
  fi

  # Bare hostname:port (only strip if what remains is a plausible hostname)
  if [[ "$t" =~ ^([a-z0-9.-]+):[0-9]+$ ]]; then
    t="${BASH_REMATCH[1]}"
  fi

  # Fail closed on anything outside the ASCII hostname charset - this
  # rejects raw-Unicode/homograph IDN input rather than guessing at a
  # punycode conversion. Pre-encode IDN scope entries as xn--... (which
  # are pure ASCII and pass through here normally).
  [[ "$t" =~ [^a-z0-9.-] ]] && return 1

  is_valid_hostname "$t" || return 1
  printf '%s' "$t"
  return 0
}

# Loads and normalizes $SCOPE_FILE into the SCOPE_* arrays. No-op if
# SCOPE_FILE is unset. Exits the program if SCOPE_FILE is set but missing,
# or (with --strict-scope) if it resolves to zero valid entries.
function scope_load() {
  SCOPE_ENABLED=0
  SCOPE_DOMAIN_ENTRIES=(); SCOPE_WILDCARD_ENTRIES=(); SCOPE_IP_ENTRIES=()
  [[ -z "$SCOPE_FILE" ]] && return 0

  if [[ ! -f "$SCOPE_FILE" ]]; then
    echo -e "${RED}[Error]${RESET} Scope file not found: $SCOPE_FILE" >&2
    exit 1
  fi

  local raw norm line_no=0 is_wild base key
  declare -A seen=()
  while IFS= read -r raw || [[ -n "$raw" ]]; do
    line_no=$((line_no + 1))
    raw="${raw%%#*}"    # strip trailing comments
    raw="${raw#"${raw%%[![:space:]]*}"}"   # trim leading whitespace
    raw="${raw%"${raw##*[![:space:]]}"}"   # trim trailing whitespace
    [[ -z "$raw" ]] && continue

    is_wild=0; base="$raw"
    if [[ "$base" == \*.* ]]; then
      is_wild=1
      base="${base#\*.}"
    fi

    if ! norm="$(normalize_target "$base")"; then
      echo -e "${YELLOW}[Warning]${RESET} Ignoring malformed scope entry on line $line_no: '$raw'" >&2
      continue
    fi

    key="$([[ $is_wild -eq 1 ]] && echo "*.$norm" || echo "$norm")"
    [[ -n "${seen[$key]:-}" ]] && continue   # de-duplicate
    seen[$key]=1

    if is_ipv4 "$base" || is_ipv6 "$base"; then
      SCOPE_IP_ENTRIES+=("$norm")
    elif [[ $is_wild -eq 1 ]]; then
      SCOPE_WILDCARD_ENTRIES+=("$norm")
    else
      SCOPE_DOMAIN_ENTRIES+=("$norm")
    fi
  done < "$SCOPE_FILE"

  local total=$(( ${#SCOPE_DOMAIN_ENTRIES[@]} + ${#SCOPE_WILDCARD_ENTRIES[@]} + ${#SCOPE_IP_ENTRIES[@]} ))
  if (( total == 0 )); then
    echo -e "${YELLOW}[Warning]${RESET} Scope file '$SCOPE_FILE' contains no valid entries - everything will be treated as out of scope." >&2
    if [[ $STRICT_SCOPE -eq 1 ]]; then
      echo -e "${RED}[Fatal]${RESET} --strict-scope requires at least one valid scope entry." >&2
      exit 1
    fi
  fi

  SCOPE_ENABLED=1
  info "${CYAN}[*] Scope enforcement enabled: $SCOPE_FILE (${#SCOPE_DOMAIN_ENTRIES[@]} domain, ${#SCOPE_WILDCARD_ENTRIES[@]} wildcard, ${#SCOPE_IP_ENTRIES[@]} IP entries)${RESET}"
}

# Returns 0 (true) if $1 is in scope, 1 otherwise. Always true when scope
# enforcement is disabled. Fails closed on malformed/unparseable input.
function scope_in_scope() {
  local raw="$1" target e
  (( SCOPE_ENABLED == 0 )) && return 0

  target="$(normalize_target "$raw")" || return 1
  [[ -z "$target" ]] && return 1

  for e in ${SCOPE_IP_ENTRIES[@]+"${SCOPE_IP_ENTRIES[@]}"}; do
    [[ "$target" == "$e" ]] && return 0
  done
  for e in ${SCOPE_DOMAIN_ENTRIES[@]+"${SCOPE_DOMAIN_ENTRIES[@]}"}; do
    if [[ "$target" == "$e" || "$target" == *".$e" ]]; then
      return 0
    fi
  done
  for e in ${SCOPE_WILDCARD_ENTRIES[@]+"${SCOPE_WILDCARD_ENTRIES[@]}"}; do
    [[ "$target" == *".$e" ]] && return 0
  done
  return 1
}

function scope_block_msg() {
  echo -e "${RED}[SCOPE] BLOCKED:${RESET} $1"
}

function scope_ignored_msg() {
  echo -e "${YELLOW}[SCOPE] OUT OF SCOPE — ignored:${RESET} $1"
}

function print_scope_summary() {
  (( SCOPE_ENABLED == 0 )) && return 0
  echo -e "\n${BOLD}${CYAN}=== Scope Summary ===${RESET}"
  echo -e "  In scope:           ${GREEN}$SCOPE_IN_COUNT${RESET}"
  echo -e "  Out of scope:       ${YELLOW}$SCOPE_OUT_COUNT${RESET}"
  echo -e "  Blocked operations: ${RED}$SCOPE_BLOCKED_COUNT${RESET}"
}

# ---------------------------------------------------------------------------
# DNS brute force (parallel unless stealth != normal)
# Scope is enforced HERE, before any dig call is issued, so out-of-scope
# candidates never trigger a DNS resolution in the first place.
# ---------------------------------------------------------------------------
function dns_brute() {
  local domain="$1"
  local words=()
  if [[ -n "$WORDLIST_FILE" && -f "$WORDLIST_FILE" ]]; then
    mapfile -t words < "$WORDLIST_FILE"
  else
    words=("${DEFAULT_WORDLIST[@]}")
  fi
  local workers; workers=$(effective_threads)
  info "\n${BOLD}${CYAN}[*] DNS brute force: ${#words[@]} candidate(s), $workers worker(s), stealth=$STEALTH${RESET}"

  local -a candidates=()
  local w sub
  for w in "${words[@]}"; do
    sub="${w,,}.$domain"
    if (( SCOPE_ENABLED == 1 )) && ! scope_in_scope "$sub"; then
      # Emitted (not counted here) because this function runs inside a
      # process-substitution subshell - the caller tallies BLOCKED: lines
      # into SCOPE_BLOCKED_COUNT so the stat survives the subshell boundary.
      echo "BLOCKED:$sub"
      continue
    fi
    candidates+=("$sub")
  done

  if (( workers <= 1 )); then
    for sub in "${candidates[@]}"; do
      dig +short "$sub" 2>/dev/null | grep -qE '[0-9a-fA-F:.]' && echo "$sub"
      stealth_delay
    done
  else
    if (( ${#candidates[@]} > 0 )); then
      printf "%s\n" "${candidates[@]}" | \
        xargs -P "$workers" -I{} bash -c 'dig +short "{}" 2>/dev/null | grep -qE "[0-9a-fA-F:.]" && echo "{}"'
    fi
  fi
}

function detect_wildcard() {
  local domain="$1"
  local probe
  probe="$(head /dev/urandom | tr -dc a-z0-9 | head -c 14).$domain"
  if dig +short "$probe" 2>/dev/null | grep -qE '[0-9]'; then
    echo "true"
  else
    echo "false"
  fi
}

function filter_wildcard() {
  local domain="$1"; shift
  local subs=("$@")
  info "\n${BOLD}${CYAN}[*] Filtering wildcard subdomains via DNS checks...${RESET}"
  if [[ "$(detect_wildcard "$domain")" != "true" ]]; then
    info "${YELLOW}No wildcard DNS on the apex domain; nothing to filter.${RESET}"
    printf "%s\n" "${subs[@]}"
    return
  fi
  local sub resolved rand_probe resolved_rand
  for sub in "${subs[@]}"; do
    resolved=$(dig +short "$sub" 2>/dev/null | head -n1)
    rand_probe="$(head /dev/urandom | tr -dc a-z0-9 | head -c 14).$domain"
    resolved_rand=$(dig +short "$rand_probe" 2>/dev/null | head -n1)
    if [[ -n "$resolved" && "$resolved" == "$resolved_rand" ]]; then
      echo "$sub"
    fi
    stealth_delay
  done
}

function check_port_open() {
  command -v nc &>/dev/null && nc -z -w 2 "$1" "$2" &>/dev/null
}

function filter_live() {
  local subs=("$@")
  if [[ $USE_HTTPX -eq 1 ]]; then
    info "\n${BOLD}${CYAN}[*] Checking live subdomains via httpx (${#subs[@]} candidate(s))...${RESET}"
    printf "%s\n" "${subs[@]}" | httpx -silent -follow-redirects -timeout 8 2>/dev/null | sed -E 's#^https?://##' | cut -d/ -f1
    return
  fi
  local workers; workers=$(effective_threads)
  info "\n${BOLD}${CYAN}[*] Checking live subdomains (${#subs[@]} candidate(s), $workers worker(s))...${RESET}"
  if (( workers <= 1 )); then
    local sub
    for sub in "${subs[@]}"; do
      if curl -sk -m 5 -I "https://$sub" 2>/dev/null | head -n1 | grep -qE '^HTTP/'; then
        echo "$sub"
      elif curl -s -m 5 -I "http://$sub" 2>/dev/null | head -n1 | grep -qE '^HTTP/'; then
        echo "$sub"
      fi
      stealth_delay
    done
  else
    printf "%s\n" "${subs[@]}" | xargs -P "$workers" -I{} bash -c '
      curl -sk -m 5 -I "https://{}" 2>/dev/null | head -n1 | grep -qE "^HTTP/" && { echo "{}"; exit 0; }
      curl -s -m 5 -I "http://{}" 2>/dev/null | head -n1 | grep -qE "^HTTP/" && echo "{}"
    '
  fi
}

# Applies scope (allow-list) then exclude (deny-list) filtering to the
# array named by $1, in place. Scope filtering runs first since it is the
# authorization boundary; exclude further narrows an already-authorized set.
function apply_scope_filters() {
  local -n arr_ref=$1
  if (( SCOPE_ENABLED == 1 )); then
    local filtered=() sub
    for sub in ${arr_ref[@]+"${arr_ref[@]}"}; do
      if scope_in_scope "$sub"; then
        filtered+=("$sub")
        SCOPE_IN_COUNT=$((SCOPE_IN_COUNT + 1))
      else
        SCOPE_OUT_COUNT=$((SCOPE_OUT_COUNT + 1))
        [[ $QUIET -eq 0 ]] && scope_ignored_msg "$sub"
      fi
    done
    arr_ref=(${filtered[@]+"${filtered[@]}"})
  fi
  if [[ -n "$EXCLUDE_FILE" && -f "$EXCLUDE_FILE" ]]; then
    local kept=() sub
    for sub in ${arr_ref[@]+"${arr_ref[@]}"}; do
      grep -qxF "$sub" "$EXCLUDE_FILE" 2>/dev/null || kept+=("$sub")
    done
    arr_ref=(${kept[@]+"${kept[@]}"})
  fi
}

# ---------------------------------------------------------------------------
# Diffing against the previous run
# ---------------------------------------------------------------------------
function run_diff() {
  local domain="$1" current_dir="$2"
  local base="results/$domain"
  [[ -d "$base" ]] || { info "${YELLOW}[diff] No prior run found for $domain.${RESET}"; return; }
  local prev_dir
  prev_dir=$(find "$base" -maxdepth 1 -mindepth 1 -type d ! -name "$(basename "$current_dir")" | sort | tail -n1)
  if [[ -z "$prev_dir" || ! -f "$prev_dir/subdomains.txt" ]]; then
    info "${YELLOW}[diff] No prior run with subdomains.txt found for $domain.${RESET}"
    return
  fi
  info "\n${BOLD}${CYAN}[*] Diffing against previous run: $prev_dir${RESET}"
  local new_hosts removed_hosts
  new_hosts=$(comm -13 <(sort -u "$prev_dir/subdomains.txt") <(sort -u "$current_dir/subdomains.txt"))
  removed_hosts=$(comm -23 <(sort -u "$prev_dir/subdomains.txt") <(sort -u "$current_dir/subdomains.txt"))
  {
    echo "MonarchDomain diff report - $(date)"
    echo "Domain: $domain"
    echo "Previous run: $prev_dir"
    echo "Current run:  $current_dir"
    echo
    echo "NEW subdomains:"
    [[ -n "$new_hosts" ]] && echo "$new_hosts" | sed 's/^/  + /' || echo "  (none)"
    echo
    echo "REMOVED subdomains:"
    [[ -n "$removed_hosts" ]] && echo "$removed_hosts" | sed 's/^/  - /' || echo "  (none)"
  } | tee "$current_dir/diff.txt"
}

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
function record_finding() {
  local sev="$1" msg="$2" host="${3:-}" confidence="${4:-Confirmed}"
  local lc="${msg,,}"
  local existing h2 m2
  for existing in "${FINDINGS[@]:-}"; do
    [[ -z "$existing" ]] && continue
    IFS='|' read -r _ h2 m2 _ <<< "$existing"
    if [[ "$h2" == "$host" && "${m2,,}" == *"$lc"* ]]; then
      return
    fi
  done
  FINDINGS+=("$sev|$host|$msg|$confidence")
}

function print_findings() {
  echo -e "\n${BOLD}${CYAN}=== Findings Summary ===${RESET}"
  if (( ${#FINDINGS[@]} == 0 )); then
    echo -e "${GREEN}No issues flagged by automated checks. Manual review still recommended.${RESET}"
    return
  fi
  local f sev host msg confidence
  for f in "${FINDINGS[@]}"; do
    IFS='|' read -r sev host msg confidence <<< "$f"
    case "$sev" in
      critical) echo -e "${RED}[CRITICAL]${RESET} ($host) $msg" ;;
      major)    echo -e "${YELLOW}[MAJOR]${RESET} ($host) $msg" ;;
      *)        echo -e "${GREEN}[MINOR]${RESET} ($host) $msg" ;;
    esac
  done
}

function print_endpoints() {
  (( ENDPOINTS_ENABLED == 0 )) && return 0
  echo -e "\n${BOLD}${CYAN}=== Endpoints Discovered ===${RESET}"
  if (( ${#SCAN_ENDPOINTS[@]} == 0 )); then
    echo -e "${YELLOW}No endpoints discovered.${RESET}"
    return
  fi
  echo "[ENDPOINTS]"
  local e url type source status
  for e in "${SCAN_ENDPOINTS[@]}"; do
    IFS='|' read -r url type source status <<< "$e"
    echo "  $url  (${type}, via ${source}, HTTP ${status:-?})"
  done
}

function detect_waf() {
  local host="$1" headers sig=""
  headers=$(curl -sk -m 8 -I "https://$host" 2>/dev/null) || { echo ""; return; }
  echo "$headers" | grep -qi "cloudflare"          && sig="Cloudflare"
  echo "$headers" | grep -qi "x-sucuri-id"         && sig="Sucuri"
  echo "$headers" | grep -qi "x-akamai"            && sig="Akamai"
  echo "$headers" | grep -qi "incap_ses\|incapsula" && sig="Imperva Incapsula"
  echo "$headers" | grep -qi "x-amz-cf-id"         && sig="AWS CloudFront"
  if [[ -n "$sig" ]]; then
    # Printed to stderr (not via info()) so callers can safely capture this
    # function's stdout via command substitution (waf=$(detect_waf "$host"))
    # without the informational line leaking into the captured value.
    [[ $QUIET -eq 0 ]] && echo -e "${YELLOW}[i] WAF/CDN detected: $sig (some active checks may be filtered)${RESET}" >&2
  fi
  echo "$sig"
}

function vuln_scan() {
  local host="$1"

  if (( SCOPE_ENABLED == 1 )) && ! scope_in_scope "$host"; then
    scope_block_msg "$host"
    SCOPE_BLOCKED_COUNT=$((SCOPE_BLOCKED_COUNT + 1))
    return
  fi

  info "\n${BOLD}${CYAN}[*] Scanning $host${RESET}"

  local ip
  ip=$(dig +short "$host" 2>/dev/null | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$|^[0-9a-fA-F:]+$' | head -n1)

  local waf
  waf=$(detect_waf "$host")

  local headers live_scheme="https"
  headers=$(curl -sk -m 10 -I "https://$host" 2>/dev/null || true)
  if [[ -z "$headers" ]]; then
    headers=$(curl -s -m 10 -I "http://$host" 2>/dev/null || true)
    live_scheme="http"
  fi

  local live=0
  if [[ -z "$headers" ]]; then
    info "${YELLOW}[-] No response from $host${RESET}"
    record_finding minor "Host did not respond to HTTP(S) requests" "$host" "Confirmed"
  else
    live=1
    local h sev
    for h in "Content-Security-Policy" "Strict-Transport-Security" "X-Frame-Options" "X-Content-Type-Options" "Referrer-Policy" "Permissions-Policy"; do
      if echo "$headers" | grep -iq "^$h:"; then
        info "${GREEN}[+] $h present${RESET}"
        SCAN_HEADERS+=("$host|$h|present")
      else
        info "${YELLOW}[-] Missing $h${RESET}"
        SCAN_HEADERS+=("$host|$h|missing")
        sev="minor"
        [[ "$h" == "Content-Security-Policy" || "$h" == "Strict-Transport-Security" ]] && sev="major"
        record_finding "$sev" "Missing security header: $h" "$host" "Confirmed"
      fi
    done
  fi

  SCAN_HOSTS+=("$host|${ip:-unknown}|$live|${waf:-Unknown}")

  info "${BOLD}[*] Port scan (${#COMMON_PORTS[@]} common ports)...${RESET}"
  local p
  for p in "${COMMON_PORTS[@]}"; do
    if check_port_open "$host" "$p"; then
      info "${GREEN}[+] Port $p open${RESET}"
      SCAN_PORTS+=("$host|$p")
      if [[ "$p" != "80" && "$p" != "443" ]]; then
        case "$p" in
          # Ports commonly associated with database/datastore services - if
          # reachable from outside, this is a materially more serious
          # exposure than an arbitrary non-standard port being open.
          3306|5432|6379|27017|9200)
            record_finding critical "Sensitive service port $p open (possible database/datastore exposure)" "$host" "Confirmed" ;;
          *)
            record_finding minor "Non-standard port $p open" "$host" "Confirmed" ;;
        esac
      fi
    fi
    stealth_delay
  done

  if check_port_open "$host" 443; then
    local cert not_after expire_epoch days_left
    cert=$(echo | openssl s_client -connect "$host:443" -servername "$host" 2>/dev/null | openssl x509 -noout -dates 2>/dev/null || true)
    if [[ -n "$cert" ]]; then
      not_after=$(echo "$cert" | grep notAfter | cut -d= -f2)
      expire_epoch=$(date -d "$not_after" +%s 2>/dev/null || true)
      if [[ -n "$expire_epoch" ]]; then
        days_left=$(( (expire_epoch - $(date +%s)) / 86400 ))
        info "SSL cert expires in $days_left day(s)."
        SCAN_TLS+=("$host|$days_left|$not_after")
        (( days_left < 30 )) && record_finding major "SSL certificate expires in $days_left day(s)" "$host" "Confirmed"
      fi
    else
      record_finding major "Could not retrieve SSL certificate info" "$host" "Potential misconfiguration - insufficient evidence"
    fi
  fi

  if (( live == 1 && ENDPOINTS_ENABLED == 1 )); then
    if declare -f endpoints_discover_host > /dev/null 2>&1; then
      endpoints_discover_host "$host" "$live_scheme"
    else
      [[ $QUIET -eq 0 ]] && echo -e "${YELLOW}[!] --endpoints requested but lib/endpoints.sh could not be loaded (expected at $SCRIPT_DIR/lib/endpoints.sh); skipping endpoint discovery for $host.${RESET}" >&2
    fi
  fi
}

function write_json_report() {
  local out="$1"
  {
    echo "{"
    echo "  \"tool\": \"MonarchDomain\","
    echo "  \"version\": \"$VERSION\","
    echo "  \"domain\": \"$(json_escape "$DOMAIN")\","
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"duration_seconds\": ${SCAN_DURATION_SECONDS:-0},"
    echo "  \"subdomains\": ["
    local i n=${#subdomains[@]}
    for i in "${!subdomains[@]}"; do
      printf '    "%s"%s\n' "$(json_escape "${subdomains[$i]}")" "$([[ $i -lt $((n-1)) ]] && echo ,)"
    done
    echo "  ],"
    echo "  \"hosts\": ["
    n=${#SCAN_HOSTS[@]}
    local hst ip live tech
    for i in "${!SCAN_HOSTS[@]}"; do
      IFS='|' read -r hst ip live tech <<< "${SCAN_HOSTS[$i]}"
      printf '    {"host": "%s", "ip": "%s", "live": %s, "technology": "%s"}%s\n' \
        "$(json_escape "$hst")" "$(json_escape "$ip")" \
        "$([[ "$live" == "1" ]] && echo true || echo false)" \
        "$(json_escape "$tech")" "$([[ $i -lt $((n-1)) ]] && echo ,)"
    done
    echo "  ],"
    echo "  \"open_ports\": ["
    n=${#SCAN_PORTS[@]}
    local pport
    for i in "${!SCAN_PORTS[@]}"; do
      IFS='|' read -r hst pport <<< "${SCAN_PORTS[$i]}"
      printf '    {"host": "%s", "port": %s}%s\n' \
        "$(json_escape "$hst")" "$pport" "$([[ $i -lt $((n-1)) ]] && echo ,)"
    done
    echo "  ],"
    echo "  \"tls\": ["
    n=${#SCAN_TLS[@]}
    local days notafter
    for i in "${!SCAN_TLS[@]}"; do
      IFS='|' read -r hst days notafter <<< "${SCAN_TLS[$i]}"
      printf '    {"host": "%s", "days_until_expiry": %s, "not_after": "%s"}%s\n' \
        "$(json_escape "$hst")" "$days" "$(json_escape "$notafter")" "$([[ $i -lt $((n-1)) ]] && echo ,)"
    done
    echo "  ],"
    echo "  \"findings\": ["
    n=${#FINDINGS[@]}
    local sev host msg confidence
    for i in "${!FINDINGS[@]}"; do
      IFS='|' read -r sev host msg confidence <<< "${FINDINGS[$i]}"
      printf '    {"severity": "%s", "host": "%s", "message": "%s", "confidence": "%s"}%s\n' \
        "$(json_escape "$sev")" "$(json_escape "$host")" "$(json_escape "$msg")" \
        "$(json_escape "${confidence:-Confirmed}")" "$([[ $i -lt $((n-1)) ]] && echo ,)"
    done
    echo "  ],"
    echo "  \"endpoints_enabled\": $([[ $ENDPOINTS_ENABLED -eq 1 ]] && echo true || echo false),"
    echo "  \"endpoints\": ["
    n=${#SCAN_ENDPOINTS[@]}
    local eurl etype esource estatus
    for i in "${!SCAN_ENDPOINTS[@]}"; do
      IFS='|' read -r eurl etype esource estatus <<< "${SCAN_ENDPOINTS[$i]}"
      printf '    {"url": "%s", "type": "%s", "source": "%s", "status_code": %s}%s\n' \
        "$(json_escape "$eurl")" "$(json_escape "$etype")" "$(json_escape "$esource")" \
        "${estatus:-0}" "$([[ $i -lt $((n-1)) ]] && echo ,)"
    done
    echo "  ],"
    echo "  \"scope\": {"
    echo "    \"enabled\": $([[ $SCOPE_ENABLED -eq 1 ]] && echo true || echo false),"
    echo "    \"scope_file\": \"$(json_escape "${SCOPE_FILE:-}")\","
    echo "    \"in_scope\": $SCOPE_IN_COUNT,"
    echo "    \"out_of_scope\": $SCOPE_OUT_COUNT,"
    echo "    \"blocked_operations\": $SCOPE_BLOCKED_COUNT"
    echo "  }"
    echo "}"
  } > "$out"
}

# ---------------------------------------------------------------------------
# write_text_report OUT_PATH
# Extracted from main() so both the normal text-format run and
# build_html_report() (lib/html_report.sh) can produce the identical text
# report without duplicating this formatting logic.
# ---------------------------------------------------------------------------
function write_text_report() {
  local out="$1"
  {
    echo "MonarchDomain v$VERSION scan report - $(date)"
    echo "Target: $DOMAIN"
    echo
    echo "Subdomains (${#subdomains[@]}):"
    printf '  %s\n' "${subdomains[@]}"
    echo
    echo "Findings:"
    local f sev host msg confidence
    for f in "${FINDINGS[@]}"; do
      IFS='|' read -r sev host msg confidence <<< "$f"
      printf '  [%s] (%s) %s\n' "$sev" "$host" "$msg"
    done
    echo
    echo "Endpoints (${#SCAN_ENDPOINTS[@]}):"
    if [[ $ENDPOINTS_ENABLED -eq 1 ]]; then
      local e eurl etype esource estatus
      for e in ${SCAN_ENDPOINTS[@]+"${SCAN_ENDPOINTS[@]}"}; do
        IFS='|' read -r eurl etype esource estatus <<< "$e"
        printf '  [%s] %s (via %s, HTTP %s)\n' "$etype" "$eurl" "$esource" "${estatus:-?}"
      done
    else
      echo "  Endpoint discovery not enabled (use --endpoints)."
    fi
    echo
    echo "Scope:"
    if [[ $SCOPE_ENABLED -eq 1 ]]; then
      echo "  Enabled: yes ($SCOPE_FILE)"
      echo "  In scope: $SCOPE_IN_COUNT"
      echo "  Out of scope: $SCOPE_OUT_COUNT"
      echo "  Blocked operations: $SCOPE_BLOCKED_COUNT"
    else
      echo "  Enabled: no"
    fi
  } > "$out"
}

function main() {
  local scan_start_epoch
  scan_start_epoch=$(date +%s)

  if [[ $# -eq 0 ]]; then usage; exit 1; fi
  parse_args "$@"
  check_dependencies

  if [[ -z "$DOMAIN" ]]; then
    echo -e "${RED}[Error]${RESET} -d/--domain is required."
    usage; exit 1
  fi
  if [[ ! "$THREADS" =~ ^[0-9]+$ || "$THREADS" -lt 1 ]]; then
    echo -e "${RED}[Error]${RESET} --threads must be a positive integer."
    exit 1
  fi
  if [[ ! "$ENDPOINTS_MAX" =~ ^[0-9]+$ || "$ENDPOINTS_MAX" -lt 1 ]]; then
    echo -e "${RED}[Error]${RESET} --endpoints-max must be a positive integer."
    exit 1
  fi
  if [[ $STRICT_SCOPE -eq 1 && -z "$SCOPE_FILE" ]]; then
    echo -e "${RED}[Error]${RESET} --strict-scope requires --scope FILE."
    exit 1
  fi
  if ! DOMAIN=$(validate_domain "$DOMAIN"); then
    exit 1
  fi
  if [[ -n "$PORTS_SPEC" ]]; then
    mapfile -t COMMON_PORTS < <(parse_ports_spec "$PORTS_SPEC") || exit 1
  fi

  scope_load
  if (( SCOPE_ENABLED == 1 )) && ! scope_in_scope "$DOMAIN"; then
    scope_block_msg "$DOMAIN"
    echo -e "${RED}[Fatal]${RESET} Target domain '$DOMAIN' is not covered by scope file '$SCOPE_FILE'. Refusing to scan." >&2
    exit 1
  fi

  log_line INFO "=== MonarchDomain v$VERSION run started for $DOMAIN (stealth=$STEALTH) ==="
  if [[ -n "$CONFIG_LOADED" ]]; then
    log_line INFO "Loaded config file: $CONFIG_LOADED"
    info "${CYAN}[*] Loaded config: $CONFIG_LOADED${RESET}"
  fi

  local timestamp results_dir resuming=0
  if [[ $RESUME -eq 1 ]]; then
    local prior_dir
    prior_dir=$(checkpoint_dir_for_domain "$DOMAIN" || true)
    if [[ -n "$prior_dir" && -f "$prior_dir/.completed_sources" ]]; then
      results_dir="$prior_dir"
      resuming=1
      info "${CYAN}[*] Resuming previous run: $results_dir${RESET}"
    else
      info "${YELLOW}[!] --resume given but no resumable run found; starting fresh.${RESET}"
    fi
  fi
  if [[ -z "${results_dir:-}" ]]; then
    timestamp=$(date +%Y%m%d-%H%M%S)
    results_dir="results/$DOMAIN/$timestamp"
  fi
  [[ -z "$OUTPUT_FILE" ]] && mkdir -p "$results_dir"

  if [[ $MODE_VULN_ONLY -eq 0 ]]; then
    info "${BOLD}${BLUE}[*] Enumerating subdomains for $DOMAIN (sources: $SOURCES)...${RESET}"
    local combined=() t=()

    if (( resuming )) && [[ -f "$results_dir/.partial_subdomains" ]]; then
      mapfile -t t < "$results_dir/.partial_subdomains"
      combined+=("${t[@]}")
    fi

    run_source_if_needed() {
      local name="$1" fn="$2"
      if (( resuming )) && checkpoint_is_done "$results_dir" "$name"; then
        info "${CYAN}[*] Skipping already-completed source: $name${RESET}"
        return
      fi
      mapfile -t t < <("$fn" "$DOMAIN")
      combined+=("${t[@]}")
      checkpoint_append_subs "$results_dir" "${t[@]}"
      checkpoint_mark_done "$results_dir" "$name"
    }

    [[ "$SOURCES" == "all" || "$SOURCES" == *crtsh* ]]    && run_source_if_needed "crtsh" src_crtsh
    [[ "$SOURCES" == "all" || "$SOURCES" == *wayback* ]]  && run_source_if_needed "wayback" src_wayback
    [[ "$SOURCES" == "all" || "$SOURCES" == *otx* ]]      && run_source_if_needed "otx" src_otx
    [[ "$SOURCES" == "all" || "$SOURCES" == *rapiddns* ]] && run_source_if_needed "rapiddns" src_rapiddns
    if ! { (( resuming )) && checkpoint_is_done "$results_dir" "dns_brute"; }; then
      mapfile -t t < <(dns_brute "$DOMAIN")
      local -a brute_resolved=() line
      for line in ${t[@]+"${t[@]}"}; do
        if [[ "$line" == BLOCKED:* ]]; then
          SCOPE_BLOCKED_COUNT=$((SCOPE_BLOCKED_COUNT + 1))
          [[ $QUIET -eq 0 ]] && scope_block_msg "${line#BLOCKED:}"
        else
          brute_resolved+=("$line")
        fi
      done
      combined+=(${brute_resolved[@]+"${brute_resolved[@]}"})
      checkpoint_append_subs "$results_dir" ${brute_resolved[@]+"${brute_resolved[@]}"}
      checkpoint_mark_done "$results_dir" "dns_brute"
    else
      info "${CYAN}[*] Skipping already-completed source: dns_brute${RESET}"
    fi

    local domain_escaped="${DOMAIN//./\\.}"
    mapfile -t subdomains < <(printf "%s\n" "${combined[@]}" | sed 's/^\*\.//' | tr '[:upper:]' '[:lower:]' | grep -E "(^|\.)${domain_escaped}$" | sort -u)

    apply_scope_filters subdomains

    if [[ $FILTER_WILDCARD -eq 1 && ${#subdomains[@]} -gt 0 ]]; then
      mapfile -t subdomains < <(filter_wildcard "$DOMAIN" "${subdomains[@]}")
    fi
    if [[ $FILTER_LIVE -eq 1 && ${#subdomains[@]} -gt 0 ]]; then
      mapfile -t subdomains < <(filter_live "${subdomains[@]}")
    fi

    info "${GREEN}[+] Found ${#subdomains[@]} unique subdomain(s).${RESET}"
    local s
    for s in "${subdomains[@]}"; do info "  - $s"; done

    if [[ -n "$OUTPUT_FILE" ]]; then
      printf "%s\n" "${subdomains[@]}" > "$OUTPUT_FILE"
    else
      printf "%s\n" "${subdomains[@]}" > "$results_dir/subdomains.txt"
    fi

    if [[ $DIFF_MODE -eq 1 && -z "$OUTPUT_FILE" ]]; then
      run_diff "$DOMAIN" "$results_dir"
    fi

    if [[ $MODE_SUBS_ONLY -eq 1 ]]; then
      print_scope_summary
      log_line INFO "Run complete (subs-only)."
      exit 0
    fi
  fi

  local targets=("$DOMAIN")
  [[ $MODE_VULN_ONLY -eq 0 ]] && targets+=("${subdomains[@]:0:30}")

  info "\n${BOLD}${BLUE}[*] Running vulnerability scans on ${#targets[@]} target(s)...${RESET}"
  local target
  for target in "${targets[@]}"; do
    vuln_scan "$target"
  done

  print_findings
  print_endpoints
  print_scope_summary

  SCAN_DURATION_SECONDS=$(( $(date +%s) - scan_start_epoch ))

  if [[ "$OUTPUT_FORMAT" == "json" ]]; then
    write_json_report "${OUTPUT_FILE:-$results_dir/report.json}"
  else
    write_text_report "${OUTPUT_FILE:-$results_dir/report.txt}"
  fi

  if [[ $HTML_REPORT -eq 1 ]]; then
    if declare -f build_html_report > /dev/null 2>&1; then
      local html_dir="${REPORT_DIR:-$results_dir/monarch-report}"
      build_html_report "$html_dir"
      info "${CYAN}[*] HTML report: $html_dir/report.html${RESET}"
      log_line INFO "HTML report written to $html_dir/report.html"
    else
      echo -e "${YELLOW}[!] --html-report requested but lib/html_report.sh could not be loaded (expected at $SCRIPT_DIR/lib/html_report.sh); skipping HTML report.${RESET}" >&2
    fi
  fi

  log_line INFO "Run finished."
  info "\n${BOLD}${GREEN}[OK] Scan complete.${RESET}"
  if [[ -z "$OUTPUT_FILE" ]]; then
    info "${CYAN}Results saved under: $results_dir${RESET}"
  fi
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
  exit 0
fi
