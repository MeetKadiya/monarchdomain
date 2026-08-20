#!/usr/bin/env bash
# shellcheck disable=SC2154
# lib/endpoints.sh - MonarchDomain HTTP URL & Endpoint Discovery (Feature 3)
#
# Sourced by monarchdomain.sh (never executed standalone). Discovers
# publicly-accessible URLs on live HTTP/HTTPS hosts using only safe,
# non-destructive, GET-only techniques:
#   robots.txt, sitemap.xml (incl. sitemap indexes), HTML links/forms/script
#   tags, JavaScript path references, and a small fixed list of common
#   well-known/API-documentation paths. No wordlist-based brute forcing is
#   performed here - that stays a distinct, explicitly opt-in feature if it
#   is ever added.
#
# The following globals are declared/populated by monarchdomain.sh (not
# this file): USER_AGENTS, PROXY, MAX_RETRIES, QUIET, SCOPE_ENABLED,
# SCOPE_BLOCKED_COUNT, ENDPOINTS_ENABLED, ENDPOINTS_MAX, ENDPOINTS_TIMEOUT,
# ENDPOINTS_MAX_SITEMAP_DEPTH, SCAN_ENDPOINTS, log_line, info, stealth_delay,
# scope_in_scope, scope_ignored_msg.
#
# Architecture (mirrors lib/html_report.sh's existing convention):
#   pure parsers (testable, no network)  ->  endpoints_maybe_probe (network,
#   scope-checked, deduped, rate-limited)  ->  SCAN_ENDPOINTS (normalized
#   result array, url|type|source|status_code, same pipe-delimited
#   convention as FINDINGS/SCAN_HOSTS/SCAN_PORTS/SCAN_TLS/SCAN_HEADERS)
# ---------------------------------------------------------------------------

ENDPOINTS_COMMON_PATHS=(
  "/robots.txt"
  "/sitemap.xml"
  "/security.txt"
  "/.well-known/security.txt"
  "/openapi.json"
  "/swagger.json"
  "/swagger/"
  "/graphql"
)

# Pre-declared at module load (not just inside endpoints_discover_host) so
# endpoints_maybe_probe() is safely callable on its own - e.g. from tests -
# without first requiring a full endpoints_discover_host() run. Under
# `set -u`, indexing an associative array that was never `declare -A`'d
# falls through to arithmetic-index evaluation of the key string instead,
# which is not what dedupe-by-URL needs.
declare -gA ENDPOINTS_SEEN 2>/dev/null || true
declare -gi ENDPOINTS_REQUEST_COUNT=0

# ---------------------------------------------------------------------------
# url_normalize URL
# Normalizes scheme (lowercased), hostname (lowercased), default ports
# (80 for http, 443 for https - stripped), fragment (stripped), and
# trailing slash (stripped except for the bare root path "/"). Prints the
# normalized URL and returns 0, or prints nothing and returns 1 for a
# malformed/unsupported URL (fail closed - never silently "fix" a bad URL
# into something that looks safe to request).
#
# Uses python3's urllib.parse when available for fully correct handling
# (IDN hosts, percent-encoding, userinfo, etc.). Falls back to a
# best-effort bash implementation covering the common case (plain ASCII
# host, no userinfo) - same "install python3 for full fidelity" pattern
# already used by normalize_ipv6() in monarchdomain.sh.
# ---------------------------------------------------------------------------
function url_normalize() {
  local url="$1"
  if command -v python3 &>/dev/null; then
    python3 -c '
import sys
from urllib.parse import urlsplit, urlunsplit
url = sys.argv[1]
try:
    p = urlsplit(url)
    scheme = p.scheme.lower()
    if scheme not in ("http", "https"):
        sys.exit(1)
    host = p.hostname
    if not host:
        sys.exit(1)
    host = host.lower()
    port = p.port
    netloc = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = "%s:%d" % (host, port)
    path = p.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/") or "/"
    out = urlunsplit((scheme, netloc, path, p.query, ""))
    print(out)
except Exception:
    sys.exit(1)
' "$url" 2>/dev/null
    return $?
  fi
  local scheme host rest path query
  [[ "$url" =~ ^(https?)://([^/?#]+)(.*)$ ]] || return 1
  scheme="${BASH_REMATCH[1],,}"
  host="${BASH_REMATCH[2],,}"
  rest="${BASH_REMATCH[3]}"
  rest="${rest%%#*}"
  path="$rest"; query=""
  if [[ "$path" == *\?* ]]; then query="${path#*\?}"; path="${path%%\?*}"; fi
  [[ -z "$path" ]] && path="/"
  [[ "$scheme" == "http"  && "$host" == *:80  ]] && host="${host%:80}"
  [[ "$scheme" == "https" && "$host" == *:443 ]] && host="${host%:443}"
  if [[ ${#path} -gt 1 && "$path" == */ ]]; then
    while [[ ${#path} -gt 1 && "$path" == */ ]]; do path="${path%/}"; done
    [[ -z "$path" ]] && path="/"
  fi
  local out="$scheme://$host$path"
  [[ -n "$query" ]] && out="$out?$query"
  printf '%s' "$out"
  return 0
}

# ---------------------------------------------------------------------------
# url_join BASE REF
# Resolves a possibly-relative reference (href/src/action/JS-literal path)
# against BASE into an absolute http(s) URL. Prints the result and returns
# 0, or prints nothing and returns 1 if it cannot be safely resolved into
# an http(s) URL (e.g. javascript:, mailto:, data: URIs - fail closed,
# never guess).
# ---------------------------------------------------------------------------
function url_join() {
  local base="$1" ref="$2"
  [[ -z "$ref" ]] && return 1
  if command -v python3 &>/dev/null; then
    python3 -c '
import sys
from urllib.parse import urljoin, urlsplit
base, ref = sys.argv[1], sys.argv[2]
try:
    joined = urljoin(base, ref)
    p = urlsplit(joined)
    if p.scheme not in ("http", "https") or not p.hostname:
        sys.exit(1)
    print(joined)
except Exception:
    sys.exit(1)
' "$base" "$ref" 2>/dev/null
    return $?
  fi
  case "$ref" in
    http://*|https://*) printf '%s' "$ref"; return 0 ;;
    //*)
      local scheme
      [[ "$base" =~ ^(https?): ]] && scheme="${BASH_REMATCH[1]}" || return 1
      printf '%s:%s' "$scheme" "$ref"; return 0 ;;
    /*)
      local scheme host
      [[ "$base" =~ ^(https?)://([^/]+) ]] || return 1
      scheme="${BASH_REMATCH[1]}"; host="${BASH_REMATCH[2]}"
      printf '%s://%s%s' "$scheme" "$host" "$ref"; return 0 ;;
    *) return 1 ;;  # relative (non-root) paths need python3 to resolve safely
  esac
}

# ---------------------------------------------------------------------------
# endpoint_categorize URL
# Best-effort classification into one of: api, authentication,
# documentation, static, administrative, metadata, other. This is purely
# informational grouping for the report - it never asserts or implies that
# a path is vulnerable just because it looks sensitive (e.g. "/admin" is
# categorized "administrative", not flagged as a finding).
# ---------------------------------------------------------------------------
function endpoint_categorize() {
  local url="$1" path
  path="${url#*://}"
  path="${path#*/}"
  path="/${path%%\?*}"
  path="${path,,}"

  case "$path" in
    */robots.txt|*/sitemap*.xml|*/security.txt|*/.well-known/*|*/humans.txt|*/manifest.json)
      printf 'metadata'; return ;;
  esac
  case "$path" in
    *swagger*|*openapi*|*api-docs*|*apidocs*|*redoc*|*/docs|*/docs/*)
      printf 'documentation'; return ;;
  esac
  case "$path" in
    */login*|*/logout*|*/signin*|*/sign-in*|*/signup*|*/sign-up*|*/register*|*/auth*|*oauth*|*/sso*|*password*reset*|*/session*)
      printf 'authentication'; return ;;
  esac
  case "$path" in
    *.js|*.css|*.png|*.jpg|*.jpeg|*.gif|*.svg|*.ico|*.woff|*.woff2|*.ttf|*.map|*/static/*|*/assets/*|*/public/*|*/dist/*)
      printf 'static'; return ;;
  esac
  case "$path" in
    */admin*|*/wp-admin*|*/cpanel*|*/dashboard*|*/manage*|*/console*|*/panel*)
      printf 'administrative'; return ;;
  esac
  case "$path" in
    */api|*/api/*|*/graphql|*/gql|*/rest|*/rest/*|*/v1|*/v1/*|*/v2|*/v2/*)
      printf 'api'; return ;;
  esac
  printf 'other'
}

# ---------------------------------------------------------------------------
# robots.txt parsing (pure - operates on already-fetched content)
# ---------------------------------------------------------------------------
function robots_extract_sitemaps() {
  local content="$1"
  printf '%s\n' "$content" | tr -d '\r' \
    | grep -iE '^[[:space:]]*sitemap[[:space:]]*:' \
    | sed -E 's/^[[:space:]]*[Ss]itemap[[:space:]]*:[[:space:]]*//' \
    | sed '/^$/d'
}

function robots_extract_paths() {
  local content="$1"
  printf '%s\n' "$content" | tr -d '\r' \
    | grep -iE '^[[:space:]]*(disallow|allow)[[:space:]]*:' \
    | sed -E 's/^[[:space:]]*[A-Za-z]+[[:space:]]*:[[:space:]]*//' \
    | sed '/^$/d' | sed '/^\*$/d'
}

# ---------------------------------------------------------------------------
# sitemap.xml / sitemap index parsing (pure)
# ---------------------------------------------------------------------------
function sitemap_is_index() {
  [[ "$1" == *"<sitemapindex"* ]]
}

function sitemap_extract_locs() {
  local content="$1"
  printf '%s\n' "$content" \
    | grep -oE '<loc>[^<]+</loc>' \
    | sed -E 's#</?loc>##g' \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
    | sed '/^$/d'
}

# ---------------------------------------------------------------------------
# HTML link extraction (pure): href= on <a>, src= on <script>, action= on
# <form>. Handles both single- and double-quoted attribute values. Filters
# out non-fetchable pseudo-schemes (javascript:, mailto:, tel:) and
# bare-fragment ("#...") links.
# ---------------------------------------------------------------------------
function html_extract_links() {
  local content="$1" dq='"' sq="'"
  printf '%s' "$content" \
    | grep -ioP "(?:href|src|action)\s*=\s*[${dq}${sq}]\K[^${dq}${sq}]*" 2>/dev/null \
    | sed '/^$/d' \
    | grep -viE '^(javascript|mailto|tel|data):' \
    | grep -v '^#'
}

# ---------------------------------------------------------------------------
# JavaScript path/URL reference extraction (pure). Heuristic: quoted
# strings that are either a full http(s) URL or begin with "/" (root- or
# protocol-relative path), e.g. fetch("/api/users"), axios.get('/login').
# Deliberately conservative - this is not a JS parser, just pattern
# matching over already-fetched script content.
# ---------------------------------------------------------------------------
function js_extract_paths() {
  local content="$1" dq='"' sq="'"
  printf '%s' "$content" \
    | grep -oP "[${dq}${sq}](?:https?://[^${dq}${sq}[:space:]]+|/[a-zA-Z0-9_./-]+)[${dq}${sq}]" 2>/dev/null \
    | sed -E "s/^[${dq}${sq}]//; s/[${dq}${sq}]\$//" \
    | sed '/^$/d' | sort -u
}

# ---------------------------------------------------------------------------
# _endpoints_fetch URL
# GET-only fetch used exclusively by endpoint discovery. Mirrors
# curl_fetch()'s UA rotation / proxy / retry-with-backoff / 429-aware
# behavior (see monarchdomain.sh), kept as a separate function rather than
# changing curl_fetch()'s contract for its existing callers ("do not
# rewrite existing scanners"). Prints "<body>\n<http_status>" to stdout
# (status is always the last line, "0" on total failure) so both pieces
# survive being returned through a `$(...)` command substitution - a
# single extra global (as curl_fetch-style callers might expect) would
# silently vanish here, since a value set *inside* a `$(...)` subshell by
# a callee never propagates back to the caller's shell.
#
# Rate limiting: conservative fixed timeout (ENDPOINTS_TIMEOUT), bounded
# retries (reuses MAX_RETRIES), exponential-ish backoff on 429, and no
# concurrency of its own - callers serialize requests per host and apply
# stealth_delay() between them (see endpoints_maybe_probe).
# ---------------------------------------------------------------------------
function _endpoints_fetch() {
  local url="$1"
  local ua="${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}"
  local proxy_args=()
  [[ -n "${PROXY:-}" ]] && proxy_args=(--proxy "$PROXY")
  local attempt=0 out code retries="${MAX_RETRIES:-3}"
  while (( attempt < retries )); do
    out=$(curl -sS -k -L --max-time "${ENDPOINTS_TIMEOUT:-10}" -A "$ua" "${proxy_args[@]}" \
          -w $'\n%{http_code}' "$url" 2>/dev/null) || out=""
    code="${out##*$'\n'}"
    out="${out%$'\n'*}"
    if [[ "$code" == "429" ]]; then
      local backoff=$(( (attempt + 1) * 5 ))
      log_line WARN "429 rate-limited on $url (endpoint discovery), backing off ${backoff}s"
      sleep "$backoff"
    elif [[ -n "$code" && "$code" != "000" ]]; then
      printf '%s\n%s' "$out" "$code"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep "$attempt"
  done
  printf '\n0'
  return 1
}

# ---------------------------------------------------------------------------
# endpoints_maybe_probe URL SOURCE
# The single choke point every discovered URL passes through before a
# request is ever made. In order: normalize (fail closed on malformed
# URLs) -> dedupe (ENDPOINTS_SEEN) -> scope re-check (fail closed,
# defense-in-depth even though the host was already scope-checked before
# discovery started) -> per-host request cap (ENDPOINTS_MAX) -> rate-limit
# delay -> GET request -> categorize -> record into SCAN_ENDPOINTS.
#
# IMPORTANT: always call this directly (`endpoints_maybe_probe url src`),
# never as `x="$(endpoints_maybe_probe ...)"`. Command substitution forks
# a subshell, and this function's real work - appending to SCAN_ENDPOINTS,
# marking ENDPOINTS_SEEN, incrementing ENDPOINTS_REQUEST_COUNT - are all
# side effects on arrays/vars that must persist in the *caller's* shell.
# The response body (for chained parsing) is instead handed back via the
# global ENDPOINTS_LAST_BODY, which a direct call leaves intact.
# ---------------------------------------------------------------------------
function endpoints_maybe_probe() {
  local raw_url="$1" source="$2"
  ENDPOINTS_LAST_BODY=""
  local norm
  norm="$(url_normalize "$raw_url")" || { log_line WARN "endpoints: skipping malformed URL: $raw_url"; return 1; }

  [[ -n "${ENDPOINTS_SEEN[$norm]:-}" ]] && return 1
  ENDPOINTS_SEEN[$norm]=1

  local hostpart
  hostpart="${norm#*://}"; hostpart="${hostpart%%/*}"; hostpart="${hostpart%%:*}"
  if (( ${SCOPE_ENABLED:-0} == 1 )) && ! scope_in_scope "$hostpart"; then
    SCOPE_BLOCKED_COUNT=$((SCOPE_BLOCKED_COUNT + 1))
    [[ ${QUIET:-0} -eq 0 ]] && scope_ignored_msg "$norm (endpoint)"
    return 1
  fi

  if (( ENDPOINTS_REQUEST_COUNT >= ${ENDPOINTS_MAX:-60} )); then
    return 1
  fi
  ENDPOINTS_REQUEST_COUNT=$((ENDPOINTS_REQUEST_COUNT + 1))

  declare -f stealth_delay > /dev/null 2>&1 && stealth_delay

  local raw status body
  raw="$(_endpoints_fetch "$norm")"
  status="${raw##*$'\n'}"
  body="${raw%$'\n'*}"
  [[ "$body" == "$raw" ]] && body=""

  SCAN_ENDPOINTS+=("$norm|$(endpoint_categorize "$norm")|$source|$status")
  ENDPOINTS_LAST_BODY="$body"
  return 0
}

# ---------------------------------------------------------------------------
# endpoints_process_sitemap URL SOURCE DEPTH
# Fetches a sitemap URL and either recurses (sitemap index, up to
# ENDPOINTS_MAX_SITEMAP_DEPTH) or records each <loc> as a discovered
# endpoint. Depth-bounded so a malicious/misconfigured sitemap index
# cannot cause unbounded recursion (dedup via ENDPOINTS_SEEN independently
# also stops a directly self-referencing sitemap).
# ---------------------------------------------------------------------------
function endpoints_process_sitemap() {
  local url="$1" source="$2" depth="${3:-0}"
  (( depth > ${ENDPOINTS_MAX_SITEMAP_DEPTH:-2} )) && return 0

  endpoints_maybe_probe "$url" "$source"
  local body="$ENDPOINTS_LAST_BODY"
  [[ -z "$body" ]] && return 0

  local loc
  if sitemap_is_index "$body"; then
    while IFS= read -r loc; do
      [[ -z "$loc" ]] && continue
      endpoints_process_sitemap "$loc" "sitemap" $((depth + 1))
    done < <(sitemap_extract_locs "$body")
  else
    while IFS= read -r loc; do
      [[ -z "$loc" ]] && continue
      endpoints_maybe_probe "$loc" "sitemap"
    done < <(sitemap_extract_locs "$body")
  fi
}

# ---------------------------------------------------------------------------
# endpoints_discover_host HOST SCHEME
# Entry point called (once per live host) from vuln_scan() when
# --endpoints is given. Runs every source in Feature 3's spec, all
# GET-only and scope-checked/rate-limited via endpoints_maybe_probe:
#   1. the homepage's HTML links/scripts/forms, plus JS path references
#      pulled out of any same-response-set .js files found that way
#   2. robots.txt -> its Sitemap: entries and Disallow/Allow paths
#   3. sitemap.xml (direct, in case robots.txt didn't reference one)
#   4. the fixed common well-known/API-doc path list
# No wordlist-based brute forcing is performed.
# ---------------------------------------------------------------------------
function endpoints_discover_host() {
  local host="$1" scheme="$2"
  local base="${scheme}://${host}"
  declare -gA ENDPOINTS_SEEN=()
  ENDPOINTS_REQUEST_COUNT=0

  info "\n${BOLD:-}${CYAN:-}[*] Discovering endpoints on $base (safe sources only)...${RESET:-}"

  # Homepage HTML is fetched and parsed FIRST and deliberately not skipped
  # even if something later (a sitemap or robots.txt entry) also points at
  # "/" - dedup is keyed by normalized URL, so whichever source reaches a
  # given URL first "wins" it. Parsing HTML is the only source that reads
  # links/forms/scripts out of the page, so it has to get first claim on
  # the homepage or that entire source would silently go empty whenever a
  # sitemap happens to list the site root (a common, unremarkable case).
  endpoints_maybe_probe "$base/" "html"
  local home_body="$ENDPOINTS_LAST_BODY"
  if [[ -n "$home_body" ]]; then
    local link lurl body2 jp jurl
    while IFS= read -r link; do
      [[ -z "$link" ]] && continue
      lurl="$(url_join "$base/" "$link")" || continue
      endpoints_maybe_probe "$lurl" "html"
      body2="$ENDPOINTS_LAST_BODY"
      if [[ "$lurl" == *.js && -n "$body2" ]]; then
        while IFS= read -r jp; do
          [[ -z "$jp" ]] && continue
          jurl="$(url_join "$lurl" "$jp")" || continue
          endpoints_maybe_probe "$jurl" "javascript"
        done < <(js_extract_paths "$body2")
      fi
    done < <(html_extract_links "$home_body")
  fi

  endpoints_maybe_probe "$base/robots.txt" "robots"
  local robots_body="$ENDPOINTS_LAST_BODY"
  if [[ -n "$robots_body" ]]; then
    local sm
    while IFS= read -r sm; do
      [[ -z "$sm" ]] && continue
      endpoints_process_sitemap "$sm" "robots" 0
    done < <(robots_extract_sitemaps "$robots_body")

    local rp rurl
    while IFS= read -r rp; do
      [[ -z "$rp" ]] && continue
      rurl="$(url_join "$base/" "$rp")" || continue
      endpoints_maybe_probe "$rurl" "robots"
    done < <(robots_extract_paths "$robots_body")
  fi

  endpoints_process_sitemap "$base/sitemap.xml" "sitemap" 0

  local p
  for p in "${ENDPOINTS_COMMON_PATHS[@]}"; do
    [[ "$p" == "/robots.txt" || "$p" == "/sitemap.xml" ]] && continue
    endpoints_maybe_probe "$base$p" "wellknown"
  done
}
