#!/usr/bin/env bash
# shellcheck disable=SC2154
# The following globals are intentionally NOT declared in this file - they
# are declared and populated by monarchdomain.sh, which is the only script
# that sources this one: DOMAIN, VERSION, subdomains, FINDINGS, SCAN_HOSTS,
# SCAN_PORTS, SCAN_TLS, SCAN_HEADERS, SCAN_ENDPOINTS, ENDPOINTS_ENABLED,
# SCOPE_ENABLED, SCOPE_FILE, SCOPE_IN_COUNT, SCOPE_OUT_COUNT,
# SCOPE_BLOCKED_COUNT, SCAN_DURATION_SECONDS, json_escape, write_json_report,
# write_text_report.
#
# lib/html_report.sh - MonarchDomain HTML report renderer (Feature 2)
#
# This file is sourced by monarchdomain.sh (never executed standalone). It
# does NOT perform any scanning of its own - it only reads the normalized
# result arrays that monarchdomain.sh already populates while scanning
# (subdomains, FINDINGS, SCAN_HOSTS, SCAN_PORTS, SCAN_TLS, SCAN_HEADERS,
# SCOPE_* counters, DOMAIN, VERSION, SCAN_DURATION_SECONDS, ...) and renders
# them into a self-contained, offline-viewable HTML dashboard.
#
# Architecture:
#   scanners -> normalized result arrays -> write_text_report / write_json_report / build_html_report
#
# Data shapes (all pipe-delimited strings, same convention already used by
# FINDINGS in monarchdomain.sh):
#   FINDINGS      : severity|host|message|confidence
#   SCAN_HOSTS    : host|ip|live(0|1)|technology_or_waf
#   SCAN_PORTS    : host|port
#   SCAN_TLS      : host|days_until_expiry|not_after
#   SCAN_HEADERS  : host|header_name|present|missing
#   SCAN_ENDPOINTS: url|type|source|status_code   (Feature 3: lib/endpoints.sh)
#
# Security: every piece of scan-derived text (domains, hosts, header names,
# messages, DNS/WHOIS-ish strings, etc.) MUST be passed through html_escape
# before being written into report.html. Nothing here trusts its inputs.
# ---------------------------------------------------------------------------
# html_escape STRING
# Escapes the five HTML-significant characters. Safe for both element text
# content and double-quoted attribute values.
# ---------------------------------------------------------------------------
# Length of an array given by name. All arrays this is called with
# (subdomains, FINDINGS, SCAN_*) are pre-declared as empty arrays in
# monarchdomain.sh, so this is safe under `set -u`.
function _arr_len() {
  local -n _arr_len_ref="$1"
  printf '%s' "${#_arr_len_ref[@]}"
}

function html_escape() {
  # NOTE: in bash's ${var//pattern/replacement}, an unescaped & inside
  # `replacement` means "the matched text" (like sed) - it must be
  # backslash-escaped (\&) to mean a literal ampersand, or every one of
  # these would corrupt its own output (e.g. "<" -> "<lt;" instead of
  # "&lt;"). This bit us during development; keep the backslashes.
  local s="${1-}"
  s="${s//&/\&amp;}"
  s="${s//</\&lt;}"
  s="${s//>/\&gt;}"
  s="${s//\"/\&quot;}"
  s="${s//\'/\&#39;}"
  printf '%s' "$s"
}

# ---------------------------------------------------------------------------
# sev_tier SEVERITY
# Maps MonarchDomain's internal 3-level severity token (critical|major|minor)
# onto the 5-tier scale the report displays (Critical/High/Medium/Low/
# Informational). Unknown input safely falls back to "Informational" rather
# than guessing upward - never over-claim severity for unrecognized data.
# Prints: "<Tier>|<css-class>"
# ---------------------------------------------------------------------------
function sev_tier() {
  local sev="${1,,}"
  case "$sev" in
    critical) printf 'Critical|sev-critical' ;;
    major)    printf 'High|sev-high' ;;
    minor)    printf 'Medium|sev-medium' ;;
    low)      printf 'Low|sev-low' ;;
    info|informational) printf 'Informational|sev-info' ;;
    *) printf 'Informational|sev-info' ;;
  esac
}

# ---------------------------------------------------------------------------
# finding_title / finding_evidence / finding_recommendation
# Small, deliberately literal templates keyed off the exact message strings
# monarchdomain.sh's vuln_scan() produces. These never assert a vulnerability
# that wasn't actually observed - where the scanner itself only has weak
# evidence (e.g. a TLS handshake that failed to return parsable cert data),
# the wording says "Potential misconfiguration", not "vulnerable".
# ---------------------------------------------------------------------------
function finding_title() {
  local msg="$1"
  case "$msg" in
    "Missing security header:"*) printf '%s' "${msg/Missing security header: /Missing Security Header: }" ;;
    "SSL certificate expires in"*) printf 'TLS Certificate Nearing Expiry' ;;
    "Could not retrieve SSL certificate info") printf 'Potential TLS Misconfiguration' ;;
    "Sensitive service port"*"open"*) printf 'Sensitive Data-Store Port Exposed' ;;
    "Non-standard port"*"open") printf 'Non-Standard Port Open' ;;
    "Host did not respond to HTTP(S) requests") printf 'Host Unresponsive to HTTP(S)' ;;
    *) printf '%s' "$msg" ;;
  esac
}

function finding_evidence() {
  local msg="$1" host="$2"
  case "$msg" in
    "Missing security header:"*)
      printf 'HTTP response headers returned by %s did not include this header at scan time.' "$host" ;;
    "SSL certificate expires in"*)
      printf 'TLS handshake against %s:443 (openssl s_client + x509 -dates) returned a notAfter date consistent with the day count shown.' "$host" ;;
    "Could not retrieve SSL certificate info")
      printf 'A TLS handshake against %s:443 did not return parsable certificate data. This can indicate a TLS misconfiguration, WAF/proxy interception, or a transient network condition - the scanner could not confirm which.' "$host" ;;
    "Sensitive service port"*"open"*)
      printf 'A TCP connect probe against %s succeeded on a port commonly associated with a database or datastore service.' "$host" ;;
    "Non-standard port"*"open")
      printf 'A TCP connect probe against %s succeeded on a port outside the standard web ports (80/443).' "$host" ;;
    "Host did not respond to HTTP(S) requests")
      printf 'Neither an HTTPS nor an HTTP request to %s returned a response within the configured timeout.' "$host" ;;
    *) printf 'Observed during automated reconnaissance of %s.' "$host" ;;
  esac
}

function finding_recommendation() {
  local msg="$1"
  case "$msg" in
    "Missing security header: Content-Security-Policy")
      printf 'Deploy a Content-Security-Policy restricting script, style, and object sources to trusted origins.' ;;
    "Missing security header: Strict-Transport-Security")
      printf 'Enable Strict-Transport-Security with a long max-age (and includeSubDomains once verified safe).' ;;
    "Missing security header: X-Frame-Options")
      printf 'Set X-Frame-Options: DENY/SAMEORIGIN, or a CSP frame-ancestors directive, to mitigate clickjacking.' ;;
    "Missing security header: X-Content-Type-Options")
      printf 'Set X-Content-Type-Options: nosniff to stop MIME-type sniffing.' ;;
    "Missing security header: Referrer-Policy")
      printf 'Set a restrictive Referrer-Policy, e.g. strict-origin-when-cross-origin.' ;;
    "Missing security header: Permissions-Policy")
      printf 'Define a Permissions-Policy that disables powerful browser features not in use.' ;;
    "SSL certificate expires in"*)
      printf 'Renew the TLS certificate before expiry; consider automated renewal (e.g. ACME/Lets Encrypt).' ;;
    "Could not retrieve SSL certificate info")
      printf 'Manually verify the TLS configuration on this host and check for WAF/proxy interception.' ;;
    "Sensitive service port"*"open"*)
      printf 'Restrict this port with firewall rules / security groups / VPN; do not expose datastore ports publicly.' ;;
    "Non-standard port"*"open")
      printf 'Confirm this port is intentionally exposed; close or firewall it if it is not required publicly.' ;;
    "Host did not respond to HTTP(S) requests")
      printf 'Confirm this host is intended to be publicly reachable. Informational only if not.' ;;
    *) printf 'Review manually.' ;;
  esac
}

# ---------------------------------------------------------------------------
# _count_live_hosts / _count_distinct_tech
# Small counters over the normalized SCAN_HOSTS array (host|ip|live|tech).
# ---------------------------------------------------------------------------
function _count_live_hosts() {
  local n=0 entry live
  for entry in ${SCAN_HOSTS[@]+"${SCAN_HOSTS[@]}"}; do
    IFS='|' read -r _ _ live _ <<< "$entry"
    [[ "$live" == "1" ]] && n=$((n + 1))
  done
  printf '%s' "$n"
}

function _count_distinct_tech() {
  local entry tech
  declare -A seen=()
  local n=0
  for entry in ${SCAN_HOSTS[@]+"${SCAN_HOSTS[@]}"}; do
    IFS='|' read -r _ _ _ tech <<< "$entry"
    [[ -z "$tech" || "$tech" == "Unknown" ]] && continue
    if [[ -z "${seen[$tech]:-}" ]]; then
      seen[$tech]=1
      n=$((n + 1))
    fi
  done
  printf '%s' "$n"
}

# ---------------------------------------------------------------------------
# Section fragment builders. Every one of these treats its inputs as
# untrusted and runs them through html_escape before writing any markup.
# ---------------------------------------------------------------------------
function _frag_discovered_assets() {
  if [[ $(_arr_len subdomains) -eq 0 ]]; then
    printf '<p class="empty-state">No subdomains were discovered in this run.</p>'
    return
  fi
  printf '<table class="data-table"><thead><tr><th>#</th><th>Subdomain</th></tr></thead><tbody>'
  local i=1 s
  for s in "${subdomains[@]}"; do
    printf '<tr><td>%d</td><td><code>%s</code></td></tr>' "$i" "$(html_escape "$s")"
    i=$((i + 1))
  done
  printf '</tbody></table>'
}

function _frag_live_hosts() {
  local rows="" entry host ip live tech has_rows=0
  for entry in ${SCAN_HOSTS[@]+"${SCAN_HOSTS[@]}"}; do
    IFS='|' read -r host ip live tech <<< "$entry"
    [[ "$live" != "1" ]] && continue
    has_rows=1
    rows+="<tr><td><code>$(html_escape "$host")</code></td><td>$(html_escape "${ip:-unknown}")</td><td>$(html_escape "${tech:-Unknown}")</td></tr>"
  done
  if [[ $has_rows -eq 0 ]]; then
    printf '<p class="empty-state">No hosts responded to HTTP(S) probes in this run.</p>'
    return
  fi
  printf '<table class="data-table"><thead><tr><th>Host</th><th>Resolved IP</th><th>Technology / WAF</th></tr></thead><tbody>%s</tbody></table>' "$rows"
}

function _frag_dns_intel() {
  local rows="" entry host ip live tech has_rows=0
  for entry in ${SCAN_HOSTS[@]+"${SCAN_HOSTS[@]}"}; do
    IFS='|' read -r host ip live tech <<< "$entry"
    [[ -z "$ip" || "$ip" == "unknown" ]] && continue
    has_rows=1
    rows+="<tr><td><code>$(html_escape "$host")</code></td><td>$(html_escape "$ip")</td></tr>"
  done
  if [[ $has_rows -eq 0 ]]; then
    printf '<p class="empty-state">No DNS resolution data was captured for scanned hosts in this run.</p>'
    return
  fi
  printf '<table class="data-table"><thead><tr><th>Host</th><th>Resolved Address</th></tr></thead><tbody>%s</tbody></table>' "$rows"
}

function _frag_open_ports() {
  if [[ $(_arr_len SCAN_PORTS) -eq 0 ]]; then
    printf '<p class="empty-state">No open ports were recorded (port scanning may have been unavailable, or no scanned host had a reachable port).</p>'
    return
  fi
  printf '<table class="data-table"><thead><tr><th>Host</th><th>Port</th></tr></thead><tbody>'
  local entry host port
  for entry in "${SCAN_PORTS[@]}"; do
    IFS='|' read -r host port <<< "$entry"
    printf '<tr><td><code>%s</code></td><td>%s</td></tr>' "$(html_escape "$host")" "$(html_escape "$port")"
  done
  printf '</tbody></table>'
}

function _frag_technologies() {
  local entry host tech has_rows=0
  declare -A seen=()
  local rows=""
  for entry in ${SCAN_HOSTS[@]+"${SCAN_HOSTS[@]}"}; do
    IFS='|' read -r host _ _ tech <<< "$entry"
    [[ -z "$tech" || "$tech" == "Unknown" ]] && continue
    has_rows=1
    seen["$tech"]+="${seen[$tech]:+, }$host"
  done
  if [[ $has_rows -eq 0 ]]; then
    printf '<p class="empty-state">No WAF/CDN or technology signatures were positively identified in this run.</p>'
    return
  fi
  printf '<table class="data-table"><thead><tr><th>Technology / WAF</th><th>Observed On</th></tr></thead><tbody>'
  local t
  for t in "${!seen[@]}"; do
    printf '<tr><td>%s</td><td>%s</td></tr>' "$(html_escape "$t")" "$(html_escape "${seen[$t]}")"
  done
  printf '</tbody></table>'
}

function _frag_tls() {
  if [[ $(_arr_len SCAN_TLS) -eq 0 ]]; then
    printf '<p class="empty-state">No TLS certificate data was collected (no scanned host had port 443 open, or certificate retrieval failed - see Findings).</p>'
    return
  fi
  printf '<table class="data-table"><thead><tr><th>Host</th><th>Days Until Expiry</th><th>Not After</th></tr></thead><tbody>'
  local entry host days notafter cls
  for entry in "${SCAN_TLS[@]}"; do
    IFS='|' read -r host days notafter <<< "$entry"
    cls=""
    [[ "$days" =~ ^-?[0-9]+$ ]] && (( days < 30 )) && cls=' class="tls-warn"'
    printf '<tr%s><td><code>%s</code></td><td>%s</td><td>%s</td></tr>' \
      "$cls" "$(html_escape "$host")" "$(html_escape "$days")" "$(html_escape "$notafter")"
  done
  printf '</tbody></table>'
}

function _frag_headers() {
  if [[ $(_arr_len SCAN_HEADERS) -eq 0 ]]; then
    printf '<p class="empty-state">No security-header data was collected (no scanned host returned an HTTP(S) response).</p>'
    return
  fi
  printf '<table class="data-table"><thead><tr><th>Host</th><th>Header</th><th>Status</th></tr></thead><tbody>'
  local entry host header status badge
  for entry in "${SCAN_HEADERS[@]}"; do
    IFS='|' read -r host header status <<< "$entry"
    if [[ "$status" == "present" ]]; then
      badge='<span class="pill pill-good">Present</span>'
    else
      badge='<span class="pill pill-bad">Missing</span>'
    fi
    printf '<tr><td><code>%s</code></td><td>%s</td><td>%s</td></tr>' \
      "$(html_escape "$host")" "$(html_escape "$header")" "$badge"
  done
  printf '</tbody></table>'
}

function _frag_endpoints() {
  if [[ "${ENDPOINTS_ENABLED:-0}" -ne 1 ]]; then
    printf '<p class="empty-state">Endpoint/URL discovery was not enabled for this run (use <code>--endpoints</code> to discover robots.txt, sitemap.xml, HTML links/forms/scripts, JS path references, and common API-doc/well-known paths on live hosts).</p>'
    return
  fi
  if [[ $(_arr_len SCAN_ENDPOINTS) -eq 0 ]]; then
    printf '<p class="empty-state">Endpoint discovery ran but found no accessible endpoints for this target.</p>'
    return
  fi
  printf '<table class="data-table"><thead><tr><th>URL</th><th>Type</th><th>Source</th><th>Status</th></tr></thead><tbody>'
  local entry url type source status badge
  for entry in "${SCAN_ENDPOINTS[@]}"; do
    IFS='|' read -r url type source status <<< "$entry"
    if [[ "$status" =~ ^2[0-9][0-9]$ ]]; then
      badge="<span class=\"pill pill-good\">$(html_escape "$status")</span>"
    elif [[ "$status" == "0" ]]; then
      badge='<span class="pill pill-bad">No response</span>'
    else
      badge="<span class=\"pill\">$(html_escape "$status")</span>"
    fi
    printf '<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>' \
      "$(html_escape "$url")" "$(html_escape "$type")" "$(html_escape "$source")" "$badge"
  done
  printf '</tbody></table>'
}

function _frag_findings() {
  if [[ $(_arr_len FINDINGS) -eq 0 ]]; then
    printf '<p class="empty-state">No issues flagged by automated checks. Manual review is still recommended.</p>'
    return
  fi
  local f sev host msg confidence tier cls title evidence recommendation
  for f in "${FINDINGS[@]}"; do
    IFS='|' read -r sev host msg confidence <<< "$f"
    IFS='|' read -r tier cls <<< "$(sev_tier "$sev")"
    title="$(finding_title "$msg")"
    evidence="$(finding_evidence "$msg" "$host")"
    recommendation="$(finding_recommendation "$msg")"
    printf '<div class="finding-card %s">' "$cls"
    printf '<div class="finding-head"><span class="pill %s">%s</span><h3>%s</h3></div>' \
      "$cls" "$(html_escape "$tier")" "$(html_escape "$title")"
    printf '<dl class="finding-meta">'
    printf '<dt>Affected Asset</dt><dd><code>%s</code></dd>' "$(html_escape "$host")"
    printf '<dt>Confidence</dt><dd>%s</dd>' "$(html_escape "${confidence:-Confirmed}")"
    printf '<dt>Description</dt><dd>%s</dd>' "$(html_escape "$msg")"
    printf '<dt>Evidence</dt><dd>%s</dd>' "$(html_escape "$evidence")"
    printf '<dt>Recommendation</dt><dd>%s</dd>' "$(html_escape "$recommendation")"
    printf '</dl></div>'
  done
}

function _frag_severity_badges() {
  local -A counts=([Critical]=0 [High]=0 [Medium]=0 [Low]=0 [Informational]=0)
  local f sev tier cls
  for f in ${FINDINGS[@]+"${FINDINGS[@]}"}; do
    IFS='|' read -r sev _ <<< "$f"
    IFS='|' read -r tier cls <<< "$(sev_tier "$sev")"
    counts[$tier]=$(( ${counts[$tier]:-0} + 1 ))
  done
  local t css icon
  for t in Critical High Medium Low Informational; do
    case "$t" in
      Critical) css="sev-critical"; icon="●" ;;
      High) css="sev-high"; icon="▲" ;;
      Medium) css="sev-medium"; icon="◆" ;;
      Low) css="sev-low"; icon="■" ;;
      *) css="sev-info"; icon="○" ;;
    esac
    printf '<div class="sev-badge %s"><span class="sev-icon">%s</span><span class="sev-count">%s</span><span class="sev-label">%s</span></div>' \
      "$css" "$icon" "${counts[$t]}" "$t"
  done
}

function _frag_scope() {
  if [[ "${SCOPE_ENABLED:-0}" -ne 1 ]]; then
    printf '<p class="empty-state">Scope enforcement was not enabled for this run (no <code>--scope</code> file given). All discovered assets under the target domain were treated as authorized.</p>'
    return
  fi
  printf '<table class="kv-table">'
  printf '<tr><th>Scope file</th><td><code>%s</code></td></tr>' "$(html_escape "${SCOPE_FILE:-}")"
  printf '<tr><th>In scope</th><td>%s</td></tr>' "$(html_escape "${SCOPE_IN_COUNT:-0}")"
  printf '<tr><th>Out of scope</th><td>%s</td></tr>' "$(html_escape "${SCOPE_OUT_COUNT:-0}")"
  printf '<tr><th>Blocked operations</th><td>%s</td></tr>' "$(html_escape "${SCOPE_BLOCKED_COUNT:-0}")"
  printf '</table>'
}

function _write_css() {
  cat > "$1" << 'CSSEOF'
:root {
  --bg: #0a0e16; --bg-glow-1: #1a1040; --bg-glow-2: #0d2b3d;
  --panel: #121728; --panel-alt: #171d33; --panel-raise: #1b2340; --border: #262f4a;
  --text: #eef2fb; --muted: #8f9bbd; --accent: #37e6ff; --accent-2: #a78bfa;
  --crit: #ff3d68; --crit-glow: rgba(255,61,104,.35);
  --high: #ff9f1c; --high-glow: rgba(255,159,28,.3);
  --med: #ffd60a; --med-glow: rgba(255,214,10,.28);
  --low: #06d6a0; --low-glow: rgba(6,214,160,.3);
  --info: #8d99ae; --info-glow: rgba(141,153,174,.25);
  --good: #2ee6a6; --bad: #ff3d68;
  --blue: #4d9bff; --purple: #b18bff; --pink: #ff6bd6; --teal: #22e0c9; --orange: #ffab4a;
}
* { box-sizing: border-box; }
body {
  margin: 0; background:
    radial-gradient(900px 500px at 8% -5%, var(--bg-glow-1), transparent 60%),
    radial-gradient(900px 600px at 100% 0%, var(--bg-glow-2), transparent 55%),
    var(--bg);
  color: var(--text);
  font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.55; -webkit-font-smoothing: antialiased;
}
header.report-header {
  padding: 34px 32px 28px;
  background: linear-gradient(120deg, #140b33 0%, #0f1d3a 55%, #0a2436 100%);
  border-bottom: 1px solid var(--border);
  box-shadow: 0 1px 0 rgba(255,255,255,.03) inset;
}
header.report-header h1 {
  margin: 0 0 14px; font-size: 26px; font-weight: 800; letter-spacing: .01em;
  background: linear-gradient(90deg, #7ff5ff, #a78bfa 55%, #ff8bd6);
  -webkit-background-clip: text; background-clip: text; color: transparent;
}
header.report-header .subtitle { display: flex; flex-wrap: wrap; gap: 8px; }
.meta-chip {
  display: inline-flex; align-items: center; gap: 6px;
  background: rgba(255,255,255,.045); border: 1px solid var(--border);
  border-radius: 999px; padding: 5px 12px; font-size: 12.5px; color: var(--muted);
}
.meta-chip b, .meta-chip code { color: var(--text); font-weight: 600; }
.meta-chip.scope-on { border-color: rgba(6,214,160,.4); color: var(--low); }
.meta-chip.scope-off { border-color: rgba(141,153,174,.4); }
nav.toc {
  display: flex; flex-wrap: wrap; gap: 6px; padding: 12px 32px;
  background: rgba(18,23,40,.92);
  border-bottom: 1px solid var(--border);
  position: sticky; top: 0; z-index: 10;
}
nav.toc a {
  color: var(--muted); text-decoration: none; font-size: 12.5px; font-weight: 600;
  padding: 7px 12px; border-radius: 999px; border: 1px solid transparent;
  transition: color .15s, border-color .15s, background .15s;
}
nav.toc a:hover {
  background: rgba(55,230,255,.08); border-color: rgba(55,230,255,.35); color: var(--accent);
}
main { padding: 28px 32px 64px; max-width: 1200px; margin: 0 auto; }
section { margin-bottom: 42px; }
section h2 {
  display: flex; align-items: center; gap: 10px;
  font-size: 15px; text-transform: uppercase; letter-spacing: .09em; font-weight: 700;
  color: var(--text); border-bottom: 1px solid var(--border); padding-bottom: 10px;
  margin-bottom: 18px;
}
section h2::before {
  content: ''; width: 8px; height: 8px; border-radius: 50%;
  background: var(--accent); box-shadow: 0 0 10px 1px var(--accent);
  flex: none;
}
#exec-summary h2::before { background: var(--accent); box-shadow: 0 0 10px 1px var(--accent); }
#scope h2::before { background: var(--purple); box-shadow: 0 0 10px 1px var(--purple); }
#assets h2::before { background: var(--blue); box-shadow: 0 0 10px 1px var(--blue); }
#live-hosts h2::before { background: var(--low); box-shadow: 0 0 10px 1px var(--low); }
#dns h2::before { background: var(--teal); box-shadow: 0 0 10px 1px var(--teal); }
#ports h2::before { background: var(--orange); box-shadow: 0 0 10px 1px var(--orange); }
#tech h2::before { background: var(--purple); box-shadow: 0 0 10px 1px var(--purple); }
#tls h2::before { background: var(--blue); box-shadow: 0 0 10px 1px var(--blue); }
#headers h2::before { background: var(--pink); box-shadow: 0 0 10px 1px var(--pink); }
#endpoints h2::before { background: var(--info); box-shadow: 0 0 10px 1px var(--info); }
#findings h2::before { background: var(--crit); box-shadow: 0 0 10px 1px var(--crit); }
#raw h2::before { background: var(--muted); box-shadow: 0 0 10px 1px var(--muted); }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; }
.card {
  position: relative; overflow: hidden;
  background: linear-gradient(160deg, var(--panel-raise), var(--panel));
  border: 1px solid var(--border); border-radius: 14px; padding: 18px 18px 16px;
  box-shadow: 0 8px 20px -12px rgba(0,0,0,.6);
}
.card::before {
  content: ''; position: absolute; inset: 0 0 auto 0; height: 3px;
  background: linear-gradient(90deg, var(--accent-color, var(--accent)), transparent);
}
.card .card-icon { font-size: 18px; opacity: .9; margin-bottom: 8px; display: block; }
.card .card-value { font-size: 30px; font-weight: 800; letter-spacing: -.01em; }
.card .card-label { color: var(--muted); font-size: 11.5px; text-transform: uppercase; letter-spacing: .06em; margin-top: 2px; }
.card-hosts { --accent-color: var(--blue); } .card-hosts .card-value { color: var(--blue); }
.card-live { --accent-color: var(--low); } .card-live .card-value { color: var(--low); }
.card-ports { --accent-color: var(--orange); } .card-ports .card-value { color: var(--orange); }
.card-tech { --accent-color: var(--purple); } .card-tech .card-value { color: var(--purple); }
.card-findings { --accent-color: var(--crit); } .card-findings .card-value { color: var(--crit); }
.sev-row { display: flex; flex-wrap: wrap; gap: 14px; }
.sev-badge {
  flex: 1; min-width: 130px; border-radius: 14px; padding: 16px; text-align: center;
  border: 1px solid var(--border); background: var(--panel); position: relative;
}
.sev-badge .sev-icon { display: block; font-size: 16px; margin-bottom: 4px; }
.sev-badge .sev-count { display: block; font-size: 24px; font-weight: 800; }
.sev-badge .sev-label { font-size: 11.5px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
.sev-critical { border-color: var(--crit); background: linear-gradient(160deg, rgba(255,61,104,.12), var(--panel)); box-shadow: 0 0 22px -8px var(--crit-glow); }
.sev-critical .sev-count { color: var(--crit); }
.sev-high { border-color: var(--high); background: linear-gradient(160deg, rgba(255,159,28,.12), var(--panel)); box-shadow: 0 0 22px -8px var(--high-glow); }
.sev-high .sev-count { color: var(--high); }
.sev-medium { border-color: var(--med); background: linear-gradient(160deg, rgba(255,214,10,.10), var(--panel)); box-shadow: 0 0 22px -8px var(--med-glow); }
.sev-medium .sev-count { color: var(--med); }
.sev-low { border-color: var(--low); background: linear-gradient(160deg, rgba(6,214,160,.12), var(--panel)); box-shadow: 0 0 22px -8px var(--low-glow); }
.sev-low .sev-count { color: var(--low); }
.sev-info { border-color: var(--info); background: linear-gradient(160deg, rgba(141,153,174,.10), var(--panel)); box-shadow: 0 0 22px -8px var(--info-glow); }
.sev-info .sev-count { color: var(--info); }
table.data-table, table.kv-table {
  width: 100%; border-collapse: collapse; background: var(--panel);
  border: 1px solid var(--border); border-radius: 10px; overflow: hidden; font-size: 13px;
  box-shadow: 0 6px 16px -12px rgba(0,0,0,.7);
}
table.data-table th, table.data-table td, table.kv-table th, table.kv-table td {
  padding: 10px 14px; border-bottom: 1px solid var(--border); text-align: left;
}
table.data-table th {
  background: linear-gradient(180deg, var(--panel-raise), var(--panel-alt));
  color: var(--accent); font-weight: 700; font-size: 11.5px; text-transform: uppercase; letter-spacing: .05em;
}
table.kv-table th { color: var(--muted); width: 220px; background: var(--panel-alt); }
table.data-table tbody tr:hover { background: rgba(55,230,255,.05); }
table.data-table tbody tr:last-child td, table.kv-table tbody tr:last-child td { border-bottom: none; }
tr.tls-warn { background: rgba(255,159,28,.08); }
tr.tls-warn td { color: var(--high); font-weight: 600; }
code {
  font-family: "SFMono-Regular", Consolas, Menlo, monospace; font-size: 12.5px;
  background: rgba(55,230,255,.08); color: #bdf4ff; padding: 2px 6px; border-radius: 5px;
}
.pill { display: inline-flex; align-items: center; gap: 4px; padding: 3px 11px; border-radius: 999px; font-size: 11px; font-weight: 700; letter-spacing: .02em; }
.pill-good { background: rgba(46,230,166,.15); color: var(--good); border: 1px solid rgba(46,230,166,.35); }
.pill-bad { background: rgba(255,61,104,.15); color: var(--bad); border: 1px solid rgba(255,61,104,.35); }
.pill.sev-critical { background: rgba(255,61,104,.18); color: var(--crit); border: 1px solid rgba(255,61,104,.4); }
.pill.sev-high { background: rgba(255,159,28,.18); color: var(--high); border: 1px solid rgba(255,159,28,.4); }
.pill.sev-medium { background: rgba(255,214,10,.18); color: var(--med); border: 1px solid rgba(255,214,10,.4); }
.pill.sev-low { background: rgba(6,214,160,.18); color: var(--low); border: 1px solid rgba(6,214,160,.4); }
.pill.sev-info { background: rgba(141,153,174,.18); color: var(--info); border: 1px solid rgba(141,153,174,.4); }
.finding-card {
  border: 1px solid var(--border); border-left: 6px solid var(--info);
  border-radius: 12px; background: var(--panel); padding: 18px 20px; margin-bottom: 16px;
  box-shadow: 0 8px 18px -14px rgba(0,0,0,.7);
}
.finding-card.sev-critical { border-left-color: var(--crit); background: linear-gradient(100deg, rgba(255,61,104,.07), var(--panel) 35%); }
.finding-card.sev-high { border-left-color: var(--high); background: linear-gradient(100deg, rgba(255,159,28,.07), var(--panel) 35%); }
.finding-card.sev-medium { border-left-color: var(--med); background: linear-gradient(100deg, rgba(255,214,10,.06), var(--panel) 35%); }
.finding-card.sev-low { border-left-color: var(--low); background: linear-gradient(100deg, rgba(6,214,160,.07), var(--panel) 35%); }
.finding-card.sev-info { border-left-color: var(--info); background: linear-gradient(100deg, rgba(141,153,174,.06), var(--panel) 35%); }
.finding-head { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
.finding-head h3 { margin: 0; font-size: 15px; font-weight: 700; }
dl.finding-meta { margin: 0; display: grid; grid-template-columns: 160px 1fr; row-gap: 8px; column-gap: 10px; }
dl.finding-meta dt { color: var(--muted); font-size: 11.5px; text-transform: uppercase; letter-spacing: .04em; font-weight: 600; }
dl.finding-meta dd { margin: 0; font-size: 13px; }
.empty-state {
  color: var(--muted); font-style: italic; font-size: 13px; padding: 14px 16px;
  background: var(--panel); border: 1px dashed var(--border); border-radius: 10px;
}
footer.report-footer {
  padding: 22px 32px; color: var(--muted); font-size: 12px;
  border-top: 1px solid var(--border); background: rgba(255,255,255,.015);
}
.raw-links a {
  display: inline-flex; align-items: center; gap: 6px;
  color: var(--accent); text-decoration: none; margin-right: 12px; font-size: 13px; font-weight: 600;
  background: rgba(55,230,255,.08); border: 1px solid rgba(55,230,255,.3);
  border-radius: 8px; padding: 8px 14px;
}
.raw-links a:hover { background: rgba(55,230,255,.16); }
CSSEOF
}

# ---------------------------------------------------------------------------
# build_html_report HTML_DIR
# Assembles the offline HTML dashboard at HTML_DIR/report.html, using only
# already-collected normalized scan data. Also drops raw JSON/text copies
# under HTML_DIR/raw/ by calling the existing report writers - it does not
# reimplement report serialization.
# ---------------------------------------------------------------------------
function build_html_report() {
  local html_dir="$1"
  mkdir -p "$html_dir/assets" "$html_dir/raw"

  _write_css "$html_dir/assets/style.css"

  if declare -f write_json_report > /dev/null 2>&1; then
    write_json_report "$html_dir/raw/report.json"
  fi
  if declare -f write_text_report > /dev/null 2>&1; then
    write_text_report "$html_dir/raw/report.txt"
  fi

  local hosts_found; hosts_found="$(_arr_len subdomains)"
  local live_hosts; live_hosts="$(_count_live_hosts)"
  local open_ports_count; open_ports_count="$(_arr_len SCAN_PORTS)"
  local tech_count; tech_count="$(_count_distinct_tech)"
  local findings_count; findings_count="$(_arr_len FINDINGS)"
  local gen_time; gen_time="$(date -Iseconds 2>/dev/null || date)"
  local duration="${SCAN_DURATION_SECONDS:-0}"

  local scope_line="Disabled" scope_chip_cls="scope-off"
  if [[ "${SCOPE_ENABLED:-0}" -eq 1 ]]; then
    scope_line="Enabled (${SCOPE_IN_COUNT:-0} in scope / ${SCOPE_OUT_COUNT:-0} out of scope)"
    scope_chip_cls="scope-on"
  fi
  {
    cat << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MonarchDomain Report - $(html_escape "$DOMAIN")</title>
<link rel="stylesheet" href="assets/style.css">
</head>
<body>
<header class="report-header">
  <h1>MonarchDomain Security Reconnaissance Report</h1>
  <div class="subtitle">
    <span class="meta-chip">Target: <code>$(html_escape "$DOMAIN")</code></span>
    <span class="meta-chip">Generated: <b>$(html_escape "$gen_time")</b></span>
    <span class="meta-chip">Duration: <b>$(html_escape "$duration")s</b></span>
    <span class="meta-chip">MonarchDomain <b>v$(html_escape "$VERSION")</b></span>
    <span class="meta-chip $scope_chip_cls">Scope: $(html_escape "$scope_line")</span>
  </div>
</header>
<nav class="toc">
  <a href="#exec-summary">Executive Summary</a>
  <a href="#scope">Scope</a>
  <a href="#assets">Discovered Assets</a>
  <a href="#live-hosts">Live Hosts</a>
  <a href="#dns">DNS Intelligence</a>
  <a href="#ports">Open Ports</a>
  <a href="#tech">Technologies</a>
  <a href="#tls">TLS</a>
  <a href="#headers">Security Headers</a>
  <a href="#endpoints">Endpoints</a>
  <a href="#findings">Findings</a>
  <a href="#raw">Raw Data</a>
</nav>
<main>

<section id="exec-summary">
  <h2>Executive Summary</h2>
  <div class="cards">
    <div class="card card-hosts"><span class="card-icon">◈</span><div class="card-value">$hosts_found</div><div class="card-label">Hosts Found</div></div>
    <div class="card card-live"><span class="card-icon">◉</span><div class="card-value">$live_hosts</div><div class="card-label">Live Hosts</div></div>
    <div class="card card-ports"><span class="card-icon">◆</span><div class="card-value">$open_ports_count</div><div class="card-label">Open Ports</div></div>
    <div class="card card-tech"><span class="card-icon">▣</span><div class="card-value">$tech_count</div><div class="card-label">Technologies</div></div>
    <div class="card card-findings"><span class="card-icon">▲</span><div class="card-value">$findings_count</div><div class="card-label">Findings</div></div>
  </div>
  <h2 style="margin-top:28px;">Severity Breakdown</h2>
  <div class="sev-row">
$(_frag_severity_badges)
  </div>
</section>

<section id="scope"><h2>Scope</h2>$(_frag_scope)</section>
<section id="assets"><h2>Discovered Assets</h2>$(_frag_discovered_assets)</section>
<section id="live-hosts"><h2>Live Hosts</h2>$(_frag_live_hosts)</section>
<section id="dns"><h2>DNS Intelligence</h2>$(_frag_dns_intel)</section>
<section id="ports"><h2>Open Ports</h2>$(_frag_open_ports)</section>
<section id="tech"><h2>Technologies</h2>$(_frag_technologies)</section>
<section id="tls"><h2>TLS</h2>$(_frag_tls)</section>
<section id="headers"><h2>Security Headers</h2>$(_frag_headers)</section>
<section id="endpoints"><h2>Endpoints</h2>$(_frag_endpoints)</section>
<section id="findings"><h2>Findings</h2>$(_frag_findings)</section>

<section id="raw">
  <h2>Raw Data</h2>
  <p class="raw-links">
    <a href="raw/report.json">raw/report.json</a>
    <a href="raw/report.txt">raw/report.txt</a>
  </p>
</section>

</main>
<footer class="report-footer">
  Generated by MonarchDomain v$(html_escape "$VERSION") for authorized security testing only.
  This report reflects automated, point-in-time checks and is not a substitute for manual review.
</footer>
</body>
</html>
HTMLEOF
  } > "$html_dir/report.html"
}
