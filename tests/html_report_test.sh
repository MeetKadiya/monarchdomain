#!/usr/bin/env bats
#
# HTML report tests for MonarchDomain (Feature 2 - Professional HTML
# Security Reporting). Run with: bats tests/html_report_test.sh
#
# Like tests/scope_test.sh, these source monarchdomain.sh directly (main()
# is guarded so sourcing does not execute a scan or touch the network) and
# exercise the report-building functions in isolation against synthetic
# normalized-result arrays (subdomains, FINDINGS, SCAN_HOSTS, SCAN_PORTS,
# SCAN_TLS, SCAN_HEADERS) - no scanning, no network access required.
# shellcheck disable=SC2034

setup() {
  SCRIPT_DIR="$(cd "$(dirname "${BATS_TEST_FILENAME}")/.." && pwd)"
  # shellcheck disable=SC1091
  source "$SCRIPT_DIR/monarchdomain.sh"
  TMPDIR_TEST="$(mktemp -d)"
  DOMAIN="example.com"
  VERSION="test"
  SCAN_DURATION_SECONDS=42
  SCOPE_ENABLED=0
  # NOTE: monarchdomain.sh's top-level `declare -a subdomains=()` (and
  # FINDINGS/SCAN_HOSTS/SCAN_PORTS/SCAN_TLS/SCAN_HEADERS) run above via
  # `source`, but that `source` call happens inside this setup() function -
  # so under normal bash scoping those `declare` statements create
  # variables local to setup(), which vanish the instant setup() returns.
  # Without an explicit `-g` here, every @test body below would see them
  # as genuinely unbound under `set -u` (this was verified empirically -
  # it's exactly why this file was never wired into CI until now; see the
  # html-report-tests job in .github/workflows/ci.yml). `declare -g`
  # promotes them to real globals that persist into the test bodies.
  declare -ga subdomains=()
  declare -ga FINDINGS=()
  declare -ga SCAN_HOSTS=()
  declare -ga SCAN_PORTS=()
  declare -ga SCAN_TLS=()
  declare -ga SCAN_HEADERS=()
  declare -ga SCAN_ENDPOINTS=()
  ENDPOINTS_ENABLED=0
}

teardown() {
  rm -rf "$TMPDIR_TEST"
}

# ---------------------------------------------------------------------------
# html_escape
# ---------------------------------------------------------------------------
@test "html_escape neutralizes all five HTML-significant characters" {
  run html_escape '<script>&"'"'"'</script>'
  [ "$status" -eq 0 ]
  [ "$output" = '&lt;script&gt;&amp;&quot;&#39;&lt;/script&gt;' ]
}

@test "html_escape leaves plain text untouched" {
  run html_escape "api.example.com"
  [ "$output" = "api.example.com" ]
}

@test "html_escape handles an empty string without error" {
  run html_escape ""
  [ "$status" -eq 0 ]
  [ "$output" = "" ]
}

# ---------------------------------------------------------------------------
# sev_tier
# ---------------------------------------------------------------------------
@test "sev_tier maps critical/major/minor onto the 5-tier scale" {
  run sev_tier "critical"; [ "$output" = "Critical|sev-critical" ]
  run sev_tier "major";    [ "$output" = "High|sev-high" ]
  run sev_tier "minor";    [ "$output" = "Medium|sev-medium" ]
}

@test "sev_tier never invents a higher tier for unrecognized severities" {
  run sev_tier "banana"
  [ "$output" = "Informational|sev-info" ]
}

# ---------------------------------------------------------------------------
# record_finding / print_findings text-format compatibility
# ---------------------------------------------------------------------------
@test "record_finding defaults confidence to Confirmed when not given" {
  record_finding minor "Non-standard port 8080 open" "host.example.com"
  [ "${#FINDINGS[@]}" -eq 1 ]
  [ "${FINDINGS[0]}" = "minor|host.example.com|Non-standard port 8080 open|Confirmed" ]
}

@test "record_finding stores an explicit confidence value" {
  record_finding major "Could not retrieve SSL certificate info" "host.example.com" "Potential misconfiguration - insufficient evidence"
  [ "${FINDINGS[0]}" = "major|host.example.com|Could not retrieve SSL certificate info|Potential misconfiguration - insufficient evidence" ]
}

@test "print_findings text output format is unchanged by the confidence field" {
  record_finding minor "Non-standard port 8080 open" "host.example.com"
  run print_findings
  [[ "$output" == *"[MINOR] (host.example.com) Non-standard port 8080 open"* ]]
  # The confidence value must never leak into the human-readable line.
  [[ "$output" != *"Confirmed"* ]]
}

# ---------------------------------------------------------------------------
# write_text_report / write_json_report - existing-format preservation
# ---------------------------------------------------------------------------
@test "write_text_report produces the same shape as before (subdomains/findings/scope)" {
  subdomains=("a.example.com" "b.example.com")
  record_finding minor "Non-standard port 8080 open" "a.example.com"
  write_text_report "$TMPDIR_TEST/report.txt"
  run cat "$TMPDIR_TEST/report.txt"
  [[ "$output" == *"Target: example.com"* ]]
  [[ "$output" == *"Subdomains (2):"* ]]
  [[ "$output" == *"a.example.com"* ]]
  [[ "$output" == *"[minor] (a.example.com) Non-standard port 8080 open"* ]]
  [[ "$output" == *"Scope:"* ]]
  [[ "$output" == *"Enabled: no"* ]]
}

@test "write_json_report preserves all pre-existing top-level keys" {
  subdomains=("a.example.com")
  record_finding minor "Non-standard port 8080 open" "a.example.com"
  write_json_report "$TMPDIR_TEST/report.json"
  run python3 -c "
import json
d = json.load(open('$TMPDIR_TEST/report.json'))
for k in ('tool','version','domain','timestamp','subdomains','findings','scope'):
    assert k in d, f'missing key: {k}'
assert d['findings'][0]['severity'] == 'minor'
assert d['findings'][0]['confidence'] == 'Confirmed'
print('OK')
"
  [ "$status" -eq 0 ]
  [ "$output" = "OK" ]
}

@test "write_json_report is valid JSON even with zero results" {
  write_json_report "$TMPDIR_TEST/report.json"
  run python3 -c "import json; json.load(open('$TMPDIR_TEST/report.json')); print('OK')"
  [ "$status" -eq 0 ]
  [ "$output" = "OK" ]
}

# ---------------------------------------------------------------------------
# build_html_report - end-to-end, offline, against synthetic data
# ---------------------------------------------------------------------------
@test "build_html_report with completely empty results shows graceful empty states" {
  build_html_report "$TMPDIR_TEST/out"
  [ -f "$TMPDIR_TEST/out/report.html" ]
  [ -f "$TMPDIR_TEST/out/assets/style.css" ]
  [ -f "$TMPDIR_TEST/out/raw/report.json" ]
  [ -f "$TMPDIR_TEST/out/raw/report.txt" ]
  run cat "$TMPDIR_TEST/out/report.html"
  [[ "$output" == *"No subdomains were discovered in this run."* ]]
  [[ "$output" == *"No issues flagged by automated checks."* ]]
}

@test "build_html_report Endpoints section shows the disabled empty-state when --endpoints was not used" {
  build_html_report "$TMPDIR_TEST/out"
  run cat "$TMPDIR_TEST/out/report.html"
  [[ "$output" == *"Endpoint/URL discovery was not enabled for this run"* ]]
}

@test "build_html_report renders discovered endpoints as a table when --endpoints was used" {
  ENDPOINTS_ENABLED=1
  SCAN_ENDPOINTS=(
    "https://a.example.com/robots.txt|metadata|robots|200"
    "https://a.example.com/admin|administrative|robots|404"
  )
  build_html_report "$TMPDIR_TEST/out"
  run cat "$TMPDIR_TEST/out/report.html"
  [[ "$output" == *"https://a.example.com/robots.txt"* ]]
  [[ "$output" == *"metadata"* ]]
  [[ "$output" == *'<span class="pill pill-good">200</span>'* ]]
  [[ "$output" == *"administrative"* ]]
}

@test "build_html_report escapes an HTML/script-injecting domain and subdomain" {
  DOMAIN='<script>alert(1)</script>.com'
  subdomains=('"><img src=x onerror=alert(1)>.example.com')
  build_html_report "$TMPDIR_TEST/out"
  run cat "$TMPDIR_TEST/out/report.html"
  [[ "$output" != *"<script>alert(1)</script>"* ]]
  [[ "$output" == *"&lt;script&gt;alert(1)&lt;/script&gt;"* ]]
  [[ "$output" != *"<img src=x onerror=alert(1)>"* ]]
}

@test "build_html_report escapes HTML injected via a finding message" {
  record_finding minor "<b>bold injected</b> header missing: X-Frame-Options" "a.example.com"
  build_html_report "$TMPDIR_TEST/out"
  run cat "$TMPDIR_TEST/out/report.html"
  [[ "$output" != *"<b>bold injected</b>"* ]]
  [[ "$output" == *"&lt;b&gt;bold injected&lt;/b&gt;"* ]]
}

@test "build_html_report handles a finding with a missing/empty confidence field gracefully" {
  FINDINGS=("minor|a.example.com|Non-standard port 8080 open|")
  build_html_report "$TMPDIR_TEST/out"
  run cat "$TMPDIR_TEST/out/report.html"
  [[ "$output" == *"Confirmed"* ]]
}

# ---------------------------------------------------------------------------
# Additional coverage: multiple hosts, large result sets, special characters,
# missing fields, all five severity tiers, and JSON/HTML consistency.
# ---------------------------------------------------------------------------
@test "build_html_report renders multiple hosts and omits non-live hosts from Live Hosts" {
  subdomains=("a.example.com" "b.example.com" "c.example.com")
  SCAN_HOSTS=(
    "a.example.com|93.184.216.34|1|Cloudflare"
    "b.example.com|93.184.216.35|1|Unknown"
    "c.example.com|unknown|0|Unknown"
  )
  SCAN_PORTS=("a.example.com|443" "b.example.com|22")
  build_html_report "$TMPDIR_TEST/out"
  run cat "$TMPDIR_TEST/out/report.html"
  [[ "$output" == *"a.example.com"* ]]
  [[ "$output" == *"b.example.com"* ]]
  [[ "$output" == *"c.example.com"* ]]
  [[ "$output" == *"Cloudflare"* ]]
  # c.example.com never went live, so it must never get a Live Hosts row.
  [[ "$output" != *'<td><code>c.example.com</code></td><td>unknown</td><td>Unknown</td>'* ]]
}

@test "build_html_report handles a large result set (300 subdomains, 50 findings) without error" {
  local i
  subdomains=()
  for (( i=0; i<300; i++ )); do subdomains+=("host$i.example.com"); done
  for (( i=0; i<50; i++ )); do
    SCAN_HOSTS+=("host$i.example.com|10.0.0.$((i % 250))|1|Unknown")
    SCAN_PORTS+=("host$i.example.com|8080")
    record_finding minor "Non-standard port 8080 open" "host$i.example.com"
  done
  build_html_report "$TMPDIR_TEST/out"
  [ -f "$TMPDIR_TEST/out/report.html" ]
  run grep -c "host0.example.com" "$TMPDIR_TEST/out/report.html"
  [ "$status" -eq 0 ]
  run grep -c "host299.example.com" "$TMPDIR_TEST/out/report.html"
  [ "$status" -eq 0 ]
}

@test "build_html_report shows distinct counts across all five severity tiers" {
  FINDINGS=(
    "critical|a.example.com|Sensitive service port 3306 open (possible database/datastore exposure)|Confirmed"
    "major|a.example.com|Missing security header: Strict-Transport-Security|Confirmed"
    "minor|a.example.com|Non-standard port 8080 open|Confirmed"
    "low|a.example.com|Old TLS protocol version supported|Confirmed"
    "info|a.example.com|Server banner discloses software version|Confirmed"
  )
  build_html_report "$TMPDIR_TEST/out"
  run cat "$TMPDIR_TEST/out/report.html"
  [[ "$output" == *'<span class="sev-count">1</span><span class="sev-label">Critical</span>'* ]]
  [[ "$output" == *'<span class="sev-count">1</span><span class="sev-label">High</span>'* ]]
  [[ "$output" == *'<span class="sev-count">1</span><span class="sev-label">Medium</span>'* ]]
  [[ "$output" == *'<span class="sev-count">1</span><span class="sev-label">Low</span>'* ]]
  [[ "$output" == *'<span class="sev-count">1</span><span class="sev-label">Informational</span>'* ]]
}

@test "build_html_report escapes unicode, quotes and ampersands in a finding message" {
  record_finding minor 'Header value contains <danger> "quoted" & unescaped '"'"'apostrophe'"'"' cafe-\xc3\xa9' "a.example.com"
  build_html_report "$TMPDIR_TEST/out"
  run cat "$TMPDIR_TEST/out/report.html"
  [[ "$output" != *"<danger>"* ]]
  [[ "$output" == *"&lt;danger&gt;"* ]]
  [[ "$output" == *"&quot;quoted&quot;"* ]]
  [[ "$output" == *"&amp; unescaped"* ]]
  [[ "$output" == *"&#39;apostrophe&#39;"* ]]
}

@test "build_html_report falls back to safe defaults when SCAN_HOSTS ip/tech fields are empty" {
  SCAN_HOSTS=("a.example.com||1|")
  build_html_report "$TMPDIR_TEST/out"
  run cat "$TMPDIR_TEST/out/report.html"
  [[ "$output" == *"a.example.com"* ]]
  [[ "$output" == *">unknown<"* ]]
  [[ "$output" == *">Unknown<"* ]]
}

@test "build_html_report handles a FINDINGS entry with an empty severity field gracefully" {
  FINDINGS=("|host-only.example.com|Unclassified observation|")
  build_html_report "$TMPDIR_TEST/out"
  run cat "$TMPDIR_TEST/out/report.html"
  [[ "$output" == *"Informational"* ]]
  [[ "$output" == *"host-only.example.com"* ]]
}

@test "report.json and report.html agree on subdomain and findings counts (JSON/HTML consistency)" {
  subdomains=("a.example.com" "b.example.com" "c.example.com")
  record_finding critical "Sensitive service port 3306 open (possible database/datastore exposure)" "a.example.com"
  record_finding major "Missing security header: Strict-Transport-Security" "b.example.com"
  build_html_report "$TMPDIR_TEST/out"
  run python3 -c "
import json
d = json.load(open('$TMPDIR_TEST/out/raw/report.json'))
print(len(d['subdomains']), len(d['findings']))
"
  [ "$status" -eq 0 ]
  [ "$output" = "3 2" ]
  run cat "$TMPDIR_TEST/out/report.html"
  [[ "$output" == *'<div class="card-value">3</div><div class="card-label">Hosts Found</div>'* ]]
  [[ "$output" == *'<div class="card-value">2</div><div class="card-label">Findings</div>'* ]]
}
