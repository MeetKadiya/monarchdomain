#!/usr/bin/env bats
#
# HTTP URL & Endpoint Discovery tests for MonarchDomain (Feature 3).
# Run with: bats tests/endpoints_test.sh
#
# Two kinds of tests here:
#   - Pure-function tests (url_normalize, url_join, endpoint_categorize,
#     robots_/sitemap_/html_/js_ extractors) - no network, operate on
#     fixture strings/files directly, same style as scope_test.sh.
#   - Integration tests against a local fixture HTTP server
#     (tests/fixtures/endpoints/fixture_server.py, bound to 127.0.0.1) that
#     exercise endpoints_maybe_probe / endpoints_discover_host end to end:
#     dedup, scope rejection, the ENDPOINTS_MAX cap, redirects, and
#     timeout handling against a non-routable address. No external network
#     access is required or performed.
#
# shellcheck disable=SC2034

setup() {
  SCRIPT_DIR="$(cd "$(dirname "${BATS_TEST_FILENAME}")/.." && pwd)"
  FIXTURES="$SCRIPT_DIR/tests/fixtures/endpoints"
  # shellcheck disable=SC1091
  source "$SCRIPT_DIR/monarchdomain.sh"

  TMPDIR_TEST="$(mktemp -d)"
  QUIET=1
  SCOPE_ENABLED=0
  SCOPE_BLOCKED_COUNT=0
  ENDPOINTS_ENABLED=1
  ENDPOINTS_MAX=60
  ENDPOINTS_TIMEOUT=4
  ENDPOINTS_MAX_SITEMAP_DEPTH=2
  MAX_RETRIES=1
  SCAN_ENDPOINTS=()
  declare -gA ENDPOINTS_SEEN=()
  ENDPOINTS_REQUEST_COUNT=0
}

teardown() {
  stop_fixture_server
  rm -rf "$TMPDIR_TEST"
}

# ---------------------------------------------------------------------------
# Local fixture HTTP server helpers. Copies the static fixtures into a
# scratch webroot, substituting TESTHOST for the real 127.0.0.1:PORT (and
# OUTOFSCOPEHOST for a placeholder host that is never actually resolved -
# it must be scope-blocked before MonarchDomain ever tries).
# ---------------------------------------------------------------------------
start_fixture_server() {
  WEBROOT="$TMPDIR_TEST/webroot"
  mkdir -p "$WEBROOT/.well-known"
  SERVER_PORT=$(( 20000 + (BASHPID % 10000) ))
  BASE_URL="http://127.0.0.1:${SERVER_PORT}"

  local f
  for f in robots.txt sitemap.xml sitemap_index.xml sitemap-a.xml sitemap-b.xml page.html script.js; do
    sed -e "s#TESTHOST#127.0.0.1:${SERVER_PORT}#g" \
        -e "s#OUTOFSCOPEHOST#out-of-scope.invalid#g" \
        "$FIXTURES/$f" > "$WEBROOT/$f"
  done
  cp "$WEBROOT/page.html" "$WEBROOT/index.html"
  mkdir -p "$WEBROOT/static"
  cp "$WEBROOT/script.js" "$WEBROOT/static/app.js"

  python3 "$FIXTURES/fixture_server.py" "$SERVER_PORT" "$WEBROOT" \
    > "$TMPDIR_TEST/server.log" 2>&1 &
  SERVER_PID=$!

  local i
  for i in $(seq 1 30); do
    curl -s -o /dev/null "$BASE_URL/robots.txt" && return 0
    sleep 0.1
  done
  echo "fixture server failed to start" >&2
  return 1
}

stop_fixture_server() {
  [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null
  wait "${SERVER_PID:-}" 2>/dev/null || true
}

# ===========================================================================
# url_normalize
# ===========================================================================
@test "url_normalize strips default https port and trailing slash" {
  run url_normalize "https://Example.com:443/Foo/"
  [ "$status" -eq 0 ]
  [ "$output" = "https://example.com/Foo" ]
}

@test "url_normalize strips default http port" {
  run url_normalize "http://example.com:80/bar/"
  [ "$status" -eq 0 ]
  [ "$output" = "http://example.com/bar" ]
}

@test "url_normalize strips fragment but keeps query" {
  run url_normalize "https://example.com/a/b/?x=1#frag"
  [ "$status" -eq 0 ]
  [ "$output" = "https://example.com/a/b?x=1" ]
}

@test "url_normalize keeps a non-default port" {
  run url_normalize "https://example.com:8443/x"
  [ "$status" -eq 0 ]
  [ "$output" = "https://example.com:8443/x" ]
}

@test "url_normalize rejects a non-http(s) scheme, fail closed" {
  run url_normalize "ftp://example.com/x"
  [ "$status" -eq 1 ]
}

@test "url_normalize rejects a malformed URL, fail closed" {
  run url_normalize "not a url"
  [ "$status" -eq 1 ]
}

@test "url_normalize is a stable dedup key across equivalent URLs" {
  a="$(url_normalize "https://Example.com:443/Foo/")"
  b="$(url_normalize "https://example.com/Foo")"
  [ "$a" = "$b" ]
}

# ===========================================================================
# url_join
# ===========================================================================
@test "url_join resolves a root-relative path" {
  run url_join "https://example.com/" "/login"
  [ "$status" -eq 0 ]
  [ "$output" = "https://example.com/login" ]
}

@test "url_join resolves a same-directory relative path" {
  run url_join "https://example.com/a/b" "c.js"
  [ "$status" -eq 0 ]
  [ "$output" = "https://example.com/a/c.js" ]
}

@test "url_join keeps an absolute URL to a different host as-is" {
  run url_join "https://example.com/" "https://other.com/z"
  [ "$status" -eq 0 ]
  [ "$output" = "https://other.com/z" ]
}

@test "url_join rejects javascript: pseudo-links" {
  run url_join "https://example.com/" "javascript:void(0)"
  [ "$status" -eq 1 ]
}

@test "url_join rejects mailto: links" {
  run url_join "https://example.com/" "mailto:a@b.com"
  [ "$status" -eq 1 ]
}

# ===========================================================================
# endpoint_categorize
# ===========================================================================
@test "endpoint_categorize: robots.txt is metadata" {
  run endpoint_categorize "https://x.com/robots.txt"
  [ "$output" = "metadata" ]
}

@test "endpoint_categorize: api path is api" {
  run endpoint_categorize "https://x.com/api/v1/users"
  [ "$output" = "api" ]
}

@test "endpoint_categorize: graphql is api" {
  run endpoint_categorize "https://x.com/graphql"
  [ "$output" = "api" ]
}

@test "endpoint_categorize: login is authentication" {
  run endpoint_categorize "https://x.com/login"
  [ "$output" = "authentication" ]
}

@test "endpoint_categorize: admin path is administrative" {
  run endpoint_categorize "https://x.com/admin/panel"
  [ "$output" = "administrative" ]
}

@test "endpoint_categorize: .js under static/ is static" {
  run endpoint_categorize "https://x.com/static/app.js"
  [ "$output" = "static" ]
}

@test "endpoint_categorize: swagger.json is documentation, not just metadata" {
  run endpoint_categorize "https://x.com/swagger.json"
  [ "$output" = "documentation" ]
}

@test "endpoint_categorize: unrecognized path is other (never fabricated as a finding)" {
  run endpoint_categorize "https://x.com/about"
  [ "$output" = "other" ]
}

# ===========================================================================
# robots.txt parsing
# ===========================================================================
@test "robots_extract_sitemaps pulls Sitemap: entries" {
  content="$(sed 's#TESTHOST#example.com#g' "$FIXTURES/robots.txt")"
  run robots_extract_sitemaps "$content"
  [ "$status" -eq 0 ]
  [[ "$output" == *"http://example.com/sitemap.xml"* ]]
  [[ "$output" == *"http://example.com/sitemap-news.xml"* ]]
}

@test "robots_extract_paths pulls Disallow/Allow paths, not the Sitemap line" {
  content="$(sed 's#TESTHOST#example.com#g' "$FIXTURES/robots.txt")"
  run robots_extract_paths "$content"
  [[ "$output" == *"/admin/"* ]]
  [[ "$output" == *"/private"* ]]
  [[ "$output" == *"/public/"* ]]
  [[ "$output" != *"sitemap"* ]]
}

@test "robots_extract_sitemaps on malformed/empty content returns nothing, does not crash" {
  run robots_extract_sitemaps "this is not a robots.txt file at all"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

# ===========================================================================
# sitemap.xml / sitemap index parsing
# ===========================================================================
@test "sitemap_is_index is false for a regular urlset" {
  content="$(cat "$FIXTURES/sitemap.xml")"
  run sitemap_is_index "$content"
  [ "$status" -eq 1 ]
}

@test "sitemap_is_index is true for a sitemapindex" {
  content="$(cat "$FIXTURES/sitemap_index.xml")"
  run sitemap_is_index "$content"
  [ "$status" -eq 0 ]
}

@test "sitemap_extract_locs pulls every <loc> from a urlset" {
  content="$(sed 's#TESTHOST#example.com#g; s#OUTOFSCOPEHOST#evil.example#g' "$FIXTURES/sitemap.xml")"
  run sitemap_extract_locs "$content"
  [[ "$output" == *"http://example.com/"* ]]
  [[ "$output" == *"http://example.com/about"* ]]
  [[ "$output" == *"http://example.com/api/v1"* ]]
}

@test "sitemap_extract_locs on malformed XML returns nothing, does not crash" {
  run sitemap_extract_locs "<not><valid>xml at all"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

# ===========================================================================
# HTML link extraction
# ===========================================================================
@test "html_extract_links pulls href, src and action, skips javascript:/mailto:/fragment" {
  content="$(sed 's#TESTHOST#example.com#g' "$FIXTURES/page.html")"
  run html_extract_links "$content"
  [[ "$output" == *"/login"* ]]
  [[ "$output" == *"/api/v1/users"* ]]
  [[ "$output" == *"https://example.com/docs"* ]]
  [[ "$output" == *"/static/app.js"* ]]
  [[ "$output" == *"/search"* ]]
  [[ "$output" != *"javascript:"* ]]
  [[ "$output" != *"mailto:"* ]]
  [[ "$output" != *"#section"* ]]
}

@test "html_extract_links preserves duplicate links as-is (dedup happens at probe time)" {
  content="$(sed 's#TESTHOST#example.com#g' "$FIXTURES/page.html")"
  run html_extract_links "$content"
  count=$(printf '%s\n' "$output" | grep -c '^/login$')
  [ "$count" -eq 2 ]
}

# ===========================================================================
# JS path/URL reference extraction
# ===========================================================================
@test "js_extract_paths pulls root-relative and absolute URL references" {
  content="$(sed 's#TESTHOST#example.com#g' "$FIXTURES/script.js")"
  run js_extract_paths "$content"
  [[ "$output" == *"/api/v2/orders"* ]]
  [[ "$output" == *"https://example.com/graphql"* ]]
  [[ "$output" == *"/login"* ]]
  [[ "$output" != *"just some text"* ]]
}

# ===========================================================================
# Integration: endpoints_maybe_probe / endpoints_discover_host against a
# real local fixture server (127.0.0.1 only - no external network).
# ===========================================================================
@test "endpoints_maybe_probe records a real GET with its status code" {
  start_fixture_server
  endpoints_maybe_probe "$BASE_URL/robots.txt" "robots"
  [ "${#SCAN_ENDPOINTS[@]}" -eq 1 ]
  IFS='|' read -r url type source status <<< "${SCAN_ENDPOINTS[0]}"
  [ "$url" = "$BASE_URL/robots.txt" ]
  [ "$type" = "metadata" ]
  [ "$status" = "200" ]
}

@test "endpoints_maybe_probe dedupes equivalent URLs, only one request/record" {
  start_fixture_server
  endpoints_maybe_probe "$BASE_URL/robots.txt" "robots"
  endpoints_maybe_probe "$BASE_URL/robots.txt" "robots"       # exact repeat
  endpoints_maybe_probe "$BASE_URL/robots.txt/" "robots"      # trailing-slash variant normalizes to the same URL
  local count=0 e
  for e in "${SCAN_ENDPOINTS[@]}"; do
    [[ "$e" == "$BASE_URL/robots.txt|"* ]] && count=$((count + 1))
  done
  [ "$count" -eq 1 ]
}

@test "endpoints_maybe_probe rejects a malformed URL without recording or requesting anything" {
  run endpoints_maybe_probe "not-a-url-at-all" "test"
  [ "${#SCAN_ENDPOINTS[@]}" -eq 0 ]
}

@test "endpoints_maybe_probe never requests an out-of-scope URL (scope-checked before fetch)" {
  start_fixture_server
  SCOPE_ENABLED=1
  scope_in_scope() { [[ "$1" == "127.0.0.1" ]]; }
  endpoints_maybe_probe "http://out-of-scope.invalid/steal" "test"
  [ "$SCOPE_BLOCKED_COUNT" -eq 1 ]
  [ "${#SCAN_ENDPOINTS[@]}" -eq 0 ]
}

@test "endpoints_maybe_probe respects ENDPOINTS_MAX and stops requesting beyond the cap" {
  start_fixture_server
  ENDPOINTS_MAX=2
  endpoints_maybe_probe "$BASE_URL/robots.txt" "test"
  endpoints_maybe_probe "$BASE_URL/sitemap.xml" "test"
  endpoints_maybe_probe "$BASE_URL/page.html" "test"
  endpoints_maybe_probe "$BASE_URL/script.js" "test"
  [ "${#SCAN_ENDPOINTS[@]}" -eq 2 ]
}

@test "endpoints_maybe_probe follows a redirect and records the final status code" {
  start_fixture_server
  endpoints_maybe_probe "$BASE_URL/redirect-me" "test"
  [ "${#SCAN_ENDPOINTS[@]}" -eq 1 ]
  IFS='|' read -r url type source status <<< "${SCAN_ENDPOINTS[0]}"
  [ "$status" = "200" ]
}

@test "endpoints_maybe_probe against an unroutable address times out cleanly (status 0, no hang)" {
  ENDPOINTS_TIMEOUT=2
  MAX_RETRIES=1
  start_time=$(date +%s)
  endpoints_maybe_probe "http://192.0.2.1/unreachable" "test"
  end_time=$(date +%s)
  elapsed=$(( end_time - start_time ))
  [ "$elapsed" -le 10 ]
  [ "${#SCAN_ENDPOINTS[@]}" -eq 1 ]
  IFS='|' read -r url type source status <<< "${SCAN_ENDPOINTS[0]}"
  [ "$status" = "0" ]
}

@test "endpoints_process_sitemap recurses into a sitemap index and records leaf URLs" {
  start_fixture_server
  endpoints_process_sitemap "$BASE_URL/sitemap_index.xml" "sitemap" 0
  local found_a=0 found_b=0 e url
  for e in "${SCAN_ENDPOINTS[@]}"; do
    IFS='|' read -r url _ <<< "$e"
    [[ "$url" == "$BASE_URL/from-index-a" ]] && found_a=1
    [[ "$url" == "$BASE_URL/from-index-b" ]] && found_b=1
  done
  [ "$found_a" -eq 1 ]
  [ "$found_b" -eq 1 ]
}

@test "endpoints_discover_host performs full discovery: html, js, robots, sitemap, wellknown" {
  start_fixture_server
  endpoints_discover_host "127.0.0.1:${SERVER_PORT}" "http"
  local sources="" e src
  for e in "${SCAN_ENDPOINTS[@]}"; do
    IFS='|' read -r _ _ src _ <<< "$e"
    sources="$sources $src"
  done
  [[ "$sources" == *" html"* ]]
  [[ "$sources" == *" javascript"* ]]
  [[ "$sources" == *" robots"* ]]
  [[ "$sources" == *" sitemap"* ]]
  [[ "$sources" == *" wellknown"* ]]
}

@test "endpoints_discover_host does not perform wordlist-based brute forcing (only fixed common paths + discovered links)" {
  start_fixture_server
  endpoints_discover_host "127.0.0.1:${SERVER_PORT}" "http"
  # A path that exists on disk but is never referenced by any safe source
  # (robots/sitemap/html/js/common-paths) must never be discovered.
  local e url
  for e in "${SCAN_ENDPOINTS[@]}"; do
    IFS='|' read -r url _ <<< "$e"
    [[ "$url" == *"/never-linked-brute-force-target"* ]] && false
  done
}
