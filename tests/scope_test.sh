#!/usr/bin/env bats
#
# Scope enforcement tests for MonarchDomain (Feature 1 - Authorized Scope
# Enforcement). Run with: bats tests/scope_test.sh
#
# These tests source monarchdomain.sh directly (main() is guarded so
# sourcing does not execute a scan) and exercise the scope functions
# in isolation - no network access required.
#
# Most test bodies below set MonarchDomain's globals (SCOPE_FILE,
# STRICT_SCOPE, QUIET, ...) and then call functions defined in the
# sourced monarchdomain.sh (scope_load, apply_scope_filters, ...).
# ShellCheck can't see across that source boundary (SC1091 above is
# suppressed for the same reason), so it sometimes flags these
# assignments as unused even though monarchdomain.sh reads them.
# shellcheck disable=SC2034

setup() {
  SCRIPT_DIR="$(cd "$(dirname "${BATS_TEST_FILENAME}")/.." && pwd)"
  # shellcheck disable=SC1091
  source "$SCRIPT_DIR/monarchdomain.sh"
  TMPDIR_TEST="$(mktemp -d)"
}

teardown() {
  rm -rf "$TMPDIR_TEST"
}

write_scope() {
  printf '%s\n' "$@" > "$TMPDIR_TEST/scope.txt"
}

# ---------------------------------------------------------------------------
# 1. Exact domain
# ---------------------------------------------------------------------------
@test "exact domain: apex is in scope" {
  write_scope "example.com"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "example.com"
  [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# 2. Valid subdomain
# ---------------------------------------------------------------------------
@test "valid subdomain of a bare domain entry is in scope" {
  write_scope "example.com"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "api.example.com"
  [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# 3. Invalid sibling domain
# ---------------------------------------------------------------------------
@test "sibling domain is rejected" {
  write_scope "example.com"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "example.net"
  [ "$status" -eq 1 ]
}

@test "unrelated domain sharing a substring is rejected" {
  write_scope "example.com"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "notexample.com"
  [ "$status" -eq 1 ]
}

# ---------------------------------------------------------------------------
# 4. Evil suffix domain (classic bypass attempt)
# ---------------------------------------------------------------------------
@test "evil suffix domain example.com.evil.com is rejected" {
  write_scope "example.com"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "example.com.evil.com"
  [ "$status" -eq 1 ]
}

# ---------------------------------------------------------------------------
# 5. Wildcard
# ---------------------------------------------------------------------------
@test "wildcard entry matches descendants" {
  write_scope "*.example.com"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "api.example.com"
  [ "$status" -eq 0 ]
  run scope_in_scope "deep.sub.example.com"
  [ "$status" -eq 0 ]
}

@test "wildcard entry does NOT match the bare apex" {
  write_scope "*.example.com"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "example.com"
  [ "$status" -eq 1 ]
}

@test "wildcard entry does not match evil suffix" {
  write_scope "*.example.com"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "api.example.com.evil.com"
  [ "$status" -eq 1 ]
}

# ---------------------------------------------------------------------------
# 6. Uppercase domain
# ---------------------------------------------------------------------------
@test "uppercase target normalizes and matches lowercase scope entry" {
  write_scope "example.com"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "API.EXAMPLE.COM"
  [ "$status" -eq 0 ]
}

@test "uppercase scope entry normalizes and matches lowercase target" {
  write_scope "EXAMPLE.COM"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "api.example.com"
  [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# 7. Trailing dot
# ---------------------------------------------------------------------------
@test "trailing dot on target is stripped before comparison" {
  write_scope "example.com"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "api.example.com."
  [ "$status" -eq 0 ]
}

@test "trailing dot on scope entry is stripped before comparison" {
  write_scope "example.com."
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "api.example.com"
  [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# 8. Malformed domain
# ---------------------------------------------------------------------------
@test "malformed target (double dot) is rejected, fail closed" {
  write_scope "example.com"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "api..example.com"
  [ "$status" -eq 1 ]
}

@test "malformed scope entry is skipped at load time with a warning, not fatal" {
  write_scope "not a domain!!" "example.com"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  run scope_load
  [ "$status" -eq 0 ]
  [[ "$output" == *"malformed"* ]]
  run scope_in_scope "example.com"
  [ "$status" -eq 0 ]
}

@test "raw non-ASCII / IDN homograph target is rejected, fail closed" {
  write_scope "example.com"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope $'ex\xc3\xa4mple.com'
  [ "$status" -eq 1 ]
}

@test "punycode-encoded IDN entry is accepted (pure ASCII)" {
  write_scope "xn--exmple-cua.com"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "xn--exmple-cua.com"
  [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# 9. IPv4
# ---------------------------------------------------------------------------
@test "IPv4 exact match is in scope" {
  write_scope "203.0.113.10"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "203.0.113.10"
  [ "$status" -eq 0 ]
}

@test "IPv4 non-matching address is rejected" {
  write_scope "203.0.113.10"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "203.0.113.11"
  [ "$status" -eq 1 ]
}

@test "IPv4 with ambiguous leading-zero octet is rejected, fail closed" {
  write_scope "203.0.113.10"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "203.0.113.010"
  [ "$status" -eq 1 ]
}

# ---------------------------------------------------------------------------
# 10. IPv6
# ---------------------------------------------------------------------------
@test "IPv6 exact match is in scope" {
  write_scope "2001:db8::1"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "2001:db8::1"
  [ "$status" -eq 0 ]
}

@test "IPv6 differing compressed/expanded representations still match" {
  write_scope "2001:db8::1"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "2001:0db8:0000:0000:0000:0000:0000:0001"
  [ "$status" -eq 0 ]
}

@test "IPv6 bracketed literal with port normalizes and matches" {
  write_scope "::1"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  run scope_in_scope "[::1]:8443"
  [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# 11. Empty scope
# ---------------------------------------------------------------------------
@test "empty scope file: everything is out of scope (fail closed)" {
  : > "$TMPDIR_TEST/scope.txt"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load 2> "$TMPDIR_TEST/warnings.log"
  grep -q "no valid entries" "$TMPDIR_TEST/warnings.log"
  run scope_in_scope "example.com"
  [ "$status" -eq 1 ]
}

@test "empty scope file with --strict-scope is fatal" {
  : > "$TMPDIR_TEST/scope.txt"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  STRICT_SCOPE=1
  run scope_load
  [ "$status" -eq 1 ]
}

# ---------------------------------------------------------------------------
# 12. Missing scope file
# ---------------------------------------------------------------------------
@test "missing scope file is a fatal error" {
  SCOPE_FILE="$TMPDIR_TEST/does-not-exist.txt"
  run scope_load
  [ "$status" -eq 1 ]
  [[ "$output" == *"not found"* ]]
}

# ---------------------------------------------------------------------------
# 13. Duplicate scope entries
# ---------------------------------------------------------------------------
@test "duplicate scope entries are de-duplicated, not double counted" {
  write_scope "example.com" "example.com" "EXAMPLE.COM" "example.com."
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  [ "${#SCOPE_DOMAIN_ENTRIES[@]}" -eq 1 ]
}

@test "duplicate wildcard and bare entries are tracked as distinct scope types" {
  write_scope "example.com" "*.example.com"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  [ "${#SCOPE_DOMAIN_ENTRIES[@]}" -eq 1 ]
  [ "${#SCOPE_WILDCARD_ENTRIES[@]}" -eq 1 ]
}

# ---------------------------------------------------------------------------
# Disabled-scope baseline (regression guard: no --scope means no filtering)
# ---------------------------------------------------------------------------
@test "scope disabled (no --scope given): everything is in scope" {
  SCOPE_FILE=""
  scope_load
  run scope_in_scope "anything.at.all.example.net"
  [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# apply_scope_filters integration (array filtering + counters)
# ---------------------------------------------------------------------------
@test "apply_scope_filters keeps in-scope hosts and drops out-of-scope hosts" {
  write_scope "example.com"
  SCOPE_FILE="$TMPDIR_TEST/scope.txt"
  scope_load
  QUIET=1
  local -a hosts=("api.example.com" "evil.example.net" "www.example.com")
  apply_scope_filters hosts
  [ "${#hosts[@]}" -eq 2 ]
  [ "$SCOPE_IN_COUNT" -eq 2 ]
  [ "$SCOPE_OUT_COUNT" -eq 1 ]
}
