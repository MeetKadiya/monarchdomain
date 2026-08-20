# Changelog
All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/), versioning is semver.

## [Unreleased]

_No unreleased changes yet._

## [1.3.0] - 2026-08-17

### Added
- **HTTP URL & Endpoint Discovery (`--endpoints`).** After a host is confirmed live,
  MonarchDomain can discover publicly-accessible URLs/endpoints on it using only safe,
  non-destructive, GET-only techniques - never form submission, authentication, credential
  brute-forcing, or destructive requests, and no wordlist-based path brute-forcing.
  - Sources: `robots.txt` (its `Sitemap:` entries and `Disallow`/`Allow` paths),
    `sitemap.xml` (including recursive, depth-capped sitemap-index support), the homepage's
    HTML `<a href>`/`<script src>`/`<form action>` references, JavaScript path/URL literals
    pulled from any same-run `.js` file, and a small fixed list of common well-known/API-doc
    paths (`/robots.txt`, `/sitemap.xml`, `/security.txt`, `/.well-known/security.txt`,
    `/openapi.json`, `/swagger.json`, `/swagger/`, `/graphql`).
  - URLs are normalized (scheme/host lowercased, default ports and fragments stripped,
    trailing slashes collapsed) and deduplicated before being requested.
  - Every discovered URL is checked against `--scope` before it is ever requested - the same
    fail-closed scope boundary used everywhere else in the tool (Feature 1). Without
    `--scope`, everything reachable from the target is fair game, matching the tool's
    existing default-open behavior when no scope file is given.
  - Conservative rate limiting: configurable per-request timeout, bounded retries with
    429-aware backoff (reusing the same pattern as the existing `curl_fetch`), and a
    per-host request cap (`--endpoints-max`, default 60) so discovery can't run away.
  - Endpoints are categorized (informationally only, never as a "finding") into api,
    authentication, documentation, static, administrative, metadata, or other, based on
    path heuristics. A sensitive-looking path is never treated as evidence of a
    vulnerability on its own.
  - New CLI flags: `--endpoints` (opt-in; issues extra requests against the target, so it
    stays off by default), `--no-endpoints`, `--endpoints-max N`.
  - Text output gains an `[ENDPOINTS]` section; JSON output gains `"endpoints_enabled"` and
    an `"endpoints": [{"url", "type", "source", "status_code"}, ...]` array. The HTML
    report's previously-empty Endpoints section (Feature 2) now renders real data when
    `--endpoints` was used.
  - New module `lib/endpoints.sh`, sourced by `monarchdomain.sh`, following the same
    architecture as `lib/html_report.sh`: pure, network-free parsers (`url_normalize`,
    `url_join`, `endpoint_categorize`, `robots_extract_*`, `sitemap_*`, `html_extract_links`,
    `js_extract_paths`) feeding a single scope-checked/rate-limited/deduped network
    chokepoint (`endpoints_maybe_probe`) that populates the new `SCAN_ENDPOINTS` array.
- `tests/endpoints_test.sh` - 40-case bats suite: pure-function coverage for URL
  normalization/joining, endpoint categorization, and the robots.txt/sitemap/HTML/JS
  parsers (including malformed input), plus integration tests against a local fixture HTTP
  server (`tests/fixtures/endpoints/`, 127.0.0.1-only) covering deduplication, out-of-scope
  rejection, the `--endpoints-max` cap, redirect-following, sitemap-index recursion, timeout
  handling against a non-routable address, and a regression guard that no wordlist-based
  brute forcing occurs.
- `endpoints-tests` CI job (`.github/workflows/ci.yml`) running `tests/endpoints_test.sh`
  alongside the existing `scope-tests` and `html-report-tests` jobs.

### Changed
- **HTML report visual redesign.** Reworked `lib/html_report.sh`'s bundled `assets/style.css`
  for a more colorful, higher-contrast dashboard so findings and metrics are easier to scan
  at a glance: gradient header/title, glowing color-coded severity badges and section markers
  (accent dot per section: Scope=purple, Live Hosts=green, Ports=orange, Findings=red, etc.),
  per-metric colored summary cards (Hosts=blue, Live=green, Ports=orange, Technologies=purple,
  Findings=red), filled severity/status pill badges, zebra-safe hover rows, and a chip-style
  header metadata bar. Purely presentational - no changes to `html_escape`, data model, JSON
  output, or any test-asserted markup structure (summary-card and severity-badge inner markup
  kept byte-identical to what `tests/html_report_test.sh` checks for). Still zero external
  assets/CDN calls and no `<script>` tags - fully offline.

Verified: `bats tests/scope_test.sh tests/html_report_test.sh tests/endpoints_test.sh`
(93/93 passing) and `shellcheck --severity warning` (clean).

## [1.2.0] - 2026-08-14

### Added
- **Professional HTML Security Reporting (`--html-report`).** Generates an offline,
  self-contained HTML reconnaissance dashboard (`report.html` + `assets/style.css`) from
  the exact same normalized scan data already used for the text/JSON reports - no scanning
  logic is duplicated.
  - `--report-dir DIR` - override the output location (default:
    `<results_dir>/monarch-report/`).
  - Dashboard includes: target, generation timestamp, scan duration, scope status, summary
    cards (Hosts Found / Live Hosts / Open Ports / Technologies / Findings), and a 5-tier
    severity breakdown (Critical/High/Medium/Low/Informational).
  - Dedicated sections: Executive Summary, Scope, Discovered Assets, Live Hosts, DNS
    Intelligence, Open Ports, Technologies, TLS, Security Headers, Endpoints, Findings, and
    Raw Data (links to `raw/report.json` and `raw/report.txt`, copies of the standard
    outputs, written alongside the HTML report).
  - Each finding card shows title, severity, confidence, affected asset, description,
    evidence, and a remediation recommendation. Wording never over-claims: unconfirmed
    observations (e.g. an unparsable TLS handshake) are labeled "Potential misconfiguration"
    rather than asserted as vulnerabilities.
  - Every piece of scan-derived text (domains, hosts, header names, finding messages) is
    passed through `html_escape` before being written into the report - HTML/script
    injection via a malicious domain, header, or finding is neutralized, not just quoted.
  - No external CDN assets - the report (including its stylesheet) works fully offline.
  - Does not alter, remove, or duplicate the existing text/JSON output formats or any
    existing CLI flag.
  - New module `lib/html_report.sh`, sourced by `monarchdomain.sh`; new architecture:
    `scanners -> normalized result arrays -> write_text_report / write_json_report /
    build_html_report`.
- `tests/html_report_test.sh` - bats test suite covering HTML-escaping (script tags,
  quotes, ampersands, unicode), empty results, large result sets (300 subdomains / 50
  findings), multiple hosts (live and non-live), all five severity tiers, missing/empty
  fields, and JSON/HTML consistency (subdomain and finding counts match between
  `report.json` and `report.html`).
- `html-report-tests` CI job (`.github/workflows/ci.yml`) running `tests/html_report_test.sh`
  alongside the existing `scope-tests` job.

## [1.1.0] - 2026-08-13

### Added
- **Authorized Scope Enforcement.** `--scope FILE` is now a real allow-list boundary instead
  of an exact-line match: it supports bare domains (which also cover their subdomains),
  explicit `*.wildcard` entries, and IPv4/IPv6 literals, all matched with dot-boundary logic
  so a lookalike like `example.com.evil.com` can never pass a scope of `example.com`.
  - Enforced *before* DNS brute-force resolution (candidates are filtered before any `dig`
    call is issued), wildcard-DNS checks, live-host checks, port scanning, and vulnerability
    scanning - not just applied to the final report.
  - The primary `-d` target itself is checked against scope; if it's out of scope the run
    refuses to start (`[SCOPE] BLOCKED: ...`).
  - Discovered-but-unauthorized assets are dropped with `[SCOPE] OUT OF SCOPE — ignored: ...`
    and the scan continues against everything that remains in scope.
  - Inputs are normalized (lowercase, scheme/path/port/trailing-dot stripped) before
    comparison; anything that fails to normalize cleanly (malformed hostnames, raw
    Unicode/IDN homograph labels, ambiguous IPv4 octets) is treated as out of scope - scope
    enforcement fails closed, never open.
  - `--strict-scope` - new flag requiring `--scope` to be given and to resolve to at least
    one valid entry; refuses to run otherwise. Intended for CI/unattended use.
  - Scope statistics (`in_scope` / `out_of_scope` / `blocked_operations`) are now reported in
    the console summary, the text report, and the JSON report (`"scope": {...}`).
- `tests/scope_test.sh` - bats test suite covering exact/subdomain/wildcard/IP matching,
  case and trailing-dot normalization, malformed and IDN input, empty and missing scope
  files, and duplicate-entry de-duplication.

### Changed
- `monarchdomain.sh` now guards its `main "$@"` entry point so the script can be sourced
  (e.g. by the bats test suite) without triggering a scan.

## [1.0.0] - 2026-07-08
First public release.

### Added
- Multi-source subdomain enumeration: crt.sh, Wayback Machine, OTX, RapidDNS, plus DNS brute force.
- Wildcard-DNS detection and live-host filtering.
- Recon vulnerability scan: missing security headers, open ports, SSL certificate expiry, basic WAF/CDN detection.
- Stealth modes (normal/high/paranoid) with randomized user agents and delays.
- `--resume` - checkpoint completed enumeration sources + partial subdomain list so an
  interrupted scan can continue instead of restarting from zero.
- `--diff` - compare this run's subdomains against the most recent previous run for the
  same domain; writes `diff.txt` with new/removed hosts.
- `--ports LIST` - custom port spec for the vulnerability-scan stage (comma list + ranges).
- `--use-httpx` - optional integration with ProjectDiscovery's `httpx` for faster/richer
  live-host detection; falls back to curl-based checks if not installed.
- HTTP 429-specific backoff in the shared fetch wrapper.
- Scope include/exclude lists, config file support (`~/.monarchdomainrc`).
- Text and JSON output formats.
