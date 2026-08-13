# Changelog
All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/), versioning is semver.

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
