# Changelog
All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/), versioning is semver.

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
