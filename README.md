# 👑 MonarchDomain - Subdomain Finder and Vulnerability Scanner

**Author:** MeetKadiya 
**Version:** 1.3.0
**File:** `monarchdomain.sh`  
**Purpose:** Discover subdomains and perform quick vulnerability assessments — ideal for bug bounty or recon workflows.

---

## ⚙️ Overview

MonarchDomain is a dual-purpose Bash tool that performs **subdomain enumeration** and **vulnerability scanning**.  
It uses multiple sources like `crt.sh` (Certificate Transparency logs) and DNS brute forcing to identify subdomains.  
Additionally, it runs HTTP header checks, SSL validation, and port scanning for vulnerabilities.

---

## 🧠 Features

- 🌐 Subdomain discovery via:
  - Certificate Transparency (`crt.sh`)
  - DNS brute force (common wordlist)
- 🧩 Wildcard DNS detection
- 🧭 Live subdomain filtering (HTTP/HTTPS)
- 🔒 Vulnerability scanning with:
  - Security header checks
  - SSL certificate details
  - Open port detection (80, 443, 21, 22)
- 🛡️ **Authorized Scope Enforcement** — a `--scope` allow-list that's checked before every DNS
  resolution, HTTP request, port scan, or vuln check, so the tool can never touch an
  asset you weren't authorized to test (see below)
- 🕵️ Stealth mode for slower, randomized requests (with 429 rate-limit-aware backoff)
- 🔁 `--resume` — pick up an interrupted scan instead of starting over
- 🆚 `--diff` — compare against the previous run and flag new/removed subdomains
- ⚡ `--use-httpx` — optional ProjectDiscovery httpx integration for faster/richer live checks
- 🎯 `--ports` — custom port list/ranges for the vulnerability scan stage
- 🔗 `--endpoints` — safe, GET-only HTTP URL/endpoint discovery on live hosts: robots.txt,
  sitemap.xml (incl. sitemap indexes), HTML links/forms/scripts, JS path references, and a
  small fixed list of common API-doc/well-known paths. Every discovered URL is scope-checked
  before it's requested; no wordlist-based brute forcing (see [Endpoint Discovery](#-endpoint-discovery) below)
- 📄 Exportable scan results (text or JSON, including scope statistics)
- 🖥️ `--html-report` — professional, offline, self-contained HTML security dashboard built
  from the same scan data as the text/JSON output (see [HTML Report](#-html-report) below)

---

## 🧩 Dependencies

Requires:
```
curl, dig, openssl, nc
```

Optional:
```
python3   # enables fully RFC-5952-correct IPv6 scope comparisons; without it,
          # IPv6 scope matching falls back to a best-effort lowercase compare
```

---

## 📦 Installation

### Option A: Quick install (recommended)

The repo ships with an `install.sh` that handles everything below in one step.

```bash
git clone https://github.com/meet0625/MONARCHDOMAIN.git
cd MONARCHDOMAIN
chmod +x install.sh
sudo ./install.sh
```

This will:
- Install dependencies (`curl`, `dnsutils`, `openssl`, `netcat-openbsd`) via `apt-get`
- Print a hint to install `httpx-toolkit` if you don't already have `httpx` (needed for `--use-httpx`)
- Make `monarchdomain.sh` executable
- Symlink it to `/usr/local/bin/monarchdomain`, so you can run `monarchdomain -d example.com` from anywhere

> `sudo` is required so the installer can install packages and write the symlink into `/usr/local/bin`.
> Tip: create `~/.monarchdomainrc` afterward to set your own defaults (`THREADS`, `STEALTH`, `PROXY`, ...).

### Option B: Manual installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/meet0625/MONARCHDOMAIN.git
   cd MONARCHDOMAIN
   ```

2. **Install dependencies** (Kali Linux / Debian-based)
   ```bash
   sudo apt update
   sudo apt install -y curl openssl dnsutils netcat-traditional
   ```
   > `dig` comes from `dnsutils`; `nc` comes from `netcat-traditional` (or `netcat-openbsd` - either works).
   > On Kali, most of these are usually preinstalled - this step just fills in anything missing.

3. **Make the script executable**
   ```bash
   chmod +x monarchdomain.sh
   ```

4. **(Optional) Install globally** so you can run it as `monarchdomain` from anywhere
   ```bash
   sudo ln -s "$(pwd)/monarchdomain.sh" /usr/local/bin/monarchdomain
   ```

5. **(Optional) Install `httpx`** for the `--use-httpx` faster/richer live-host checks
   ```bash
   sudo apt install -y golang-go   # if Go isn't already installed
   go install github.com/projectdiscovery/httpx/cmd/httpx@latest
   export PATH=$PATH:$(go env GOPATH)/bin   # add to ~/.bashrc or ~/.zshrc to persist
   ```

6. **Verify it works**
   ```bash
   ./monarchdomain.sh -h
   ```
   You should see the usage/help output shown below.

---

## 🚀 Usage

```bash
./monarchdomain.sh -d example.com [options]
```

### Options
| Option | Description |
|:--------|:-------------|
| `-d <domain>` | Target domain (**required**) |
| `-s` | Perform **only subdomain enumeration** |
| `-v` | Perform **only vulnerability scanning** |
| `-l` | Filter **live subdomains** only |
| `-w` | Filter **wildcard subdomains** only |
| `-m` | Enable **stealth mode** |
| `-e, --exclude FILE` | Deny-list: skip any subdomain matching an entry in FILE |
| `--scope FILE` | Allow-list: only touch assets matching an entry in FILE. See [Authorized Scope](#-authorized-scope) |
| `--strict-scope` | Refuse to run without `--scope`, and refuse to run on an empty/invalid scope file |
| `--resume` | Resume the last interrupted run for this domain |
| `--diff` | Diff this run's subdomains against the previous run |
| `--ports LIST` | Custom ports, e.g. `80,443,8000-8010` |
| `--use-httpx` | Use `httpx` for live-host checks if installed |
| `-o <file>` | Save output to file |
| `-f, --format FORMAT` | `text` or `json` output |
| `--html-report` | Also generate an offline HTML security dashboard (`report.html`) alongside the text/JSON output |
| `--report-dir DIR` | Directory for the HTML report (default: `<results_dir>/monarch-report/`) |
| `--endpoints` | Discover URLs/endpoints on each live host. Safe, GET-only, non-destructive. Disabled by default. See [Endpoint Discovery](#-endpoint-discovery) |
| `--no-endpoints` | Explicitly disable endpoint discovery (overrides a `.monarchdomainrc` default of `ENDPOINTS_ENABLED=1`) |
| `--endpoints-max N` | Max endpoint URLs actively requested per host (default: 60) |
| `-h`, `--help` | Display help message |

---

## 💡 Examples

```bash
# Find all subdomains
./monarchdomain.sh -d example.com -s

# Find live subdomains stealthily
./monarchdomain.sh -d example.com -s -l -m

# Perform only vulnerability scan
./monarchdomain.sh -d example.com -v

# Full scan with report
./monarchdomain.sh -d example.com -o results.txt

# Scan restricted to a bug-bounty program's declared scope
./monarchdomain.sh -d example.com --scope scope.txt

# Same, but fail loudly instead of silently doing nothing if scope.txt is
# missing/empty - recommended for CI or unattended runs
./monarchdomain.sh -d example.com --scope scope.txt --strict-scope

# JSON report, including scope statistics
./monarchdomain.sh -d example.com --scope scope.txt -f json -o report.json

# Full scan plus an offline HTML security dashboard
./monarchdomain.sh -d example.com --html-report

# HTML report written to a custom directory
./monarchdomain.sh -d example.com --html-report --report-dir /tmp/monarch-report

# Discover URLs/endpoints on every live host (robots.txt, sitemap.xml, HTML/JS links, ...)
./monarchdomain.sh -d example.com --endpoints

# Endpoint discovery, capped at 120 requests per host, restricted to a declared scope
./monarchdomain.sh -d example.com --endpoints --endpoints-max 120 --scope scope.txt
```

---

## 🛡️ Authorized Scope

**Only scan assets you are explicitly authorized to test** — your own infrastructure, or a
target covered by a bug-bounty program's or client's written scope. Scanning anything else
may be illegal, even with tools that only perform "passive" or lightweight checks.

MonarchDomain's `--scope` option lets you point the tool at a program's declared scope and
have that boundary enforced automatically, everywhere it matters:

- **What it gates:** DNS brute-force resolution, wildcard-DNS checks, live-host checks, port
  scanning, and vulnerability scanning. Out-of-scope candidates are filtered out *before* any
  of these active operations run against them - not just excluded from the final report.
- **What it doesn't gate:** the passive OSINT queries themselves (crt.sh, Wayback Machine,
  OTX, RapidDNS) are queries against third-party data sources about the domain, not requests
  sent to the target's own infrastructure; their *results* are then filtered against scope
  before anything discovered from them is acted on.

### scope.txt format

One entry per line. Blank lines and `#` comments are ignored.

```
# Bug bounty program scope
example.com
*.example.com
api.example.com
admin.example.com
203.0.113.10
2001:db8::1
```

| Entry type | Matches |
|:-----------|:--------|
| `example.com` (bare domain) | `example.com` itself **and** any subdomain, e.g. `api.example.com` |
| `*.example.com` (wildcard) | Only subdomains, e.g. `api.example.com` — **not** the bare apex |
| `203.0.113.10` / `2001:db8::1` | That exact IP literal only |

`example.com` does **not** match `example.com.evil.com` — matching is boundary-aware, not a
plain string suffix check, so a lookalike domain that merely ends with your scope string can
never sneak through.

### Normalization & safe-by-default behavior

Before comparison, both scope entries and discovered targets are normalized: lowercased,
stripped of scheme/path/port and trailing dots, and validated as a hostname or IP literal.
Anything that fails to normalize cleanly - malformed hostnames, raw Unicode/IDN homograph
labels, ambiguous IP octets - is treated as **out of scope**. Scope enforcement always fails
closed, never open. (Pre-encode internationalized domains as their ASCII `xn--...` punycode
form in `scope.txt`.)

If the target you passed via `-d` is itself outside the given scope file, MonarchDomain
refuses to start the scan at all:

```
[SCOPE] BLOCKED: example.com
[Fatal] Target domain 'example.com' is not covered by scope file 'scope.txt'. Refusing to scan.
```

Discovered-but-unauthorized assets are dropped with:

```
[SCOPE] OUT OF SCOPE — ignored: shadow-it.example.net
```

and the scan continues normally against everything that *is* in scope.

### Scope statistics

Every run with `--scope` reports scope counters in the console summary, the text report, and
the JSON report:

```
=== Scope Summary ===
  In scope:           42
  Out of scope:       17
  Blocked operations: 9
```

```json
{
  "scope": {
    "enabled": true,
    "scope_file": "scope.txt",
    "in_scope": 42,
    "out_of_scope": 17,
    "blocked_operations": 9
  }
}
```

`--strict-scope` additionally requires that `--scope` be given at all, and that the scope
file resolve to at least one valid entry - use it in CI/unattended contexts where you'd
rather the run fail loudly than silently scan nothing (or, without `--scope` at all, scan
without any authorization boundary).

---

## 🖥️ HTML Report

`--html-report` turns a normal scan into a readable, professional security-reconnaissance
dashboard, without changing or removing the existing text/JSON output. It's built entirely
from the same normalized scan-result arrays the text/JSON writers already use — it does not
re-run or duplicate any scanning logic:

```
scanners -> normalized result arrays -> write_text_report / write_json_report / build_html_report
```

```bash
./monarchdomain.sh -d example.com --html-report
./monarchdomain.sh -d example.com --html-report --report-dir /tmp/monarch-report
```

### Generated files

By default the report is written under `<results_dir>/monarch-report/` (or the directory
given to `--report-dir`):

```
monarch-report/
├── report.html          # the dashboard itself — open this in any browser, no server needed
├── assets/
│   └── style.css        # bundled locally; no CDN/network calls, works fully offline
└── raw/
    ├── report.json       # identical to -f json output
    └── report.txt        # identical to the default text output
```

### What's in the dashboard

- **Header** — target domain, generation timestamp, scan duration, tool version, and scope
  status (enabled/disabled + in-scope/out-of-scope counts).
- **Executive Summary** — five summary cards (Hosts Found, Live Hosts, Open Ports,
  Technologies, Findings) plus a severity breakdown across all five tiers: **Critical / High
  / Medium / Low / Informational**.
- **Section-by-section detail**: Scope, Discovered Assets, Live Hosts, DNS Intelligence,
  Open Ports, Technologies, TLS, Security Headers, Endpoints (populated when `--endpoints`
  was used — see [Endpoint Discovery](#-endpoint-discovery); otherwise shown as an explicit
  empty state, never fabricated), Findings, and Raw Data (links straight to
  `raw/report.json` / `raw/report.txt`).
- **Findings**, rendered as individual cards, each with: title, severity, confidence,
  affected asset, description, evidence, and a concrete remediation recommendation. Wording
  is deliberately conservative — anything the scanner couldn't fully confirm (e.g. a TLS
  handshake that returned no parsable certificate) is labeled *"Potential misconfiguration"*
  rather than asserted as a confirmed vulnerability.

### Example (what it looks like)

A dark-themed, single-page dashboard: a header bar with the target and scan metadata, a
sticky section-jump nav, five stat cards, five color-coded severity badges (red/orange/
yellow/teal/gray), clean data tables for hosts/ports/TLS/headers, and left-border-accented
finding cards colored by severity. No images are bundled — it's pure CSS.

### Security

Every piece of scan-derived text — domains, subdomains, hostnames, HTTP header names,
finding messages, TLS/WAF strings — is passed through an HTML-escaping function before being
written into `report.html`. A malicious/lookalike domain or a crafted response header can
never inject markup or script into the report. No local filesystem paths from your machine
are written into the report body.

---

## 🔗 Endpoint Discovery

`--endpoints` looks for publicly-accessible URLs on every live host discovered during the
scan, using only safe, non-destructive, **GET-only** techniques. It never submits forms,
never authenticates, never brute-forces credentials, and never performs destructive
requests. It's disabled by default because it issues additional requests against the
target beyond the base recon/vuln checks.

```bash
./monarchdomain.sh -d example.com --endpoints
./monarchdomain.sh -d example.com --endpoints --endpoints-max 120
```

### Sources

- **`robots.txt`** — its `Sitemap:` entries (followed, including sitemap indexes) and its
  `Disallow`/`Allow` paths (requested, never treated as evidence of anything sensitive on
  their own — a disallowed path is just a candidate URL, not a finding)
- **`sitemap.xml`** — including recursive, depth-capped sitemap-index support
- **HTML** — `<a href>`, `<script src>`, and `<form action>` references on the homepage
  (forms are never submitted — only their `action` URL is noted as a candidate endpoint)
- **JavaScript** — path/URL string literals pulled out of any `.js` file referenced by the
  homepage (e.g. `fetch("/api/users")`)
- **A small fixed list of common well-known/API-documentation paths:**
  `/robots.txt`, `/sitemap.xml`, `/security.txt`, `/.well-known/security.txt`,
  `/openapi.json`, `/swagger.json`, `/swagger/`, `/graphql`

**No wordlist-based directory brute forcing is performed**, by default or otherwise — only
the sources above. If wordlist-based discovery is ever added, it will be a separate,
explicitly opt-in feature.

### Normalization, deduplication & scope

Every discovered URL is normalized (scheme/host lowercased, default ports and fragments
stripped, trailing slashes collapsed) before being deduplicated and requested — the same
URL reached via two different sources (say, both `sitemap.xml` and an `<a href>`) is only
requested once.

Every discovered URL is checked against `--scope` **before** it is ever requested — the same
fail-closed boundary described in [Authorized Scope](#-authorized-scope) above. A sitemap or
robots.txt entry pointing at a different, out-of-scope host is dropped, never fetched.
Without `--scope`, everything reachable from the target is fair game, matching the tool's
existing default-open behavior.

### Rate limiting

Conservative by default: a configurable per-request timeout, bounded retries with
429-aware backoff (the same pattern the rest of the tool already uses), and a per-host
request cap (`--endpoints-max`, default 60) so a single host with a huge sitemap can't turn
into an unbounded crawl.

### Categorization

Each discovered endpoint is labeled with one of: `api`, `authentication`, `documentation`,
`static`, `administrative`, `metadata`, or `other`, based on path heuristics (e.g. `/login`
→ authentication, `/graphql` → api, `/admin/panel` → administrative). This is purely
informational grouping for the report — **a path is never treated as a vulnerability just
because it looks sensitive.** `/admin/panel` returning HTTP 200 is not, by itself, a
finding; it's just a categorized entry in the endpoints list.

### Output

Text output gains an `[ENDPOINTS]` section:

```
[ENDPOINTS]
  https://example.com/robots.txt  (metadata, via robots, HTTP 200)
  https://example.com/api/v1  (api, via sitemap, HTTP 200)
  https://example.com/login  (authentication, via html, HTTP 200)
  https://example.com/graphql  (api, via wellknown, HTTP 200)
```

JSON output gains `"endpoints_enabled"` and an `"endpoints"` array:

```json
{
  "endpoints_enabled": true,
  "endpoints": [
    {"url": "https://example.com/robots.txt", "type": "metadata", "source": "robots", "status_code": 200},
    {"url": "https://example.com/api/v1", "type": "api", "source": "sitemap", "status_code": 200},
    {"url": "https://example.com/login", "type": "authentication", "source": "html", "status_code": 200},
    {"url": "https://example.com/graphql", "type": "api", "source": "wellknown", "status_code": 200}
  ]
}
```

And if `--html-report` is also given, the dashboard's previously-empty Endpoints section
(see [HTML Report](#-html-report)) renders the same data as a table.

---

## 🧩 Working Flow

1. **Dependency Verification**
2. **Scope Loading** (if `--scope` given) - loads and normalizes the allow-list, and refuses
   to proceed if the primary target itself is out of scope
3. **Subdomain Enumeration**
   - Gathers domains from crt.sh, Wayback, OTX, RapidDNS and DNS brute force
   - Scope-filters discovered/brute-forced candidates before any active check touches them
4. **Filtering**
   - Optional filters for live or wildcard subdomains (scope-filtered set only)
5. **Vulnerability Scanning**
   - Checks ports, SSL info, and security headers (scope-filtered targets only)
   - If `--endpoints` is given, also runs safe GET-only URL/endpoint discovery on each live
     host (scope-checked per-URL) — see [Endpoint Discovery](#-endpoint-discovery)
6. **Report Generation**
   - Saves output if `-o` option used, including scope statistics
   - If `--html-report` is given, also renders the offline HTML dashboard described in
     [HTML Report](#-html-report) from the same normalized results — text/JSON output is
     unaffected

---

## 📊 Output Example

```
[*] Scope enforcement enabled: scope.txt (3 domain, 1 wildcard, 0 IP entries)
[*] Querying crt.sh for subdomains...
[SCOPE] OUT OF SCOPE — ignored: shadow-it.example.net
[+] Found 45 unique subdomains
[*] Checking HTTP security headers...
[-] Missing Strict-Transport-Security header
[*] Checking common open ports...
[+] Port 80 open
[+] Port 443 open

[ENDPOINTS]
  https://app.example.com/robots.txt  (metadata, via robots, HTTP 200)
  https://app.example.com/api/v1  (api, via sitemap, HTTP 200)

=== Scope Summary ===
  In scope:           45
  Out of scope:       6
  Blocked operations: 2
```

---

## ⚠️ Disclaimer
For **authorized security assessments only**.  
Running scans on unauthorized targets may be illegal.
