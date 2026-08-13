# 👑 MonarchDomain - Subdomain Finder and Vulnerability Scanner

**Author:** MeetKadiya 
**Version:** 1.1.0
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
- 📄 Exportable scan results (text or JSON, including scope statistics)

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
6. **Report Generation**
   - Saves output if `-o` option used, including scope statistics

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

=== Scope Summary ===
  In scope:           45
  Out of scope:       6
  Blocked operations: 2
```

---

## ⚠️ Disclaimer
For **authorized security assessments only**.  
Running scans on unauthorized targets may be illegal.
