# 👑 MonarchDomain - Subdomain Finder and Vulnerability Scanner

**Author:** MeetKadiya 
**Version:** 1.0.0
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
- 🕵️ Stealth mode for slower, randomized requests (with 429 rate-limit-aware backoff)
- 🔁 `--resume` — pick up an interrupted scan instead of starting over
- 🆚 `--diff` — compare against the previous run and flag new/removed subdomains
- ⚡ `--use-httpx` — optional ProjectDiscovery httpx integration for faster/richer live checks
- 🎯 `--ports` — custom port list/ranges for the vulnerability scan stage
- 📄 Exportable scan results (text or JSON)

---

## 🧩 Dependencies

Requires:
```
curl, dig, openssl, nc
```

---

## 📦 Installation

### Option A: Quick install (recommended)

The repo ships with an `install.sh` that handles everything below in one step.

```bash
git clone https://github.com/MeetKadiya/MonarchDomain.git
cd MonarchDomain
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
   git clone https://github.com/MeetKadiya/MonarchDomain.git
   cd MonarchDomain
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
| `--resume` | Resume the last interrupted run for this domain |
| `--diff` | Diff this run's subdomains against the previous run |
| `--ports LIST` | Custom ports, e.g. `80,443,8000-8010` |
| `--use-httpx` | Use `httpx` for live-host checks if installed |
| `-o <file>` | Save output to file |
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
```

---

## 🧩 Working Flow

1. **Dependency Verification**
2. **Subdomain Enumeration**
   - Gathers domains from crt.sh and DNS brute force
3. **Filtering**
   - Optional filters for live or wildcard subdomains
4. **Vulnerability Scanning**
   - Checks ports, SSL info, and security headers
5. **Report Generation**
   - Saves output if `-o` option used

---

## 📊 Output Example

```
[*] Querying crt.sh for subdomains...
[+] Found 45 unique subdomains
[*] Checking HTTP security headers...
[-] Missing Strict-Transport-Security header
[*] Checking common open ports...
[+] Port 80 open
[+] Port 443 open
```

---

## ⚠️ Disclaimer
For **authorized security assessments only**.  
Running scans on unauthorized targets may be illegal.
