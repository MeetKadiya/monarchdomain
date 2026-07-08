# 👑 MonarchDomain - Subdomain Finder and Vulnerability Scanner

**Author:** Meet_Kadiya 
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
