<p align="center">
  <img src="assets/s4w-logo.png" alt="S4W Logo" width="220">
</p>

# S4W

**Passive Web Security Auditor for modern web applications.**

S4W is a terminal-based passive web security assessment toolkit designed to support initial security reviews, exposure analysis, hardening checks and structured reporting for web applications.

The tool focuses on observable application behavior and publicly reachable metadata. It does not perform brute force, automatic exploitation, aggressive fuzzing, bypass attempts or destructive testing.

Use S4W only on assets you own, controlled labs or environments where you have formal authorization.

---

## Core capabilities

- Passive OSINT: DNS records, TLS information, local WHOIS lookup, robots.txt and security.txt.
- Passive recon: apparent technologies, links, scripts, assets, forms, visible endpoints and public e-mails.
- Endpoint Intelligence: prioritization of URLs and forms based on parameters, authentication patterns, CRUD operations, upload flows, APIs and sensitive indicators.
- Web hardening review: security headers, cookies, CSP, exposure indicators and security score.
- Header audit: technical review of HTTP response headers and browser-side protections.
- Subdomain profile: focused analysis using `-s` for a specific authorized subdomain.
- Structured findings: severity, confidence, evidence, impact, remediation, OWASP mapping, CWE references and JSON export.

---

## Installation on Kali Linux

```bash
sudo apt update
sudo apt install git python3 python3-pip python3-venv whois -y
git clone https://github.com/silv4code/s4w.git
cd s4w
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
s4w -help
```

---

## Installation with pipx

```bash
sudo apt install pipx -y
pipx ensurepath
pipx install git+https://github.com/silv4code/s4w.git
s4w -help
```

---

## Basic usage

Interactive mode:

```bash
s4w https://example.com
```

Non-interactive mode:

```bash
s4w https://example.com -y
```

Save JSON output:

```bash
mkdir -p reports
s4w https://example.com -y --json reports/example.json
```

Focused subdomain analysis:

```bash
s4w -s app.example.com -v
```

Subdomain analysis with JSON output:

```bash
s4w -s app.example.com -v -y --json reports/app.json
```

Increase request timeout:

```bash
s4w https://example.com -y --timeout 25
```

Cleaner terminal output:

```bash
s4w https://example.com -y --no-details --json reports/example.json
```

---

## Command-line options

| Option | Description |
|---|---|
| `s4w` | Shows a short usage guide. |
| `-h`, `--help`, `-help` | Shows help and quick examples. |
| `-y`, `--yes` | Enables non-interactive mode. |
| `-s`, `--subdomain` | Analyzes a specific authorized subdomain. |
| `-v`, `--verbose` | Shows detailed output for subdomain findings. |
| `--json` | Saves the result to a JSON file. |
| `--timeout` | Sets HTTP request timeout in seconds. |
| `--skip-whois` | Skips local WHOIS lookup. |
| `--no-details` | Reduces long terminal details. |
| `--version` | Shows the installed version. |

---

## Analysis modules

### 1. Passive OSINT

DNS records, TLS certificate information, WHOIS lookup, robots.txt and security.txt.

### 2. Passive Recon

Technologies, links, scripts, assets, forms, visible endpoints, public e-mails and inline JavaScript indicators.

### 3. Endpoint Intelligence

S4W classifies visible URLs and forms, prioritizing endpoints that receive parameters, suggest authentication, CRUD operations, upload flows, APIs, sensitive data flows or deployment artifacts.

### 4. Web Hardening Review

Security headers, cookie flags, CSP, exposure indicators, mixed content indicators and passive JavaScript risk indicators.

### 5. Web Header Audit

HTTP response status, CSP review, CORS review, missing browser protection headers and server-side policy visibility.

### 6. Findings Correlation

S4W consolidates findings with severity, confidence, evidence, impact, remediation, OWASP category, CWE reference and report-ready structure.

---

## Passive vulnerability indicators

S4W can identify passive indicators associated with:

- SQL Injection exposure patterns;
- XSS and DOM XSS indicators;
- CSRF protection gaps;
- File Inclusion indicators;
- Directory Traversal indicators;
- Command Injection indicators;
- Open Redirect indicators;
- Broken Authentication indicators;
- Insecure Direct Object Reference indicators;
- Security Misconfiguration.

These checks are based on observable patterns and should be validated manually in authorized environments before being treated as confirmed vulnerabilities.

---

## Legal notice

S4W is provided for defensive security assessment, education, authorized testing and internal hardening review.

Do not run it against third-party assets without permission.

All rights reserved.
