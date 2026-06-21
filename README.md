<p align="center">
  <img src="assets/s4w-logo.png" alt="S4W Logo" width="220">
</p>

<h1 align="center">S4W</h1>

<p align="center">
  <strong>Passive Web Security Auditor for modern web applications.</strong>
</p>

<p align="center">
  Security headers • Passive recon • Endpoint intelligence • Hardening review • Structured findings
</p>

---

## Overview

**S4W** is a terminal-based passive web security assessment toolkit designed to support initial security reviews, exposure analysis, hardening checks and structured reporting for web applications.

The project focuses on observable application behavior, publicly reachable metadata and passive indicators that can help security teams, developers and analysts identify misconfigurations, weak hardening practices and potentially sensitive exposure points.

S4W does **not** perform brute force, automatic exploitation, destructive testing, aggressive fuzzing, bypass attempts or intrusive attacks.

Use it only on assets you own, controlled labs or environments where you have formal authorization.

---

## Key Features

- Passive OSINT collection
- DNS record inspection
- TLS certificate visibility
- Local WHOIS lookup when available
- `robots.txt` and `security.txt` review
- Passive technology detection
- Link, asset, script and form discovery
- Endpoint intelligence and prioritization
- Web hardening checklist
- Security header review
- Cookie flag review
- CSP and CORS review
- Passive JavaScript risk indicators
- Subdomain-focused assessment with `-s`
- Structured findings with severity, confidence, evidence and remediation
- JSON report export

---

## Assessment Scope

S4W can identify passive indicators related to:

- Security Misconfiguration
- Missing or weak security headers
- Weak Content Security Policy
- Clickjacking exposure
- Cookie hardening issues
- CORS misconfiguration indicators
- CSRF protection gaps
- XSS and DOM XSS indicators
- SQL Injection exposure patterns
- Open Redirect indicators
- File Inclusion indicators
- Directory Traversal indicators
- Command Injection indicators
- Broken Authentication indicators
- Insecure Direct Object Reference indicators
- Sensitive endpoint exposure
- External resources without integrity controls

Passive indicators should always be validated manually in authorized environments before being treated as confirmed vulnerabilities.

---

## Installation on Kali Linux

Install system dependencies:

```bash
sudo apt update
sudo apt install git python3 python3-pip python3-venv whois -y
```

Clone the repository:

```bash
git clone https://github.com/silv4code/s4w.git
cd s4w
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install S4W:

```bash
python -m pip install --upgrade pip
pip install -e .
```

Check the installation:

```bash
s4w --version
```

Open the quick help:

```bash
s4w
```

or:

```bash
s4w -help
```

---

## Installation with pipx

```bash
sudo apt update
sudo apt install git pipx whois -y
pipx ensurepath
pipx install git+https://github.com/silv4code/s4w.git
s4w -help
```

---

## Windows Installation

Clone the repository:

```powershell
cd $env:USERPROFILE\Downloads
git clone https://github.com/silv4code/s4w.git
cd s4w
```

Create and activate a virtual environment:

```powershell
py -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\activate
```

Install S4W:

```powershell
pip install -e .
```

Run the tool:

```powershell
s4w --version
s4w -help
```

If the `s4w` command is not available in your PATH, run it through Python:

```powershell
py -m s4w.cli --version
py -m s4w.cli -help
```

---

## Basic Usage

Interactive assessment:

```bash
s4w https://example.com
```

Non-interactive assessment:

```bash
s4w https://example.com -y
```

Save JSON output:

```bash
mkdir -p reports
s4w https://example.com -y --json reports/example.json
```

Focused subdomain assessment:

```bash
s4w -s app.example.com -v
```

Subdomain assessment with JSON output:

```bash
mkdir -p reports
s4w -s app.example.com -v -y --json reports/app.json
```

Increase request timeout:

```bash
s4w https://example.com -y --timeout 25
```

Reduce terminal details:

```bash
s4w https://example.com -y --no-details --json reports/example.json
```

Skip WHOIS lookup:

```bash
s4w https://example.com -y --skip-whois
```

---

## Command-Line Options

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

## Analysis Modules

### 1. Passive OSINT

Collects passive information such as DNS records, TLS certificate details, WHOIS output, `robots.txt` and `security.txt`.

### 2. Passive Recon

Identifies apparent technologies, internal and external links, scripts, stylesheets, images, iframes, forms, visible endpoints, public e-mails and JavaScript indicators.

### 3. Endpoint Intelligence

Classifies visible URLs and forms, prioritizing endpoints that:

- receive parameters;
- suggest authentication, account, dashboard or administration flows;
- suggest create, read, update or delete operations;
- handle uploads, APIs, AJAX, checkout or sensitive workflows;
- expose IDs, tokens, redirects or deployment artifacts.

### 4. Web Hardening Review

Reviews security headers, cookie flags, CSP posture, mixed content indicators, exposed technologies and passive JavaScript risk patterns.

### 5. Web Header Audit

Reviews HTTP response headers, browser-side protection policies, CSP, CORS and visible server-side configuration indicators.

### 6. Findings Correlation

Consolidates observations into structured findings containing:

- severity;
- confidence;
- evidence;
- impact;
- remediation;
- OWASP mapping;
- CWE references;
- report-ready output.

---

## Output

S4W provides terminal output and optional JSON export.

Example:

```bash
s4w https://example.com -y --json reports/example.json
```

The JSON output is designed to support internal documentation, triage, technical reporting and security review workflows.

---

## Recommended Use Cases

- Initial web application security review
- Passive external exposure assessment
- Security header validation
- Hardening checklist automation
- Reconnaissance for authorized assessments
- Endpoint prioritization before manual testing
- Developer-focused remediation support
- Lightweight security reporting

---

## Legal Notice

S4W is intended for defensive security assessment, education, authorized testing and internal hardening review.

Do not run this tool against third-party assets without explicit permission.

All rights reserved.
