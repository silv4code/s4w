<p align="center">
  <img src="assets/s4w-logo.png" alt="S4W logo" width="240">
</p>

<h1 align="center">S4W</h1>

<p align="center">
  Passive Web Security Auditor for authorized web application reviews.
</p>

<p align="center">
  <a href="https://github.com/s4w-project/s4w/actions"><img alt="CI" src="https://img.shields.io/badge/ci-ready-2ea44f"></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-blue">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Kali%20Linux%20%7C%20Linux-lightgrey">
</p>

---

## Overview

**S4W** is a terminal-based passive web security assessment toolkit for initial web application reviews, exposure analysis, hardening checks, endpoint prioritization and structured reporting.

It focuses on observable application behavior and publicly reachable metadata. S4W does **not** perform brute force, automatic exploitation, aggressive fuzzing, authentication bypass, destructive testing or stealth activity.

Use it only on assets you own, controlled labs, bug bounty scopes that explicitly allow this activity, or environments where you have written authorization.

## What S4W Does

- Collects passive OSINT signals such as DNS, TLS, WHOIS, `robots.txt` and `security.txt`.
- Reviews visible HTML, assets, forms, scripts, links, e-mails and external domains.
- Prioritizes endpoints based on parameters, auth flows, CRUD behavior, upload surfaces, APIs and sensitive indicators.
- Audits web hardening controls such as security headers, cookies, CSP, mixed content and exposure indicators.
- Produces terminal output and optional JSON reports suitable for triage or documentation.

## What S4W Does Not Do

- No brute force.
- No password spraying.
- No credential stuffing.
- No exploit delivery.
- No hidden path fuzzing.
- No destructive or state-changing testing.

## Installation on Kali Linux

Install system dependencies:

```bash
sudo apt update
sudo apt install git python3 python3-pip python3-venv whois -y
```

Clone the repository:

```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/s4w.git
cd s4w
```

Run the installer:

```bash
chmod +x install.sh
./install.sh
```

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Check the CLI:

```bash
s4w --version
s4w -help
```

## Installation with pipx

`pipx` is a clean way to install CLI tools on Kali:

```bash
sudo apt update
sudo apt install git pipx whois -y
pipx ensurepath
pipx install git+https://github.com/YOUR_GITHUB_USERNAME/s4w.git
```

Then open a new terminal and run:

```bash
s4w -help
```

## Basic Usage

Interactive mode:

```bash
s4w https://example.com
```

Non-interactive mode:

```bash
s4w https://example.com -y
```

Save a JSON report:

```bash
mkdir -p reports
s4w https://example.com -y --json reports/example.json
```

Focused subdomain review:

```bash
s4w -s app.example.com -v
```

Skip WHOIS:

```bash
s4w https://example.com -y --skip-whois
```

Run as a Python module:

```bash
python3 -m s4w https://example.com -y
```

## Command-Line Options

| Option | Description |
|---|---|
| `s4w` | Shows a short usage guide. |
| `-h`, `--help`, `-help` | Shows help and quick examples. |
| `-y`, `--yes` | Runs all stages without interactive prompts. |
| `-s`, `--subdomain` | Reviews a specific authorized subdomain. |
| `-v`, `--verbose` | Shows detailed subdomain findings. |
| `--json` | Saves results to a JSON file. |
| `--timeout` | Sets HTTP request timeout in seconds. |
| `--skip-whois` | Skips local WHOIS lookup. |
| `--no-details` | Reduces long terminal details. |
| `--version` | Shows the installed version. |

## Analysis Modules

### Passive OSINT

- DNS records: A, AAAA, MX, NS, TXT, CAA and SOA.
- TLS certificate metadata.
- Local WHOIS lookup when available.
- `robots.txt`.
- `security.txt`.

### Passive Recon

- Apparent technologies.
- Internal and external links.
- Scripts, CSS, images and iframes.
- External domains.
- Forms.
- Relevant endpoints and URLs.
- Public e-mails in HTML.
- Inline JavaScript and event handlers.

### Endpoint Intelligence

S4W classifies visible URLs and forms, prioritizing endpoints that:

- receive parameters;
- suggest authentication, account, dashboard or administration flows;
- suggest CRUD operations;
- handle upload, checkout, API, AJAX or sensitive data flows;
- expose IDs, tokens, redirects or deployment artifacts in URLs.

### Web Hardening Review

- Security headers.
- Cookie flags: `Secure`, `HttpOnly` and `SameSite`.
- Weak or incomplete CSP.
- External resources without SRI.
- Mixed content indicators.
- Technology exposure.
- Passive JavaScript risk indicators.

## Example JSON Finding

```json
{
  "vulnerabilidade": "Missing Clickjacking Protection",
  "gravidade": "Media",
  "impacto": "The application can be embedded in a malicious iframe, increasing clickjacking risk.",
  "remediacao": "Set Content-Security-Policy frame-ancestors and/or X-Frame-Options.",
  "referencias": ["https://cwe.mitre.org/data/definitions/1021.html"],
  "confianca": "Alta",
  "categoria_owasp": "OWASP A05:2021 - Security Misconfiguration",
  "cwe": ["CWE-1021"],
  "evidencia": "Missing frame-ancestors and X-Frame-Options"
}
```

## Publishing to GitHub

From the project root:

```bash
git init
git add .
git commit -m "release: publish s4w passive web security auditor"
git branch -M main
git remote add origin https://github.com/YOUR_GITHUB_USERNAME/s4w.git
git push -u origin main
```

After publishing, install from Kali:

```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/s4w.git
cd s4w
chmod +x install.sh
./install.sh
source .venv/bin/activate
s4w -help
```

## Legal Notice

S4W is provided for defensive security assessment, education, authorized testing and internal hardening review. Do not run it against third-party assets without explicit permission.

## License

MIT. See [LICENSE](LICENSE).
