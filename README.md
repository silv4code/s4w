Save-TextNoBom ".\README.md" @'
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