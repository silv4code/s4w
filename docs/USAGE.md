# S4W Usage Guide

## Authorized Scope

Before running S4W, confirm that the target is owned by you, part of a controlled lab, or explicitly included in a written authorization scope.

## Common Commands

Interactive review:

```bash
s4w https://example.com
```

Run all modules without prompts:

```bash
s4w https://example.com -y
```

Write JSON output:

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

## Notes

S4W is passive, but it still sends HTTP requests to the target URL and optional metadata endpoints such as `robots.txt` and `security.txt`.
