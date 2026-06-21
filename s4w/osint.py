from __future__ import annotations

import re
import ipaddress
from urllib.parse import urljoin

from .net import dns_lookup, fetch_light, tls_certificate, whois_lookup
from .utils import clean_text


def run_osint(base_url: str, hostname: str, registered_domain: str, skip_whois: bool = False) -> dict:
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except Exception:
        pass
    dns = {"A": [hostname]} if is_ip else dns_lookup(registered_domain)
    if is_ip:
        tls = {"available": False, "error": "TLS check ignorado para IP"}
    elif str(base_url).lower().startswith("http://"):
        tls = {"available": False, "error": "TLS check ignorado porque o alvo inicial usa HTTP"}
    else:
        tls = tls_certificate(hostname)
    robots_status, robots_body, _ = fetch_light(urljoin(base_url + "/", "robots.txt"))
    security_status, security_body, _ = fetch_light(urljoin(base_url + "/", ".well-known/security.txt"))
    whois_raw = "" if skip_whois else whois_lookup(registered_domain)

    return {
        "domain": registered_domain,
        "hostname": hostname,
        "dns": dns,
        "tls": tls,
        "robots": {
            "status": robots_status,
            "interesting": _interesting_robots(robots_body),
            "body_preview": clean_text(robots_body, 1000),
        },
        "security_txt": {
            "status": security_status,
            "contacts": _security_contacts(security_body),
            "body_preview": clean_text(security_body, 1200),
        },
        "whois": _parse_whois(whois_raw),
        "whois_preview": clean_text(whois_raw, 1800),
    }


def _interesting_robots(body: str) -> list[str]:
    if not body or "html" in body[:100].lower():
        return []
    rows = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if any(x in line.lower() for x in ["disallow", "allow", "sitemap", "admin", "login", "backup", "private", "wp-"]):
            rows.append(line)
    return rows[:50]


def _security_contacts(body: str) -> list[str]:
    if not body:
        return []
    contacts = []
    for line in body.splitlines():
        if line.lower().startswith("contact:") or "mailto:" in line.lower():
            contacts.append(line.strip())
    return contacts[:20]


def _parse_whois(raw: str) -> dict:
    if not raw:
        return {}
    fields = {
        "registrar": ["registrar", "sponsoring registrar"],
        "creation_date": ["creation date", "created", "created on"],
        "updated_date": ["updated date", "last updated", "changed"],
        "expiration_date": ["registry expiry date", "expiration date", "paid-till", "expires"],
        "name_servers": ["name server", "nserver"],
    }
    out: dict[str, list[str] | str] = {}
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    for out_key, keys in fields.items():
        values: list[str] = []
        for line in lines:
            line_l = line.lower()
            if any(line_l.startswith(k + ":") for k in keys):
                value = line.split(":", 1)[1].strip()
                if value and value not in values:
                    values.append(value)
        if values:
            out[out_key] = values[:10] if out_key == "name_servers" else values[0]
    emails = sorted(set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", raw)))
    if emails:
        out["emails"] = emails[:10]
    return out
