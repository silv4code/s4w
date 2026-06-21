from __future__ import annotations

import ssl
import socket
import subprocess
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import requests

DEFAULT_HEADERS = {
    "User-Agent": "S4W/1.5 Web Security Auditor",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.7,en;q=0.6",
}


def fetch_url(url: str, timeout: int = 12) -> requests.Response:
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    return session.get(url, timeout=timeout, allow_redirects=True, verify=True)


def fetch_light(url: str, timeout: int = 8) -> tuple[int | None, str, dict[str, str]]:
    try:
        response = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True, verify=True)
        text = response.text[:8000] if response.text else ""
        return response.status_code, text, dict(response.headers)
    except Exception as exc:
        return None, str(exc), {}


def set_cookie_headers(response: requests.Response) -> list[str]:
    raw_headers = getattr(response.raw, "headers", None)
    if raw_headers is None:
        value = response.headers.get("Set-Cookie")
        return [value] if value else []

    for method_name in ("get_all", "getlist"):
        method = getattr(raw_headers, method_name, None)
        if callable(method):
            try:
                values = method("Set-Cookie")
                if values:
                    return list(values)
            except Exception:
                pass

    value = response.headers.get("Set-Cookie")
    if not value:
        return []
    return [v.strip() for v in value.split(", ") if "=" in v]


def dns_lookup(domain: str) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    resolver.timeout = 3
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA"]:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [str(a).strip() for a in answers]
        except Exception:
            records[rtype] = []
    return records


def tls_certificate(hostname: str, port: int = 443, timeout: int = 7) -> dict[str, Any]:
    data: dict[str, Any] = {
        "available": False,
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "san": [],
        "error": None,
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        data["available"] = True
        data["subject"] = _tuple_name(cert.get("subject", []))
        data["issuer"] = _tuple_name(cert.get("issuer", []))
        data["not_before"] = cert.get("notBefore")
        data["not_after"] = cert.get("notAfter")
        san = cert.get("subjectAltName", [])
        data["san"] = [value for key, value in san if key.lower() == "dns"]
        if cert.get("notAfter"):
            expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            data["days_remaining"] = (expires - datetime.utcnow()).days
    except Exception as exc:
        data["error"] = str(exc)
    return data


def _tuple_name(value: Any) -> str:
    parts: list[str] = []
    try:
        for item in value:
            for key, val in item:
                parts.append(f"{key}={val}")
    except Exception:
        return str(value)
    return ", ".join(parts)


def whois_lookup(domain: str, timeout: int = 8) -> str:
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = result.stdout.strip() or result.stderr.strip()
        return output[:6000]
    except FileNotFoundError:
        return "whois não encontrado no sistema"
    except subprocess.TimeoutExpired:
        return "whois timeout"
    except Exception as exc:
        return str(exc)
