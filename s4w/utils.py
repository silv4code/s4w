from __future__ import annotations

import re
import socket
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("Target vazio")
    if not re.match(r"^https?://", target, re.I):
        target = "https://" + target
    parsed = urlparse(target)
    if not parsed.hostname:
        raise ValueError("URL inválida")
    return target.rstrip("/")


def domain_parts(url: str) -> tuple[str, str, str, str]:
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    hostname = parsed.hostname or ""
    registered = registered_domain_from_host(hostname)

    # Mantém porta customizada quando existir.
    # Isso evita perder endpoints como http://127.0.0.1:8877/robots.txt em labs locais.
    netloc = parsed.netloc or hostname
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    base = f"{scheme}://{netloc}"
    return scheme, hostname, registered, base


def absolutize(base: str, value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    if not value or value.startswith("javascript:") or value.startswith("mailto:") or value.startswith("tel:"):
        return None
    return urljoin(base, value)


def clean_text(value: str | None, limit: int = 160) -> str:
    if not value:
        return ""
    value = re.sub(r"\s+", " ", value).strip()
    if len(value) > limit:
        return value[: limit - 3] + "..."
    return value


def safe_gethost(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def risk_weight(risk: str) -> int:
    return {
        "High": 25,
        "Medium": 12,
        "Low": 5,
        "Informational": 1,
    }.get(risk, 0)


def mask_secret(value: str) -> str:
    if not value:
        return value
    if len(value) <= 10:
        return "*" * len(value)
    return value[:4] + "..." + value[-4:]


def registered_domain_from_host(hostname: str) -> str:
    host = (hostname or "").strip(".").lower()
    try:
        ipaddress.ip_address(host)
        return host
    except Exception:
        pass
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # Casos comuns de TLD composto no Brasil e alguns TLDs frequentes.
    compound_suffixes = {
        "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br",
        "co.uk", "org.uk", "ac.uk", "com.au", "com.ar", "com.mx",
    }
    last_two = ".".join(parts[-2:])
    if last_two in compound_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
