from __future__ import annotations

import re
from collections import Counter
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from .utils import absolutize, clean_text


VERSION_RE = re.compile(r"(?i)(wordpress|woocommerce|elementor|jquery|bootstrap|react|vue|angular)[^0-9]{0,20}([0-9]+(?:\.[0-9]+){1,3})")


def parse_html(html: str, base_url: str, registered_domain: str) -> dict:
    soup = BeautifulSoup(html or "", "html.parser")
    title = clean_text(soup.title.string if soup.title else "", 120)

    links = _collect_urls(soup, base_url, "a", "href")
    scripts = _collect_urls(soup, base_url, "script", "src")
    styles = _collect_urls(soup, base_url, "link", "href")
    images = _collect_urls(soup, base_url, "img", "src")
    frames = _collect_urls(soup, base_url, "iframe", "src")
    forms = _forms(soup, base_url)
    metas = _metas(soup)
    comments = re.findall(r"<!--(.*?)-->", html or "", flags=re.S)
    script_resources = _script_resources(soup, base_url)
    inline_scripts = _inline_scripts(soup)
    event_handlers = _event_handlers(soup)

    all_assets = scripts + styles + images + frames
    external_domains = sorted({urlparse(u).hostname for u in all_assets + links if _is_external(u, registered_domain) and urlparse(u).hostname})
    internal_links = sorted({u for u in links if not _is_external(u, registered_domain)})
    external_links = sorted({u for u in links if _is_external(u, registered_domain)})

    technologies = detect_technologies(html, metas, scripts, styles)
    endpoints = _extract_endpoints(html, links, scripts, forms)
    emails = sorted(set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", html or "")))

    return {
        "title": title,
        "links": links,
        "internal_links": internal_links[:200],
        "external_links": external_links[:200],
        "scripts": scripts,
        "script_resources": script_resources,
        "inline_scripts": inline_scripts,
        "event_handlers": event_handlers,
        "styles": styles,
        "images": images[:100],
        "frames": frames,
        "forms": forms,
        "metas": metas,
        "comments": [clean_text(c, 220) for c in comments[:20]],
        "external_domains": external_domains,
        "technologies": technologies,
        "endpoints": endpoints,
        "emails": emails[:30],
        "stats": {
            "links": len(links),
            "scripts": len(scripts),
            "inline_scripts": len(inline_scripts),
            "event_handlers": len(event_handlers),
            "styles": len(styles),
            "images": len(images),
            "frames": len(frames),
            "forms": len(forms),
            "external_domains": len(external_domains),
        },
    }


def _collect_urls(soup: BeautifulSoup, base_url: str, tag: str, attr: str) -> list[str]:
    items: list[str] = []
    for node in soup.find_all(tag):
        value = node.get(attr)
        url = absolutize(base_url, value)
        if url:
            items.append(url)
    return sorted(set(items))


def _script_resources(soup: BeautifulSoup, base_url: str) -> list[dict]:
    items: list[dict] = []
    for script in soup.find_all("script"):
        src = absolutize(base_url, script.get("src"))
        if not src:
            continue
        items.append({
            "src": src,
            "integrity": bool(script.get("integrity")),
            "crossorigin": script.get("crossorigin") or "",
            "async": script.has_attr("async"),
            "defer": script.has_attr("defer"),
            "type": script.get("type") or "",
        })
    return items[:250]


def _inline_scripts(soup: BeautifulSoup) -> list[dict]:
    scripts: list[dict] = []
    for idx, script in enumerate(soup.find_all("script"), 1):
        if script.get("src"):
            continue
        content = script.string or script.get_text("\n") or ""
        content = content.strip()
        if not content:
            continue
        scripts.append({
            "index": idx,
            "size": len(content),
            "snippet": clean_text(content, 500),
        })
    return scripts[:80]


def _event_handlers(soup: BeautifulSoup) -> list[dict]:
    handlers: list[dict] = []
    for tag in soup.find_all(True):
        for attr, value in tag.attrs.items():
            if attr.lower().startswith("on"):
                handlers.append({
                    "tag": tag.name,
                    "attr": attr,
                    "value": clean_text(str(value), 250),
                })
    return handlers[:120]


def _forms(soup: BeautifulSoup, base_url: str) -> list[dict]:
    forms: list[dict] = []
    for form in soup.find_all("form"):
        action = absolutize(base_url, form.get("action")) or base_url
        method = (form.get("method") or "GET").upper()
        inputs = []
        for field in form.find_all(["input", "textarea", "select"]):
            inputs.append({
                "name": field.get("name") or "",
                "type": field.get("type") or field.name,
                "id": field.get("id") or "",
                "autocomplete": field.get("autocomplete") or "",
            })
        forms.append({"method": method, "action": action, "inputs": inputs[:80]})
    return forms


def _metas(soup: BeautifulSoup) -> dict[str, str]:
    data: dict[str, str] = {}
    for meta in soup.find_all("meta"):
        key = meta.get("name") or meta.get("property") or meta.get("http-equiv")
        value = meta.get("content")
        if key and value:
            data[key.lower()] = clean_text(value, 300)
    return data


def _is_external(url: str, registered_domain: str) -> bool:
    host = urlparse(url).hostname or ""
    return registered_domain not in host


def detect_technologies(html: str, metas: dict[str, str], scripts: list[str], styles: list[str]) -> list[dict]:
    techs: dict[str, set[str]] = {}
    source = "\n".join([html or "", *scripts, *styles, *metas.values()])

    def add(name: str, evidence: str):
        techs.setdefault(name, set()).add(clean_text(evidence, 120))

    markers = {
        "WordPress": ["wp-content", "wp-includes", "generator\" content=\"WordPress"],
        "WooCommerce": ["woocommerce", "wc-cart", "wc-ajax"],
        "Elementor": ["elementor", "elementorFrontendConfig"],
        "jQuery": ["jquery", "jQuery"],
        "Google Tag Manager": ["googletagmanager.com", "GTM-"],
        "Google Analytics": ["google-analytics.com", "gtag("],
        "Google Maps": ["maps.google.com", "google.com/maps"],
        "Font Awesome": ["font-awesome", "fontawesome"],
        "PHP": [".php", "X-Powered-By: PHP"],
    }
    lower = source.lower()
    for name, terms in markers.items():
        for term in terms:
            if term.lower() in lower:
                add(name, term)
                break

    for match in VERSION_RE.finditer(source):
        add(match.group(1).title(), f"version {match.group(2)}")

    generator = metas.get("generator")
    if generator:
        add("Generator", generator)

    return [{"name": k, "evidence": sorted(v)} for k, v in sorted(techs.items())]


def _extract_endpoints(html: str, links: list[str], scripts: list[str], forms: list[dict]) -> list[str]:
    patterns = [
        r"/[A-Za-z0-9_./-]*(?:api|ajax|json|login|auth|cart|checkout|admin|wp-json|wp-admin)[A-Za-z0-9_./?=&%-]*",
        r"https?://[^'\"\s<>]+",
    ]
    found: list[str] = []
    for pattern in patterns:
        found.extend(re.findall(pattern, html or "", flags=re.I))
    found.extend(links)
    found.extend(scripts)
    found.extend([form["action"] for form in forms])
    cleaned = []
    for item in found:
        item = item.strip().rstrip("),.;'\"")
        if len(item) < 4:
            continue
        if item not in cleaned:
            cleaned.append(item)
    return cleaned[:250]


def domain_frequency(urls: list[str]) -> list[tuple[str, int]]:
    hosts = [urlparse(u).hostname for u in urls if urlparse(u).hostname]
    return Counter(hosts).most_common()
