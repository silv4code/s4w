from __future__ import annotations

import re
from http.cookies import SimpleCookie
from urllib.parse import urlparse

from .models import Alert
from .rules import CWE, OWASP, CSRF_WORDS, DOM_SINKS, DOM_SOURCES, TOKEN_WORDS

SECURITY_HEADERS = {
    "Content-Security-Policy": "Controla origens de scripts, frames, forms e recursos.",
    "Strict-Transport-Security": "Força HTTPS em acessos futuros.",
    "X-Frame-Options": "Ajuda a reduzir risco de clickjacking.",
    "X-Content-Type-Options": "Evita MIME sniffing.",
    "Referrer-Policy": "Controla vazamento de URL via Referer.",
    "Permissions-Policy": "Restringe recursos do navegador.",
    "Cross-Origin-Opener-Policy": "Isola contexto de janelas cross-origin.",
    "Cross-Origin-Resource-Policy": "Restringe leitura cross-origin de recursos.",
}


def ref(*cwes: str) -> list[str]:
    return [CWE[cwe] for cwe in cwes if cwe in CWE]


def header_audit(headers: dict[str, str]) -> tuple[dict, list[Alert]]:
    normalized = {k.lower(): v for k, v in headers.items()}
    report = {"present": {}, "missing": [], "notes": []}
    alerts: list[Alert] = []

    for header, desc in SECURITY_HEADERS.items():
        value = normalized.get(header.lower())
        if value:
            report["present"][header] = value
        else:
            report["missing"].append(header)
            risk = "Medium" if header in ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options"] else "Low"
            cwe = ["CWE-693"]
            if header == "X-Frame-Options":
                cwe = ["CWE-1021"]
            alerts.append(Alert(
                title=f"Header ausente: {header}",
                risk=risk,
                confidence="High",
                evidence=f"O header {header} não foi encontrado na resposta HTTP.",
                impact=desc,
                remediation=f"Configurar {header} com política compatível com a aplicação.",
                tags=["headers", "hardening"],
                owasp=OWASP["misconfig"],
                cwe=cwe,
                references=ref(*cwe),
            ))

    server = normalized.get("server")
    powered = normalized.get("x-powered-by")
    if powered:
        alerts.append(Alert(
            title="Exposição de tecnologia via X-Powered-By",
            risk="Low",
            confidence="High",
            evidence=f"X-Powered-By: {powered}",
            impact="Facilita fingerprinting e priorização de ataques contra versões/stack conhecidos.",
            remediation="Remover ou mascarar X-Powered-By no servidor/aplicação.",
            tags=["fingerprinting", "headers"],
            owasp=OWASP["misconfig"],
            cwe=["CWE-200"],
            references=ref("CWE-200"),
        ))
    if server:
        report["notes"].append(f"Server: {server}")

    csp = normalized.get("content-security-policy", "")
    if csp:
        alerts.extend(csp_audit(csp))

    hsts = normalized.get("strict-transport-security", "")
    if hsts and "max-age" in hsts.lower():
        if "includesubdomains" not in hsts.lower():
            alerts.append(Alert(
                title="HSTS sem includeSubDomains",
                risk="Low",
                confidence="Medium",
                evidence=hsts,
                impact="Subdomínios podem permanecer sem proteção HSTS.",
                remediation="Avaliar uso de includeSubDomains e preload após validar todos os subdomínios em HTTPS.",
                tags=["headers", "tls"],
                owasp=OWASP["misconfig"],
                cwe=["CWE-319"],
                references=ref("CWE-319"),
            ))

    cors = normalized.get("access-control-allow-origin", "")
    credentials = normalized.get("access-control-allow-credentials", "")
    if cors.strip() == "*" and credentials.lower().strip() == "true":
        alerts.append(Alert(
            title="CORS permissivo com credenciais",
            risk="Medium",
            confidence="Medium",
            evidence=f"Access-Control-Allow-Origin: {cors}; Access-Control-Allow-Credentials: {credentials}",
            impact="A combinação de wildcard com credenciais indica política de origem mal definida. Em endpoints próprios, pode abrir caminho para leitura indevida de respostas autenticadas.",
            remediation="Restringir Access-Control-Allow-Origin a domínios confiáveis e usar Access-Control-Allow-Credentials somente quando necessário.",
            tags=["cors", "headers", "access-control"],
            owasp=OWASP["access_control"],
            cwe=["CWE-346"],
            references=ref("CWE-346"),
        ))

    return report, alerts


def csp_audit(csp: str) -> list[Alert]:
    alerts: list[Alert] = []
    csp_l = csp.lower()
    checks = [
        ("frame-ancestors", "Medium", "CSP sem frame-ancestors", "A política não declara frame-ancestors, reduzindo proteção contra clickjacking.", ["CWE-1021"]),
        ("form-action", "Low", "CSP sem form-action", "A política não restringe destinos de formulários.", ["CWE-693"]),
        ("object-src", "Low", "CSP sem object-src", "Plugins/objects legados não estão restritos explicitamente.", ["CWE-693"]),
        ("base-uri", "Low", "CSP sem base-uri", "A tag base pode alterar resolução de links se houver injeção HTML.", ["CWE-693"]),
    ]
    for token, risk, title, impact, cwe in checks:
        if token not in csp_l:
            alerts.append(Alert(
                title=title,
                risk=risk,
                confidence="High",
                evidence=csp,
                impact=impact,
                remediation=f"Adicionar diretiva {token} com valor adequado, por exemplo {token} 'self'.",
                tags=["csp", "hardening"],
                owasp=OWASP["misconfig"],
                cwe=cwe,
                references=ref(*cwe),
            ))

    weak_tokens = ["'unsafe-inline'", "'unsafe-eval'", " *", "http:"]
    for token in weak_tokens:
        if token in csp_l:
            alerts.append(Alert(
                title=f"CSP permissiva: {token.strip()}",
                risk="Low",
                confidence="Medium",
                evidence=csp,
                impact="Política permissiva reduz a capacidade de mitigação contra XSS e injeções de conteúdo.",
                remediation="Migrar gradualmente para nonces/hashes, remover wildcards e validar em Report-Only antes de bloquear.",
                tags=["csp", "xss-impact"],
                owasp=OWASP["injection"],
                cwe=["CWE-79", "CWE-693"],
                references=ref("CWE-79", "CWE-693"),
            ))
    return alerts


def cookie_audit(set_cookie_values: list[str]) -> tuple[list[dict], list[Alert]]:
    cookies: list[dict] = []
    alerts: list[Alert] = []

    for raw in set_cookie_values:
        parsed = SimpleCookie()
        try:
            parsed.load(raw)
        except Exception:
            continue
        for name, morsel in parsed.items():
            attrs = raw.lower()
            item = {
                "name": name,
                "secure": "secure" in attrs,
                "httponly": "httponly" in attrs,
                "samesite": morsel.get("samesite") or _extract_samesite(raw),
                "path": morsel.get("path") or "",
                "domain": morsel.get("domain") or "",
            }
            cookies.append(item)

            sensitive = _looks_sensitive(name)
            if not item["secure"]:
                risk = "Medium" if sensitive else "Low"
                alerts.append(Alert(
                    title=f"Cookie sem Secure: {name}",
                    risk=risk,
                    confidence="High",
                    evidence=raw,
                    impact="Cookie pode ser transmitido em conexões HTTP caso existam fluxos inseguros.",
                    remediation="Adicionar flag Secure em todos os cookies quando o site opera em HTTPS.",
                    tags=["cookies", "tls"],
                    owasp=OWASP["crypto"],
                    cwe=["CWE-614"],
                    references=ref("CWE-614"),
                ))
            if not item["httponly"]:
                risk = "Medium" if sensitive else "Low"
                alerts.append(Alert(
                    title=f"Cookie sem HttpOnly: {name}",
                    risk=risk,
                    confidence="High",
                    evidence=raw,
                    impact="Em caso de XSS, JavaScript pode ler o cookie.",
                    remediation="Aplicar HttpOnly em cookies de sessão/autenticação. Validar compatibilidade para cookies funcionais.",
                    tags=["cookies", "xss-impact"],
                    owasp=OWASP["injection"],
                    cwe=["CWE-1004"],
                    references=ref("CWE-1004"),
                ))
            if not item["samesite"]:
                alerts.append(Alert(
                    title=f"Cookie sem SameSite: {name}",
                    risk="Low",
                    confidence="High",
                    evidence=raw,
                    impact="A ausência de SameSite pode ampliar exposição a fluxos CSRF em cenários específicos.",
                    remediation="Definir SameSite=Lax por padrão, ou Strict quando compatível.",
                    tags=["cookies", "csrf"],
                    owasp=OWASP["access_control"],
                    cwe=["CWE-352"],
                    references=ref("CWE-352"),
                ))
    return cookies, alerts


def _extract_samesite(raw: str) -> str:
    for part in raw.split(";"):
        part = part.strip()
        if part.lower().startswith("samesite="):
            return part.split("=", 1)[1]
    return ""


def _looks_sensitive(name: str) -> bool:
    name_l = name.lower()
    return any(term in name_l for term in ["session", "auth", "token", "logged", "wordpress_sec", "phpsessid", "jwt"])


def html_security_audit(parsed: dict, registered_domain: str) -> list[Alert]:
    alerts: list[Alert] = []
    scripts = parsed.get("scripts", [])
    styles = parsed.get("styles", [])
    frames = parsed.get("frames", [])
    forms = parsed.get("forms", [])
    metas = parsed.get("metas", {})

    http_assets = [u for u in scripts + styles + parsed.get("images", []) + frames if u.startswith("http://")]
    if http_assets:
        alerts.append(Alert(
            title="Recursos carregados por HTTP",
            risk="Medium",
            confidence="High",
            evidence="\n".join(http_assets[:8]),
            impact="Recursos sem TLS podem ser interceptados ou alterados em trânsito.",
            remediation="Carregar todos os recursos por HTTPS e manter upgrade-insecure-requests como camada adicional.",
            tags=["mixed-content", "tls"],
            owasp=OWASP["crypto"],
            cwe=["CWE-319"],
            references=ref("CWE-319"),
        ))

    external_assets = [u for u in scripts + styles if _external(u, registered_domain)]
    sri_candidates = [u for u in external_assets if not _is_dynamic_provider(u)]
    resources = parsed.get("script_resources", [])
    no_integrity = [r["src"] for r in resources if _external(r.get("src", ""), registered_domain) and not r.get("integrity") and not _is_dynamic_provider(r.get("src", ""))]
    sri_candidates = sorted(set(sri_candidates + no_integrity))
    if sri_candidates:
        alerts.append(Alert(
            title="Recursos externos sem validação SRI aparente",
            risk="Low",
            confidence="Medium",
            evidence="\n".join(sri_candidates[:10]),
            impact="Se um servidor externo for comprometido, conteúdo malicioso pode ser servido ao site.",
            remediation="Usar Subresource Integrity em recursos externos estáticos e reduzir dependências de terceiros.",
            tags=["sri", "third-party", "supply-chain"],
            owasp=OWASP["integrity"],
            cwe=["CWE-829", "CWE-345"],
            references=ref("CWE-829"),
        ))

    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "GET")
        inputs = form.get("inputs", [])
        if action.startswith("http://"):
            alerts.append(Alert(
                title="Formulário enviado por HTTP",
                risk="High",
                confidence="High",
                evidence=action,
                impact="Credenciais ou dados pessoais podem trafegar sem criptografia.",
                remediation="Enviar formulários somente para destinos HTTPS.",
                tags=["forms", "tls"],
                owasp=OWASP["crypto"],
                cwe=["CWE-319"],
                references=ref("CWE-319"),
            ))
        if action and _external(action, registered_domain):
            alerts.append(Alert(
                title="Formulário enviado para domínio externo",
                risk="Medium",
                confidence="Medium",
                evidence=action,
                impact="Dados podem ser enviados para terceiros fora do domínio principal.",
                remediation="Validar necessidade do destino externo e restringir com CSP form-action.",
                tags=["forms", "privacy"],
                owasp=OWASP["misconfig"],
                cwe=["CWE-359"],
                references=ref("CWE-359"),
            ))
        if method.upper() == "POST" and not _has_csrf_token(inputs):
            field_names = ", ".join([i.get("name") or i.get("id") or i.get("type") or "field" for i in inputs[:12]])
            alerts.append(Alert(
                title="Formulário POST sem token CSRF aparente",
                risk="Low",
                confidence="Low",
                evidence=f"{method} {action} :: {field_names}",
                impact="A ausência de token visível pode indicar proteção CSRF ausente ou implementada fora do HTML. Requer validação manual.",
                remediation="Validar no servidor o uso de token CSRF/nonce por sessão, SameSite em cookies e rejeição de submissões sem token válido.",
                tags=["csrf", "forms", "manual-validation"],
                owasp=OWASP["access_control"],
                cwe=["CWE-352"],
                references=ref("CWE-352"),
            ))

    generator = metas.get("generator")
    if generator:
        alerts.append(Alert(
            title="Meta generator expõe tecnologia/versão",
            risk="Low",
            confidence="High",
            evidence=generator,
            impact="Facilita fingerprinting de CMS, plugins ou construtores.",
            remediation="Remover meta generator quando possível e manter componentes atualizados.",
            tags=["fingerprinting"],
            owasp=OWASP["misconfig"],
            cwe=["CWE-200"],
            references=ref("CWE-200"),
        ))

    if frames:
        alerts.append(Alert(
            title="Uso de iframes detectado",
            risk="Informational",
            confidence="High",
            evidence="\n".join(frames[:8]),
            impact="Iframes ampliam dependência de terceiros e devem estar refletidos na CSP.",
            remediation="Mapear origens necessárias e restringir frame-src/frame-ancestors.",
            tags=["iframes", "csp"],
            owasp=OWASP["misconfig"],
            cwe=["CWE-693"],
            references=ref("CWE-693"),
        ))

    alerts.extend(javascript_security_audit(parsed))
    return alerts


def javascript_security_audit(parsed: dict) -> list[Alert]:
    alerts: list[Alert] = []
    inline_scripts = parsed.get("inline_scripts", [])
    handlers = parsed.get("event_handlers", [])
    endpoints = parsed.get("endpoints", [])
    js_blob = "\n".join(script.get("snippet", "") for script in inline_scripts)
    js_l = js_blob.lower()

    sinks = [sink for sink in DOM_SINKS if sink.lower() in js_l]
    sources = [source for source in DOM_SOURCES if source.lower() in js_l]
    if sinks and sources:
        alerts.append(Alert(
            title="Possível DOM XSS por uso de source e sink no JavaScript",
            risk="Medium",
            confidence="Medium",
            evidence=f"Sources: {', '.join(sources)} | Sinks: {', '.join(sinks)}",
            impact="Dados controláveis pelo usuário podem alcançar funções que interpretam HTML ou executam código, criando risco de XSS baseado em DOM.",
            remediation="Evitar sinks perigosos, usar textContent, sanitizar HTML com biblioteca confiável e validar fluxo source→sink manualmente.",
            tags=["javascript", "dom-xss", "xss"],
            owasp=OWASP["injection"],
            cwe=["CWE-79"],
            references=ref("CWE-79"),
        ))
    elif sinks:
        alerts.append(Alert(
            title="JavaScript usa sinks DOM sensíveis",
            risk="Low",
            confidence="Medium",
            evidence=", ".join(sinks),
            impact="Sinks como innerHTML, document.write ou eval podem se tornar XSS quando recebem dados não confiáveis.",
            remediation="Preferir APIs seguras, remover eval/document.write e revisar entradas que alimentam esses sinks.",
            tags=["javascript", "xss-impact"],
            owasp=OWASP["injection"],
            cwe=["CWE-79"],
            references=ref("CWE-79"),
        ))

    if handlers:
        sample = [f"<{h.get('tag')} {h.get('attr')}=\"{h.get('value')}\"" for h in handlers[:8]]
        alerts.append(Alert(
            title="Manipuladores de evento inline detectados",
            risk="Low",
            confidence="High",
            evidence="\n".join(sample),
            impact="Handlers inline dificultam CSP forte e aumentam superfície de XSS em caso de injeção HTML.",
            remediation="Mover handlers para JavaScript externo/controlado e aplicar CSP com nonce/hash quando possível.",
            tags=["javascript", "csp", "xss-impact"],
            owasp=OWASP["injection"],
            cwe=["CWE-79", "CWE-693"],
            references=ref("CWE-79", "CWE-693"),
        ))

    token_storage = _detect_token_storage(js_blob)
    if token_storage:
        alerts.append(Alert(
            title="Possível armazenamento de token no Web Storage",
            risk="Medium",
            confidence="Medium",
            evidence="\n".join(token_storage[:8]),
            impact="Tokens em localStorage/sessionStorage ficam acessíveis para JavaScript e podem ser extraídos em caso de XSS.",
            remediation="Preferir cookies HttpOnly/Secure/SameSite para sessão ou reduzir escopo/tempo de vida do token e fortalecer CSP.",
            tags=["javascript", "storage", "token", "xss-impact"],
            owasp=OWASP["auth"],
            cwe=["CWE-922", "CWE-522"],
            references=ref("CWE-922", "CWE-522"),
        ))

    if re.search(r"postMessage\s*\([^)]*,\s*['\"]\*['\"]", js_blob, flags=re.I | re.S):
        alerts.append(Alert(
            title="postMessage com origem wildcard",
            risk="Medium",
            confidence="Medium",
            evidence="postMessage(..., '*')",
            impact="Mensagens entre janelas podem ser enviadas para origens não confiáveis, expondo dados ou fluxos de integração.",
            remediation="Substituir '*' pela origem exata esperada e validar event.origin no receptor.",
            tags=["javascript", "postmessage", "origin-validation"],
            owasp=OWASP["access_control"],
            cwe=["CWE-346"],
            references=ref("CWE-346"),
        ))

    idor_candidates = _detect_idor_candidates(endpoints)
    if idor_candidates:
        alerts.append(Alert(
            title="Possíveis referências diretas a objetos em URLs/endpoints",
            risk="Informational",
            confidence="Low",
            evidence="\n".join(idor_candidates[:10]),
            impact="Parâmetros previsíveis como id, user_id ou pedido podem indicar pontos que exigem controle de autorização server-side.",
            remediation="Validar autorização no servidor para cada objeto acessado e testar manualmente troca de IDs em ambiente autorizado.",
            tags=["idor", "access-control", "manual-validation"],
            owasp=OWASP["access_control"],
            cwe=["CWE-639", "CWE-862"],
            references=ref("CWE-639", "CWE-862"),
        ))

    return alerts


def _detect_token_storage(js_blob: str) -> list[str]:
    findings: list[str] = []
    patterns = [
        r"(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*['\"]([^'\"]+)['\"]",
        r"(?:localStorage|sessionStorage)\[['\"]([^'\"]+)['\"]\]",
        r"(?:localStorage|sessionStorage)\.([A-Za-z0-9_\-]+)",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, js_blob, flags=re.I):
            key = match.group(1)
            if any(word in key.lower() for word in TOKEN_WORDS):
                findings.append(match.group(0))
    return sorted(set(findings))


def _detect_idor_candidates(endpoints: list[str]) -> list[str]:
    patterns = [
        r"[?&](?:id|user_id|uid|account|pedido|order|customer|cliente)=\d+",
        r"/(?:user|users|account|order|orders|pedido|cliente|profile)/\d+",
    ]
    found: list[str] = []
    for endpoint in endpoints:
        for pattern in patterns:
            if re.search(pattern, endpoint, flags=re.I):
                found.append(endpoint)
                break
    return sorted(set(found))


def _has_csrf_token(inputs: list[dict]) -> bool:
    for item in inputs:
        name = (item.get("name") or "").lower()
        field_id = (item.get("id") or "").lower()
        field_type = (item.get("type") or "").lower()
        if field_type == "hidden" and any(word in name or word in field_id for word in CSRF_WORDS):
            return True
        if any(word in name or word in field_id for word in CSRF_WORDS):
            return True
    return False


def _external(url: str, registered_domain: str) -> bool:
    host = urlparse(url).hostname or ""
    return bool(host and registered_domain not in host)


def _is_dynamic_provider(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return any(provider in host for provider in ["googletagmanager.com", "google-analytics.com", "google.com", "gstatic.com"])


def score_from_alerts(alerts: list[Alert]) -> dict:
    score = 100
    for alert in alerts:
        if alert.risk == "High":
            score -= 18
        elif alert.risk == "Medium":
            score -= 9
        elif alert.risk == "Low":
            score -= 3
    score = max(0, min(100, score))
    if score >= 85:
        grade = "A"
        level = "Bom"
    elif score >= 70:
        grade = "B"
        level = "Aceitável"
    elif score >= 50:
        grade = "C"
        level = "Atenção"
    else:
        grade = "D"
        level = "Crítico"
    return {"score": score, "grade": grade, "level": level}
