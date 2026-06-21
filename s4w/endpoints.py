from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

from .models import Alert, EndpointFinding
from .rules import CWE, OWASP


SENSITIVE_PARAMS = {
    "token", "access_token", "refresh_token", "id_token", "jwt", "bearer", "secret", "api_key", "apikey",
    "key", "senha", "password", "pass", "auth", "session", "sessid", "sid",
}

OBJECT_PARAMS = {
    "id", "uid", "user", "user_id", "userid", "account", "account_id", "cliente", "cliente_id",
    "customer", "customer_id", "order", "order_id", "pedido", "pedido_id", "profile", "doc", "documento",
}

REDIRECT_PARAMS = {
    "next", "url", "uri", "redirect", "redirect_uri", "return", "return_url", "continue", "callback", "dest", "destination",
}

CRUD_WORDS = {
    "create", "new", "add", "insert", "update", "edit", "delete", "remove", "save", "patch", "put", "upload",
}

AUTH_WORDS = {
    "login", "logout", "auth", "oauth", "sso", "signin", "signup", "register", "reset", "password",
    "account", "session", "token",
}

ADMIN_WORDS = {
    "admin", "wp-admin", "dashboard", "manager", "manage", "management", "console", "portal",
}

DATA_WORDS = {
    "api", "wp-json", "json", "ajax", "graphql", "rest", "download", "export", "file", "upload",
    "checkout", "cart", "payment", "pay", "invoice", "billing", "order",
}

EXPOSED_FILE_RE = re.compile(
    r"(?:^|/)(?:\.env|\.git|backup|dump|database|db|config|debug|test|dev|staging|old|bkp)[^/?#]*(?:$|[?#])|"
    r"\.(?:bak|old|sql|zip|tar|gz|7z|rar|env|log|conf|ini)(?:$|[?#])",
    flags=re.I,
)


RISK_PENALTY = {"High": 12, "Medium": 7, "Low": 3, "Informational": 0}


def ref(*cwes: str) -> list[str]:
    return [CWE[cwe] for cwe in cwes if cwe in CWE]


def endpoint_audit(parsed: dict, registered_domain: str, start_score: int = 100) -> tuple[dict, list[EndpointFinding], list[Alert]]:
    """Passive endpoint intelligence.

    The function only classifies URLs and forms already visible in the first HTML response.
    It does not brute force, fuzz or probe hidden paths.
    """
    raw_endpoints = parsed.get("endpoints", []) or []
    forms = parsed.get("forms", []) or []
    endpoints = _dedupe([e for e in raw_endpoints if isinstance(e, str) and e.strip()])

    findings: list[EndpointFinding] = []
    score = max(0, min(100, start_score))

    endpoint_profiles = []
    for endpoint in endpoints:
        profile = classify_endpoint(endpoint, registered_domain)
        endpoint_profiles.append(profile)
        for candidate in _find_endpoint_issues(profile):
            score = max(0, score - RISK_PENALTY.get(candidate["risk"], 0))
            findings.append(EndpointFinding(updated_score=score, **candidate))

    for form in forms:
        for candidate in _find_form_issues(form, registered_domain):
            score = max(0, score - RISK_PENALTY.get(candidate["risk"], 0))
            findings.append(EndpointFinding(updated_score=score, **candidate))

    findings = _dedupe_findings(findings)
    alerts = [_finding_to_alert(item) for item in findings]
    summary = _summary(endpoint_profiles, forms, findings, score)
    return summary, findings, alerts


def classify_endpoint(endpoint: str, registered_domain: str) -> dict:
    parsed = urlparse(endpoint)
    path = parsed.path or endpoint
    query = parse_qs(parsed.query, keep_blank_values=True)
    host = parsed.hostname or ""
    lower = endpoint.lower()
    params = sorted(query.keys())

    flags = {
        "external": bool(host and registered_domain not in host),
        "http": endpoint.startswith("http://"),
        "has_params": bool(params),
        "object_params": sorted(set(p.lower() for p in params) & OBJECT_PARAMS),
        "redirect_params": sorted(set(p.lower() for p in params) & REDIRECT_PARAMS),
        "sensitive_params": sorted(set(p.lower() for p in params) & SENSITIVE_PARAMS),
        "auth": any(word in lower for word in AUTH_WORDS),
        "admin": any(word in lower for word in ADMIN_WORDS),
        "crud": any(_word_in_endpoint(lower, word) for word in CRUD_WORDS),
        "data": any(word in lower for word in DATA_WORDS),
        "exposed_file": bool(EXPOSED_FILE_RE.search(lower)),
    }

    priority_score = 0
    priority_score += 30 if flags["sensitive_params"] else 0
    priority_score += 25 if flags["admin"] else 0
    priority_score += 25 if flags["auth"] else 0
    priority_score += 25 if flags["crud"] else 0
    priority_score += 20 if flags["object_params"] else 0
    priority_score += 20 if flags["redirect_params"] else 0
    priority_score += 20 if flags["data"] else 0
    priority_score += 20 if flags["http"] else 0
    priority_score += 10 if flags["external"] else 0

    if priority_score >= 65:
        priority = "Alta"
    elif priority_score >= 30:
        priority = "Média"
    else:
        priority = "Baixa"

    return {
        "endpoint": endpoint,
        "path": path,
        "host": host,
        "params": params,
        "flags": flags,
        "priority_score": priority_score,
        "priority": priority,
    }


def _find_endpoint_issues(profile: dict) -> list[dict]:
    endpoint = profile["endpoint"]
    flags = profile["flags"]
    params = profile.get("params", [])
    priority = profile.get("priority", "Média")
    issues: list[dict] = []

    if flags["http"]:
        issues.append({
            "endpoint": endpoint,
            "vulnerability": "Endpoint acessível por HTTP",
            "risk": "High",
            "confidence": "High",
            "impact": "Dados trafegando por HTTP podem ser interceptados ou alterados em trânsito, principalmente em endpoints com login, parâmetros ou operação sensível.",
            "remediation": "Forçar HTTPS, redirecionar HTTP para HTTPS e aplicar HSTS após validar o domínio.",
            "evidence": endpoint,
            "priority": priority,
            "tags": ["endpoint", "tls", "http"],
            "owasp": OWASP["crypto"],
            "cwe": ["CWE-319"],
            "references": ref("CWE-319"),
        })

    if flags["sensitive_params"]:
        issues.append({
            "endpoint": endpoint,
            "vulnerability": "Possível dado sensível em parâmetro de URL",
            "risk": "Medium",
            "confidence": "Medium",
            "impact": "Tokens, chaves ou dados de autenticação em URL podem vazar por histórico, logs, Referer, prints e ferramentas de monitoramento.",
            "remediation": "Mover segredos para corpo da requisição ou headers seguros; reduzir tempo de vida dos tokens; evitar registrar query string em logs.",
            "evidence": f"Parâmetros sensíveis: {', '.join(flags['sensitive_params'])}",
            "priority": "Alta",
            "tags": ["endpoint", "sensitive-data", "url"],
            "owasp": OWASP["crypto"],
            "cwe": ["CWE-598", "CWE-200"],
            "references": ref("CWE-598", "CWE-200"),
        })

    if flags["redirect_params"]:
        issues.append({
            "endpoint": endpoint,
            "vulnerability": "Parâmetro com possível fluxo de redirecionamento",
            "risk": "Low",
            "confidence": "Low",
            "impact": "Parâmetros como next, redirect ou return_url podem se tornar Open Redirect se o servidor aceitar destinos externos sem validação.",
            "remediation": "Validar destinos com allowlist, aceitar apenas caminhos relativos e bloquear redirecionamentos para origens não confiáveis.",
            "evidence": f"Parâmetros de redirecionamento: {', '.join(flags['redirect_params'])}",
            "priority": priority,
            "tags": ["endpoint", "redirect", "manual-validation"],
            "owasp": OWASP["access_control"],
            "cwe": ["CWE-601"],
            "references": ref("CWE-601"),
        })

    if flags["object_params"]:
        issues.append({
            "endpoint": endpoint,
            "vulnerability": "Possível referência direta a objeto em parâmetro",
            "risk": "Informational",
            "confidence": "Low",
            "impact": "Parâmetros como id, user_id, pedido ou cliente indicam pontos onde o servidor deve validar autorização por objeto para evitar IDOR/BOLA.",
            "remediation": "Garantir autorização server-side em cada acesso a objeto; não confiar apenas em ID vindo do cliente; validar troca de IDs somente em ambiente autorizado.",
            "evidence": f"Parâmetros de objeto: {', '.join(flags['object_params'])}",
            "priority": priority,
            "tags": ["endpoint", "idor", "bola", "manual-validation"],
            "owasp": OWASP["access_control"],
            "cwe": ["CWE-639", "CWE-862"],
            "references": ref("CWE-639", "CWE-862"),
        })

    if flags["exposed_file"]:
        issues.append({
            "endpoint": endpoint,
            "vulnerability": "Possível arquivo sensível ou artefato exposto",
            "risk": "Medium",
            "confidence": "Medium",
            "impact": "Arquivos de backup, logs, dumps, configs ou artefatos de teste podem revelar credenciais, estrutura interna, versões e dados sensíveis.",
            "remediation": "Remover artefatos do webroot, bloquear extensões sensíveis no servidor e revisar pipeline de deploy.",
            "evidence": endpoint,
            "priority": "Alta",
            "tags": ["endpoint", "exposure", "backup", "config"],
            "owasp": OWASP["misconfig"],
            "cwe": ["CWE-538", "CWE-548", "CWE-200"],
            "references": ref("CWE-538", "CWE-548", "CWE-200"),
        })

    if flags["admin"] or flags["auth"]:
        issues.append({
            "endpoint": endpoint,
            "vulnerability": "Endpoint crítico de autenticação/administração identificado",
            "risk": "Informational",
            "confidence": "High",
            "impact": "Endpoints de login, conta, dashboard ou administração concentram risco e devem receber controles adicionais de autenticação, sessão e rate limit.",
            "remediation": "Aplicar MFA quando possível, rate limiting, logs de autenticação, bloqueio progressivo, CSRF em ações e revisão de autorização por função.",
            "evidence": endpoint,
            "priority": "Alta" if flags["admin"] else priority,
            "tags": ["endpoint", "auth", "admin" if flags["admin"] else "account"],
            "owasp": OWASP["auth"],
            "cwe": ["CWE-287", "CWE-425"],
            "references": ref("CWE-287", "CWE-425"),
        })

    if flags["crud"] and flags["has_params"]:
        issues.append({
            "endpoint": endpoint,
            "vulnerability": "Endpoint com operação de alteração e parâmetros",
            "risk": "Low",
            "confidence": "Medium",
            "impact": "Endpoints de criação, edição, exclusão, aprovação ou upload exigem validação de autorização, CSRF, logs e checagem de entrada.",
            "remediation": "Exigir método HTTP adequado, token CSRF em ações de estado, validação server-side, autorização por função e registro de auditoria.",
            "evidence": f"Parâmetros: {', '.join(params[:12])}",
            "priority": priority,
            "tags": ["endpoint", "crud", "access-control"],
            "owasp": OWASP["access_control"],
            "cwe": ["CWE-862", "CWE-352", "CWE-20"],
            "references": ref("CWE-862", "CWE-352", "CWE-20"),
        })

    return issues


def _find_form_issues(form: dict, registered_domain: str) -> list[dict]:
    action = form.get("action") or ""
    method = (form.get("method") or "GET").upper()
    inputs = form.get("inputs", []) or []
    names = [(i.get("name") or i.get("id") or i.get("type") or "field").lower() for i in inputs]
    types = [(i.get("type") or "").lower() for i in inputs]
    parsed = urlparse(action)
    external = bool(parsed.hostname and registered_domain not in parsed.hostname)
    has_password = "password" in types or any("senha" in n or "password" in n for n in names)
    has_file = "file" in types or any("upload" in n or "arquivo" in n or "file" in n for n in names)
    has_hidden = "hidden" in types
    issues: list[dict] = []

    if method == "GET" and has_password:
        issues.append({
            "endpoint": action,
            "vulnerability": "Formulário de senha usando método GET",
            "risk": "High",
            "confidence": "High",
            "impact": "Senha ou segredo pode ser enviado na URL, vazando em histórico, logs e cabeçalho Referer.",
            "remediation": "Alterar para POST, usar HTTPS, tokens CSRF e nunca transmitir credenciais pela query string.",
            "evidence": f"method={method}; fields={', '.join(names[:12])}",
            "priority": "Alta",
            "tags": ["endpoint", "form", "credentials", "url"],
            "owasp": OWASP["auth"],
            "cwe": ["CWE-598", "CWE-319"],
            "references": ref("CWE-598", "CWE-319"),
        })

    if method == "POST" and not _has_csrf_signal(names):
        issues.append({
            "endpoint": action,
            "vulnerability": "Endpoint POST sem token anti-CSRF aparente",
            "risk": "Low",
            "confidence": "Low",
            "impact": "A ausência de token visível pode indicar risco de CSRF em ações autenticadas; também pode ser falso positivo se o token for injetado por JS ou validado por outro mecanismo.",
            "remediation": "Validar token CSRF/nonce por sessão no servidor, SameSite em cookies e rejeição de submissões sem token válido.",
            "evidence": f"method={method}; fields={', '.join(names[:12])}",
            "priority": "Alta" if has_password or has_file else "Média",
            "tags": ["endpoint", "form", "csrf", "manual-validation"],
            "owasp": OWASP["access_control"],
            "cwe": ["CWE-352"],
            "references": ref("CWE-352"),
        })

    if external:
        issues.append({
            "endpoint": action,
            "vulnerability": "Formulário envia dados para domínio externo",
            "risk": "Medium",
            "confidence": "Medium",
            "impact": "Dados preenchidos pelo usuário podem ser enviados a terceiros, exigindo validação de finalidade, privacidade e CSP form-action.",
            "remediation": "Confirmar domínio de destino, restringir form-action na CSP e remover integrações desnecessárias.",
            "evidence": action,
            "priority": "Alta" if has_password or has_file else "Média",
            "tags": ["endpoint", "form", "third-party", "privacy"],
            "owasp": OWASP["misconfig"],
            "cwe": ["CWE-359"],
            "references": ref("CWE-359"),
        })

    if has_file:
        issues.append({
            "endpoint": action,
            "vulnerability": "Endpoint de upload identificado",
            "risk": "Informational",
            "confidence": "High",
            "impact": "Uploads exigem validação de tipo, tamanho, extensão, armazenamento fora do webroot e varredura contra conteúdo malicioso.",
            "remediation": "Validar MIME e extensão no servidor, renomear arquivos, limitar tamanho, bloquear execução no diretório de upload e registrar auditoria.",
            "evidence": f"fields={', '.join(names[:12])}",
            "priority": "Alta",
            "tags": ["endpoint", "upload", "file-handling"],
            "owasp": OWASP["misconfig"],
            "cwe": ["CWE-434"],
            "references": ["https://cwe.mitre.org/data/definitions/434.html"],
        })

    if has_hidden and method == "POST":
        issues.append({
            "endpoint": action,
            "vulnerability": "Formulário POST com campos ocultos exige validação server-side",
            "risk": "Informational",
            "confidence": "Medium",
            "impact": "Campos hidden podem ser alterados pelo cliente; valores de preço, ID, cargo, status ou permissão não devem ser confiados no frontend.",
            "remediation": "Recalcular valores críticos no servidor e validar autorização para cada campo sensível.",
            "evidence": f"hidden fields in {action}",
            "priority": "Média",
            "tags": ["endpoint", "form", "hidden-fields", "manual-validation"],
            "owasp": OWASP["access_control"],
            "cwe": ["CWE-20", "CWE-862"],
            "references": ref("CWE-20", "CWE-862"),
        })

    return issues


def _finding_to_alert(finding: EndpointFinding) -> Alert:
    return Alert(
        title=f"Endpoint: {finding.vulnerability}",
        risk=finding.risk,
        confidence=finding.confidence,
        evidence=f"{finding.endpoint}\n{finding.evidence}".strip(),
        impact=finding.impact,
        remediation=finding.remediation,
        tags=finding.tags,
        owasp=finding.owasp,
        cwe=finding.cwe,
        references=finding.references,
    )


def _summary(profiles: list[dict], forms: list[dict], findings: list[EndpointFinding], final_score: int) -> dict:
    critical = [p for p in profiles if p.get("priority") == "Alta"]
    medium = [p for p in profiles if p.get("priority") == "Média"]
    risk_count: dict[str, int] = {}
    for item in findings:
        risk_count[item.risk] = risk_count.get(item.risk, 0) + 1
    return {
        "total_endpoints": len(profiles),
        "total_forms": len(forms),
        "critical_endpoints": len(critical),
        "medium_priority_endpoints": len(medium),
        "findings": len(findings),
        "risk_count": risk_count,
        "endpoint_score": final_score,
        "top_critical_endpoints": [p["endpoint"] for p in sorted(critical, key=lambda x: x.get("priority_score", 0), reverse=True)[:25]],
        "analyzer_mode": "passive-html-endpoint-intelligence",
    }


def _has_csrf_signal(names: list[str]) -> bool:
    words = ["csrf", "xsrf", "nonce", "_wpnonce", "token", "authenticity"]
    return any(any(word in name for word in words) for name in names)


def _word_in_endpoint(lower: str, word: str) -> bool:
    return bool(re.search(rf"(?:^|[/?&_=\-.]){re.escape(word)}(?:$|[/?&_=\-.])", lower)) or word in lower


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        value = value.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _dedupe_findings(findings: list[EndpointFinding]) -> list[EndpointFinding]:
    seen: set[tuple[str, str]] = set()
    out: list[EndpointFinding] = []
    for item in findings:
        key = (item.endpoint, item.vulnerability)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out[:120]
