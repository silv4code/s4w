from __future__ import annotations

import re
import shutil
from dataclasses import asdict
from urllib.parse import parse_qs, urlparse

from .models import Alert, SubdomainFinding
from .rules import CWE, OWASP, CSRF_WORDS
from .utils import registered_domain_from_host, safe_gethost

LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

SQLI_PARAMS = {"id", "uid", "user_id", "order", "order_id", "pedido", "produto", "product", "item", "cat", "category", "search", "q", "query"}
XSS_PARAMS = {"q", "query", "search", "s", "term", "keyword", "msg", "message", "name", "comment", "return", "next"}
FILE_PARAMS = {"file", "path", "page", "template", "view", "include", "load", "module", "doc", "document", "download", "url"}
CMD_PARAMS = {"cmd", "command", "exec", "execute", "ping", "host", "ip", "domain", "dns", "lookup"}
REDIRECT_PARAMS = {"next", "redirect", "redirect_uri", "redirect_url", "return", "return_url", "url", "callback", "continue", "dest", "destination"}
OBJECT_PARAMS = {"id", "uid", "user_id", "account", "order", "order_id", "client", "customer", "profile", "case"}
AUTH_WORDS = ("login", "auth", "signin", "signup", "account", "dashboard", "admin", "wp-login", "wp-admin", "session")
CRUD_WORDS = ("create", "new", "edit", "update", "delete", "remove", "save", "upload", "approve", "reject", "aprovar", "reprovar", "excluir", "salvar")
MISCONFIG_WORDS = ("debug", "test", "dev", "staging", "backup", "bkp", ".env", ".git", "config", "dump", "log", "old")

CVSS = {
    "SQL Injection": 9.8,
    "Cross-Site Scripting": 6.1,
    "CSRF": 6.5,
    "File Inclusion": 8.1,
    "Directory Traversal": 7.5,
    "Command Injection": 9.8,
    "Open Redirect": 6.1,
    "Broken Authentication": 8.8,
    "Insecure Direct Object Reference": 7.5,
    "Security Misconfiguration": 6.5,
}


def ref(*cwes: str) -> list[str]:
    return [CWE[cwe] for cwe in cwes if cwe in CWE]


def normalize_subdomain_value(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        raise ValueError("subdomínio vazio")
    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
    else:
        host = raw.split("/", 1)[0].split(":", 1)[0]
    host = host.strip().strip(".").lower()
    if not host:
        raise ValueError("subdomínio inválido")
    return host


def validate_subdomain(value: str, require_dns: bool = False) -> dict:
    """Validate a single subdomain supplied by the operator.

    This is compatible with a Sublist3r workflow: enumerate/choose a host, then pass
    the exact subdomain to s4w -s for focused auditing.
    """
    host = normalize_subdomain_value(value)
    labels = host.split(".")
    errors: list[str] = []

    if len(host) > 253:
        errors.append("tamanho total acima de 253 caracteres")
    if len(labels) < 3:
        errors.append("o valor parece ser domínio raiz; informe um subdomínio como app.example.com")
    if any(not LABEL_RE.match(label) for label in labels):
        errors.append("um ou mais labels do domínio possuem formato inválido")
    if "*" in host or ".." in host or "_" in host:
        errors.append("wildcard, label vazio ou underscore não são aceitos")

    registered = registered_domain_from_host(host)
    prefix = host[: -(len(registered) + 1)] if host.endswith("." + registered) else ""
    if registered == host or not prefix:
        errors.append("não foi possível separar prefixo de subdomínio do domínio registrado")

    ip = safe_gethost(host)
    if require_dns and not ip:
        errors.append("subdomínio não resolveu em DNS")

    raw = (value or "").strip()
    scan_target = raw.rstrip("/") if "://" in raw else host

    return {
        "valid": not errors,
        "input": value,
        "scan_target": scan_target,
        "subdomain": host,
        "registered_domain": registered,
        "prefix": prefix,
        "resolved_ip": ip,
        "dns_resolved": bool(ip),
        "errors": errors,
        "sublist3r_workflow": "Use Sublist3r para descoberta passiva e passe o host confirmado com s4w -s <subdominio>.",
        "sublist3r_installed": bool(shutil.which("sublist3r") or shutil.which("sublist3r.py")),
    }


def subdomain_vulnerability_scan(subdomain: str, parsed: dict, headers: dict[str, str], cookies: list[dict], endpoint_score: int = 100) -> tuple[dict, list[SubdomainFinding], list[Alert]]:
    findings: list[SubdomainFinding] = []
    current_score = max(0, min(100, endpoint_score))
    normalized_headers = {k.lower(): v for k, v in (headers or {}).items()}
    endpoints = parsed.get("endpoints", []) or []
    forms = parsed.get("forms", []) or []
    scripts_blob = "\n".join((s.get("snippet") or "") for s in parsed.get("inline_scripts", []) or [])
    script_l = scripts_blob.lower()

    def add(**kwargs):
        nonlocal current_score
        risk = kwargs.get("risk", "Low")
        penalty = {"Critical": 20, "High": 14, "Medium": 8, "Low": 3, "Informational": 0}.get(risk, 3)
        current_score = max(0, current_score - penalty)
        kwargs.setdefault("updated_score", current_score)
        kwargs.setdefault("subdomain", subdomain)
        findings.append(SubdomainFinding(**kwargs))

    for endpoint in _dedupe([e for e in endpoints if isinstance(e, str)]):
        profile = _endpoint_profile(endpoint)
        params = set(profile["params"])
        lower = endpoint.lower()

        if params & SQLI_PARAMS:
            add(
                endpoint=endpoint,
                vulnerability_type="SQL Injection",
                risk="Medium",
                confidence="Low",
                description="Endpoint possui parâmetros comumente usados em consultas ou filtros. Não há prova de injeção; o achado indica ponto prioritário para validação manual autorizada.",
                recommendation="Usar consultas parametrizadas/prepared statements, ORM seguro, validação de tipo e tratamento genérico de erros.",
                possible_exploitation="Em ambiente de homologação autorizado, validar se o parâmetro altera consulta SQL ou gera erro de banco ao receber entradas inesperadas. Não executar payloads em produção sem escopo formal.",
                recommended_fix="db.query('SELECT * FROM tabela WHERE id = ?', [id]) ou equivalente com prepared statement/ORM.",
                cvss=CVSS["SQL Injection"],
                evidence=f"Parâmetros sensíveis a SQLi: {', '.join(sorted(params & SQLI_PARAMS))}",
                owasp=OWASP["injection"],
                cwe=["CWE-89", "CWE-20"] if "CWE-89" in CWE else ["CWE-20"],
                references=ref("CWE-89", "CWE-20"),
            )

        if params & XSS_PARAMS:
            add(
                endpoint=endpoint,
                vulnerability_type="XSS",
                risk="Medium",
                confidence="Low",
                description="Parâmetros refletíveis/pesquisa/mensagem foram identificados. O risco deve ser validado manualmente observando reflexão no HTML/DOM.",
                recommendation="Escapar saída conforme contexto, sanitizar HTML quando necessário, usar CSP forte e validar entradas no servidor.",
                possible_exploitation="Em lab autorizado, testar se valores controlados pelo usuário retornam no HTML/DOM sem encoding adequado.",
                recommended_fix="Usar templates com autoescape, textContent no frontend e sanitização com biblioteca confiável quando aceitar HTML.",
                cvss=CVSS["Cross-Site Scripting"],
                evidence=f"Parâmetros com potencial de reflexão: {', '.join(sorted(params & XSS_PARAMS))}",
                owasp=OWASP["injection"],
                cwe=["CWE-79"],
                references=ref("CWE-79"),
            )

        if params & FILE_PARAMS:
            add(
                endpoint=endpoint,
                vulnerability_type="File Inclusion",
                risk="High",
                confidence="Low",
                description="Parâmetros relacionados a arquivos, páginas, templates, módulos ou URLs podem indicar superfície para inclusão/leitura indevida de arquivos se usados sem allowlist.",
                recommendation="Aplicar allowlist de recursos, resolver caminhos com segurança, impedir inclusão remota e bloquear acesso a arquivos fora do diretório permitido.",
                possible_exploitation="Em ambiente autorizado, validar se o parâmetro aceita nomes de arquivos/caminhos externos ao conjunto permitido.",
                recommended_fix="Mapear IDs lógicos para arquivos permitidos no servidor; nunca usar diretamente path recebido do cliente.",
                cvss=CVSS["File Inclusion"],
                evidence=f"Parâmetros de arquivo/rota: {', '.join(sorted(params & FILE_PARAMS))}",
                owasp=OWASP["access_control"],
                cwe=["CWE-22", "CWE-20"],
                references=ref("CWE-22", "CWE-20"),
            )

        if "../" in lower or "..%2f" in lower or params & {"path", "file", "download", "doc", "document"}:
            add(
                endpoint=endpoint,
                vulnerability_type="Directory Traversal",
                risk="Medium",
                confidence="Low",
                description="Endpoint tem indicadores de manipulação de caminho/arquivo. Deve existir normalização de path e bloqueio de acesso fora do diretório permitido.",
                recommendation="Normalizar caminho, negar sequências de traversal, usar allowlist e checar diretório final resolvido.",
                possible_exploitation="Validar em homologação se o parâmetro permite navegar para arquivos fora da pasta esperada.",
                recommended_fix="Resolver caminho com pathlib/realpath e confirmar que ele permanece dentro do diretório base permitido.",
                cvss=CVSS["Directory Traversal"],
                evidence="Indicador de caminho/arquivo no endpoint.",
                owasp=OWASP["access_control"],
                cwe=["CWE-22"],
                references=ref("CWE-22"),
            )

        if params & CMD_PARAMS:
            add(
                endpoint=endpoint,
                vulnerability_type="Command Injection",
                risk="High",
                confidence="Low",
                description="Parâmetros com nomes como cmd, host, ip ou domain podem indicar integração com comandos de sistema se implementados de forma insegura.",
                recommendation="Evitar shell=True, usar APIs nativas, allowlist estrita e separar argumentos com listas seguras.",
                possible_exploitation="Em lab autorizado, verificar se caracteres de controle alteram comportamento de comandos executados no servidor.",
                recommended_fix="subprocess.run(['ping', '-c', '1', host_validado], shell=False) com validação allowlist do host.",
                cvss=CVSS["Command Injection"],
                evidence=f"Parâmetros associados a comando/rede: {', '.join(sorted(params & CMD_PARAMS))}",
                owasp=OWASP["injection"],
                cwe=["CWE-78", "CWE-20"] if "CWE-78" in CWE else ["CWE-20"],
                references=ref("CWE-78", "CWE-20"),
            )

        if params & REDIRECT_PARAMS:
            add(
                endpoint=endpoint,
                vulnerability_type="Open Redirect",
                risk="Medium",
                confidence="Low",
                description="Endpoint possui parâmetros de redirecionamento. Sem validação de allowlist, pode redirecionar usuários para origem maliciosa.",
                recommendation="Aceitar apenas caminhos relativos ou origens em allowlist; rejeitar URLs absolutas externas.",
                possible_exploitation="Em ambiente autorizado, validar se o parâmetro aceita destino externo e redireciona após autenticação/ação.",
                recommended_fix="if target.startswith('/') and not target.startswith('//'): redirect(target) else: redirect('/').",
                cvss=CVSS["Open Redirect"],
                evidence=f"Parâmetros de redirecionamento: {', '.join(sorted(params & REDIRECT_PARAMS))}",
                owasp=OWASP["access_control"],
                cwe=["CWE-601"],
                references=ref("CWE-601"),
            )

        if params & OBJECT_PARAMS:
            add(
                endpoint=endpoint,
                vulnerability_type="Insecure Direct Object Reference",
                risk="Medium",
                confidence="Low",
                description="Parâmetros de objeto/conta/pedido indicam necessidade de autorização server-side por recurso para evitar IDOR/BOLA.",
                recommendation="Validar permissão do usuário autenticado para cada objeto solicitado; não confiar apenas no ID recebido.",
                possible_exploitation="Em ambiente autorizado, comparar acesso entre usuários e confirmar que trocar IDs não expõe recurso de outro usuário.",
                recommended_fix="Consultar objeto filtrando por id e owner/tenant/perfil autorizado no servidor.",
                cvss=CVSS["Insecure Direct Object Reference"],
                evidence=f"Parâmetros de objeto: {', '.join(sorted(params & OBJECT_PARAMS))}",
                owasp=OWASP["access_control"],
                cwe=["CWE-639", "CWE-862"],
                references=ref("CWE-639", "CWE-862"),
            )

        if any(word in lower for word in AUTH_WORDS):
            add(
                endpoint=endpoint,
                vulnerability_type="Broken Authentication",
                risk="Low",
                confidence="Medium",
                description="Endpoint de autenticação/administração identificado. O achado não prova falha, mas marca ponto crítico para verificar MFA, sessão, bloqueio progressivo e rate limit.",
                recommendation="Aplicar MFA, proteção contra brute force, rotação de sessão pós-login, Secure/HttpOnly/SameSite e logs de autenticação.",
                possible_exploitation="Validação segura: revisar logs e política de bloqueio/rate limit em ambiente autorizado, sem ataque de força bruta.",
                recommended_fix="Implementar rate limit, MFA, lockout progressivo e regeneração de sessão após autenticação.",
                cvss=CVSS["Broken Authentication"],
                evidence=endpoint,
                owasp=OWASP["auth"],
                cwe=["CWE-287"],
                references=ref("CWE-287"),
            )

        if any(word in lower for word in MISCONFIG_WORDS):
            add(
                endpoint=endpoint,
                vulnerability_type="Security Misconfiguration",
                risk="Medium",
                confidence="Medium",
                description="Endpoint ou recurso indica ambiente de debug, teste, backup, config, log ou artefato sensível potencialmente exposto.",
                recommendation="Remover artefatos do webroot, bloquear extensões sensíveis e revisar pipeline de deploy.",
                possible_exploitation="Validação segura: confirmar se o recurso retorna conteúdo sensível; não baixar dumps/dados sem autorização explícita.",
                recommended_fix="Negar acesso a .env, .git, backups, logs e configs no servidor web; manter esses arquivos fora do diretório público.",
                cvss=CVSS["Security Misconfiguration"],
                evidence=endpoint,
                owasp=OWASP["misconfig"],
                cwe=["CWE-548", "CWE-538", "CWE-200"],
                references=ref("CWE-548", "CWE-538", "CWE-200"),
            )

    for form in forms:
        method = (form.get("method") or "GET").upper()
        action = form.get("action") or subdomain
        inputs = form.get("inputs") or []
        names = {((field.get("name") or field.get("id") or "").lower()) for field in inputs}
        csrf = any(any(token in name for token in CSRF_WORDS) for name in names)
        if method == "POST" and not csrf:
            add(
                endpoint=action,
                vulnerability_type="CSRF",
                risk="Medium",
                confidence="Low",
                description="Formulário POST sem token CSRF aparente no HTML. Pode ser falso positivo caso o token seja aplicado via JavaScript ou cabeçalho.",
                recommendation="Validar token CSRF/nonce por sessão no servidor, SameSite nos cookies e rejeição de requisições sem token válido.",
                possible_exploitation="Em ambiente autorizado, confirmar se uma submissão sem token válido é rejeitada pelo servidor.",
                recommended_fix="Adicionar campo hidden csrf_token e validar com sessão/nonce no backend antes de alterar estado.",
                cvss=CVSS["CSRF"],
                evidence=f"{method} {action}",
                owasp=OWASP["access_control"],
                cwe=["CWE-352"],
                references=ref("CWE-352"),
            )

    missing_critical = [h for h in ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options"] if not normalized_headers.get(h)]
    if missing_critical:
        add(
            endpoint=f"https://{subdomain}/",
            vulnerability_type="Security Misconfiguration",
            risk="Medium",
            confidence="High",
            description="Headers de segurança críticos ausentes ou incompletos no subdomínio.",
            recommendation="Configurar CSP, HSTS, X-Frame-Options/frame-ancestors e X-Content-Type-Options conforme a aplicação.",
            possible_exploitation="Ausência desses controles aumenta impacto de XSS, clickjacking, downgrade/HTTP e MIME sniffing.",
            recommended_fix="Adicionar headers no servidor/reverse proxy e testar em modo Report-Only quando envolver CSP.",
            cvss=CVSS["Security Misconfiguration"],
            evidence=f"Headers ausentes: {', '.join(missing_critical)}",
            owasp=OWASP["misconfig"],
            cwe=["CWE-693", "CWE-1021"],
            references=ref("CWE-693", "CWE-1021"),
        )

    if ("innerhtml" in script_l or "document.write" in script_l or "eval(" in script_l) and ("location." in script_l or "document.referrer" in script_l or "window.name" in script_l):
        add(
            endpoint=f"https://{subdomain}/",
            vulnerability_type="XSS",
            risk="Medium",
            confidence="Medium",
            description="JavaScript contém combinação de sources controláveis e sinks DOM sensíveis, indicando possível DOM XSS.",
            recommendation="Evitar innerHTML/eval/document.write com dados não confiáveis; usar textContent e sanitização robusta.",
            possible_exploitation="Em lab autorizado, rastrear fluxo source→sink e confirmar se entrada controlável alcança HTML executável.",
            recommended_fix="Substituir sinks inseguros por APIs seguras e aplicar CSP com nonce/hash.",
            cvss=CVSS["Cross-Site Scripting"],
            evidence="Sources e sinks DOM encontrados no JavaScript inline.",
            owasp=OWASP["injection"],
            cwe=["CWE-79"],
            references=ref("CWE-79"),
        )

    findings = _dedupe_findings(findings)
    alerts = [finding_to_alert(item) for item in findings]
    summary = {
        "enabled": True,
        "subdomain": subdomain,
        "mode": "subdomain-focused passive vulnerability profile",
        "based_on": "Sublist3r-style workflow: descoberta passiva/seleção de subdomínio + validação focada no host informado.",
        "findings": len(findings),
        "score": current_score,
        "critical": sum(1 for f in findings if f.risk == "Critical"),
        "high": sum(1 for f in findings if f.risk == "High"),
        "medium": sum(1 for f in findings if f.risk == "Medium"),
        "low": sum(1 for f in findings if f.risk == "Low"),
        "informational": sum(1 for f in findings if f.risk == "Informational"),
        "classes_checked": [
            "SQL Injection", "XSS", "CSRF", "File Inclusion", "Directory Traversal", "Command Injection",
            "Open Redirect", "Broken Authentication", "Insecure Direct Object Reference", "Security Misconfiguration",
        ],
        "note": "Achados de subdomínio são passivos/heurísticos e devem ser confirmados manualmente em ambiente autorizado.",
    }
    return summary, findings, alerts


def finding_to_alert(finding: SubdomainFinding) -> Alert:
    risk = "High" if finding.risk == "Critical" else finding.risk
    return Alert(
        title=f"{finding.vulnerability_type} em subdomínio",
        risk=risk,
        confidence=finding.confidence,
        evidence=f"{finding.endpoint} :: {finding.evidence}",
        impact=finding.description,
        remediation=finding.recommended_fix or finding.recommendation,
        tags=["subdomain", "vulnerability-profile", finding.vulnerability_type.lower().replace(" ", "-")],
        owasp=finding.owasp,
        cwe=finding.cwe,
        references=finding.references,
    )


def _endpoint_profile(endpoint: str) -> dict:
    parsed = urlparse(endpoint)
    query = parse_qs(parsed.query, keep_blank_values=True)
    params = sorted({p.lower() for p in query.keys() if p})
    return {"endpoint": endpoint, "params": params, "path": parsed.path or endpoint}


def _dedupe(values: list[str]) -> list[str]:
    seen = set()
    out = []
    for value in values:
        key = value.strip()
        if key and key not in seen:
            seen.add(key)
            out.append(key)
    return out


def _dedupe_findings(findings: list[SubdomainFinding]) -> list[SubdomainFinding]:
    seen = set()
    out = []
    for item in findings:
        key = (item.endpoint, item.vulnerability_type, item.evidence)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out
