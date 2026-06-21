from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from .audit import cookie_audit, header_audit, html_security_audit, score_from_alerts
from .endpoints import endpoint_audit
from .models import ScanContext, Alert, EndpointFinding, SubdomainFinding
from .net import fetch_url, set_cookie_headers
from .osint import run_osint
from .parser import parse_html, domain_frequency
from .report import save_json, alerts_to_dict, alerts_to_structured, endpoint_findings_to_dict, endpoint_findings_to_structured, subdomain_findings_to_dict, subdomain_findings_to_structured
from .render import banner, section, context as render_context, key_values, list_block, alerts_table, alert_details, score_panel, ask_continue, console, endpoint_findings_table, subdomain_findings_table, subdomain_finding_details
from .utils import normalize_target, domain_parts, now_iso
from .subdomain import validate_subdomain, subdomain_vulnerability_scan


def build_parser() -> argparse.ArgumentParser:
    epilog = """
Exemplos rápidos:
  s4w
      Mostra este tutorial curto.

  s4w https://example.com
      Executa a análise em modo interativo, com confirmação Y/N entre blocos.

  s4w https://example.com -y
      Executa todos os blocos sem pausa.

  s4w -s app.example.com -v
      Executa análise focada em subdomínio autorizado, com saída detalhada.

  s4w https://example.com -y --json reports/example.json
      Executa tudo e salva o relatório JSON.

Uso permitido:
  Utilize somente em ativos próprios, laboratório ou escopo com autorização formal.
"""
    parser = argparse.ArgumentParser(
        prog="s4w",
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="S4W Web Security Auditor — passive recon, endpoint intelligence, hardening, headers and structured findings.",
        epilog=epilog,
    )
    parser.add_argument("target", nargs="?", help="URL ou domínio autorizado. Ex: https://example.com")
    parser.add_argument("-h", "--help", "-help", action="store_true", help="Mostra ajuda e exemplos rápidos.")
    parser.add_argument("-y", "--yes", action="store_true", help="Executa todas as etapas sem perguntar Y/N.")
    parser.add_argument("-s", "--subdomain", dest="subdomain", help="Analisa um subdomínio específico autorizado. Ex: app.example.com")
    parser.add_argument("-v", "--verbose", action="store_true", help="Exibe detalhes completos dos achados de subdomínio.")
    parser.add_argument("--timeout", type=int, default=12, help="Timeout HTTP em segundos. Padrão: 12")
    parser.add_argument("--skip-whois", action="store_true", help="Não executa whois externo.")
    parser.add_argument("--json", dest="json_path", help="Salva resultado em JSON. Ex: reports/site.json")
    parser.add_argument("--no-details", action="store_true", help="Não imprime detalhes longos dos alertas.")
    parser.add_argument("--version", action="version", version=f"s4w {__version__}", help="Mostra a versão instalada.")
    return parser


def print_quick_help(parser: argparse.ArgumentParser) -> None:
    banner()
    console.print("[bold]S4W[/bold] — Web Security Auditor")
    console.print("[dim]Passive web security assessment for authorized applications.[/dim]\n")
    console.print(parser.format_help())


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) == 1 and argv[0].lower() in {"help", "ajuda", "?"}:
        argv = ["--help"]

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.help or (not args.target and not args.subdomain):
        print_quick_help(parser)
        return 0

    banner()

    subdomain_validation = None
    target_value = args.target
    if args.subdomain:
        subdomain_validation = validate_subdomain(args.subdomain)
        if not subdomain_validation.get("valid"):
            console.print("[bold red]Subdomínio inválido:[/bold red]")
            for error in subdomain_validation.get("errors", []):
                console.print(f"- {error}")
            return 2
        target_value = subdomain_validation.get("scan_target") or subdomain_validation["subdomain"]
    if not target_value:
        console.print("[bold red]Erro:[/bold red] informe um target ou use -s <subdominio>")
        return 2

    try:
        url = normalize_target(target_value)
        scheme, hostname, registered_domain, base_url = domain_parts(url)
    except Exception as exc:
        console.print(f"[bold red]Erro:[/bold red] {exc}")
        return 2

    ctx = ScanContext(
        original_target=args.target or args.subdomain or target_value,
        url=url,
        scheme=scheme,
        hostname=hostname,
        registered_domain=registered_domain,
        base_url=base_url,
        started_at=now_iso(),
    )

    full_result: dict = {"tool": "s4w", "version": __version__, "profile": "passive web security assessment", "rights": "All rights reserved", "context": ctx.__dict__, "alerts": [], "structured_findings": []}
    all_alerts: list[Alert] = []
    endpoint_findings: list[EndpointFinding] = []
    subdomain_findings: list[SubdomainFinding] = []

    section("Inicialização", "Coleta inicial da resposta HTTP principal")
    try:
        start = time.time()
        response = fetch_url(url, timeout=args.timeout)
        elapsed = int((time.time() - start) * 1000)
        headers = dict(response.headers)
        html = response.text or ""
        ctx.status_code = response.status_code
        ctx.final_url = response.url
        ctx.server = headers.get("Server")
        ctx.powered_by = headers.get("X-Powered-By")
        ctx.elapsed_ms = elapsed
        parsed = parse_html(html, base_url, registered_domain)
        ctx.title = parsed.get("title")
        full_result["context"] = ctx.__dict__
        full_result["http"] = {"headers": headers, "set_cookie": set_cookie_headers(response), "html_size": len(html)}
        full_result["parsed"] = parsed
        render_context(ctx)
        if subdomain_validation:
            full_result["subdomain_validation"] = subdomain_validation
            key_values("Validação de subdomínio", subdomain_validation, 20)
    except Exception as exc:
        console.print(f"[bold red]Falha na coleta inicial:[/bold red] {exc}")
        return 1

    if not ask_continue(args.yes):
        return _finish(args, full_result, all_alerts, endpoint_findings, subdomain_findings)

    section("1/6 OSINT Profundo", "DNS, TLS, WHOIS, robots.txt e security.txt sem varredura agressiva")
    osint_data = run_osint(base_url, hostname, registered_domain, skip_whois=args.skip_whois)
    full_result["osint"] = osint_data
    key_values("DNS", osint_data.get("dns", {}))
    key_values("TLS", osint_data.get("tls", {}))
    if osint_data.get("whois"):
        key_values("WHOIS extraído", osint_data["whois"])
    else:
        console.print("[dim]WHOIS sem dados extraídos ou desativado.[/dim]")
    robots = osint_data.get("robots", {})
    security_txt = osint_data.get("security_txt", {})
    console.print(f"[bold]robots.txt:[/bold] status={robots.get('status')}")
    if robots.get("interesting"):
        list_block("Entradas relevantes do robots.txt", robots["interesting"], 25)
    console.print(f"[bold]security.txt:[/bold] status={security_txt.get('status')}")
    if security_txt.get("contacts"):
        list_block("Contatos security.txt", security_txt["contacts"], 20)

    if not ask_continue(args.yes):
        return _finish(args, full_result, all_alerts, endpoint_findings, subdomain_findings)

    section("2/6 Recon Passivo", "Tecnologias, assets, links, formulários, endpoints, JavaScript e dependências externas")
    parsed = full_result["parsed"]
    key_values("Estatísticas HTML", parsed.get("stats", {}))
    if parsed.get("technologies"):
        tech_table = {item["name"]: "; ".join(item.get("evidence", [])) for item in parsed["technologies"]}
        key_values("Tecnologias detectadas", tech_table, 40)
    if parsed.get("external_domains"):
        list_block("Domínios externos", parsed["external_domains"], 30)
    if parsed.get("forms"):
        form_lines = []
        for form in parsed["forms"][:20]:
            fields = ", ".join([f.get("name") or f.get("type") or "field" for f in form.get("inputs", [])[:10]])
            form_lines.append(f"{form.get('method')} {form.get('action')} :: {fields}")
        list_block("Formulários", form_lines, 20)
    if parsed.get("endpoints"):
        list_block("Endpoints/URLs relevantes", parsed["endpoints"], 40)
    if parsed.get("emails"):
        list_block("E-mails encontrados no HTML", parsed["emails"], 20)
    freq = domain_frequency(parsed.get("scripts", []) + parsed.get("styles", []) + parsed.get("images", []))
    if freq:
        key_values("Frequência de assets por host", {k: v for k, v in freq[:20]})

    if not ask_continue(args.yes):
        return _finish(args, full_result, all_alerts, endpoint_findings, subdomain_findings)

    section("3/6 Endpoint Intelligence", "Priorização passiva de URLs, parâmetros, CRUD, autenticação e dados sensíveis")
    endpoint_summary, endpoint_findings, endpoint_alerts = endpoint_audit(parsed, registered_domain, start_score=100)
    all_alerts.extend(endpoint_alerts)
    full_result["endpoint_analysis"] = endpoint_summary
    full_result["endpoint_findings"] = endpoint_findings_to_dict(endpoint_findings)
    full_result["structured_endpoint_findings"] = endpoint_findings_to_structured(endpoint_findings)
    key_values("Resumo de endpoints", endpoint_summary, 20)
    if endpoint_summary.get("top_critical_endpoints"):
        list_block("Endpoints críticos priorizados", endpoint_summary["top_critical_endpoints"], 25)
    if endpoint_findings:
        endpoint_findings_table(endpoint_findings, "Achados por endpoint")
    else:
        console.print("[green]Nenhum endpoint crítico foi classificado pelas regras atuais.[/green]")

    if args.subdomain:
        section("3.5/6 Subdomain Vulnerability Profile", "Verificação focada no subdomínio informado com heurísticas passivas e formato de vulnerabilidade")
        current_score = endpoint_summary.get("score", 100) if isinstance(endpoint_summary, dict) else 100
        sub_summary, subdomain_findings, sub_alerts = subdomain_vulnerability_scan(hostname, parsed, full_result["http"].get("headers", {}), [], endpoint_score=current_score)
        all_alerts.extend(sub_alerts)
        full_result["subdomain_vulnerability_summary"] = sub_summary
        full_result["subdomain_findings"] = subdomain_findings_to_dict(subdomain_findings)
        full_result["structured_subdomain_findings"] = subdomain_findings_to_structured(subdomain_findings)
        key_values("Resumo do subdomínio", sub_summary, 25)
        if subdomain_findings:
            subdomain_findings_table(subdomain_findings, "Achados focados no subdomínio")
            if args.verbose:
                subdomain_finding_details(subdomain_findings, limit=30)
        else:
            console.print("[green]Nenhum indicador passivo de vulnerabilidade foi classificado para o subdomínio.[/green]")

        if not ask_continue(args.yes):
            return _finish(args, full_result, all_alerts, endpoint_findings, subdomain_findings)

    section("4/6 Checklist de Hardening Web", "Pontuação por controles, cookies, CSP, TLS, exposição, terceiros e JavaScript")
    headers = full_result["http"]["headers"]
    header_report, header_alerts = header_audit(headers)
    cookies, cookie_alerts = cookie_audit(full_result["http"].get("set_cookie", []))
    html_alerts = html_security_audit(parsed, registered_domain)
    all_alerts.extend(header_alerts + cookie_alerts + html_alerts)
    score = score_from_alerts(all_alerts)
    full_result["hardening"] = {"headers": header_report, "cookies": cookies, "score": score}
    full_result["alerts"] = alerts_to_dict(all_alerts)
    full_result["structured_findings"] = alerts_to_structured(all_alerts)
    score_panel(score)
    key_values("Headers presentes", header_report.get("present", {}), 30)
    if header_report.get("missing"):
        list_block("Headers ausentes", header_report["missing"], 30)
    if cookies:
        cookie_lines = [f"{c['name']} :: Secure={c['secure']} HttpOnly={c['httponly']} SameSite={c['samesite'] or '-'}" for c in cookies]
        list_block("Cookies avaliados", cookie_lines, 30)
    alerts_table(all_alerts, "Achados de hardening")

    if not ask_continue(args.yes):
        return _finish(args, full_result, all_alerts, endpoint_findings, subdomain_findings)

    section("5/6 Web Header Auditor", "Leitura focada em cabeçalhos HTTP e política CSP")
    raw_header_table = {k: v for k, v in headers.items()}
    key_values("Resposta HTTP", raw_header_table, 80)
    csp = headers.get("Content-Security-Policy") or headers.get("content-security-policy")
    if csp:
        console.print("[bold]CSP detectada:[/bold]")
        console.print(csp)
    else:
        console.print("[yellow]CSP não detectada.[/yellow]")
    header_only_alerts = [a for a in all_alerts if "headers" in a.tags or "csp" in a.tags]
    if header_only_alerts:
        alerts_table(header_only_alerts, "Alertas de headers/CSP")

    if not ask_continue(args.yes):
        return _finish(args, full_result, all_alerts, endpoint_findings, subdomain_findings)

    section("6/6 Findings Correlation", "Resumo técnico com risco, confiança, evidência, impacto e correção")
    ordered = sorted(all_alerts, key=_alert_sort_key)
    full_result["alerts"] = alerts_to_dict(ordered)
    full_result["structured_findings"] = alerts_to_structured(ordered)
    if ordered:
        alerts_table(ordered, "Alertas consolidados")
        if not args.no_details:
            alert_details(ordered, limit=25)
    else:
        console.print("[green]Nenhum alerta relevante gerado pelas regras atuais.[/green]")

    return _finish(args, full_result, ordered, endpoint_findings, subdomain_findings)


def _alert_sort_key(alert: Alert) -> tuple[int, str]:
    order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
    return order.get(alert.risk, 9), alert.title


def _finish(args: argparse.Namespace, result: dict, alerts: list[Alert], endpoint_findings: list[EndpointFinding] | None = None, subdomain_findings: list[SubdomainFinding] | None = None) -> int:
    endpoint_findings = endpoint_findings or []
    subdomain_findings = subdomain_findings or []
    result["alerts"] = alerts_to_dict(alerts)
    result["structured_findings"] = alerts_to_structured(alerts)
    result["endpoint_findings"] = endpoint_findings_to_dict(endpoint_findings)
    result["structured_endpoint_findings"] = endpoint_findings_to_structured(endpoint_findings)
    result["subdomain_findings"] = subdomain_findings_to_dict(subdomain_findings)
    result["structured_subdomain_findings"] = subdomain_findings_to_structured(subdomain_findings)
    if args.json_path:
        path = save_json(args.json_path, result)
        console.print(f"\n[green]JSON salvo em:[/green] {path}")
    console.print("\n[bold red]S4W finalizado.[/bold red] [dim]All rights reserved.[/dim]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
