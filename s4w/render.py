from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from .models import Alert, ScanContext, EndpointFinding, SubdomainFinding

console = Console()


RISK_STYLE = {
    "Critical": "bold red on white",
    "High": "bold red",
    "Medium": "yellow",
    "Low": "cyan",
    "Informational": "dim",
}


def banner() -> None:
    text = Text()
    text.append("S4W", style="bold red")
    text.append("  Web Security Auditor", style="bold white")
    text.append("\nPassive Assessment • Recon • Endpoints • Hardening • Headers • Findings", style="dim")
    console.print(Panel(text, border_style="red", box=box.ROUNDED))


def section(title: str, subtitle: str = "") -> None:
    body = f"[bold white]{title}[/bold white]"
    if subtitle:
        body += f"\n[dim]{subtitle}[/dim]"
    console.print(Panel(body, border_style="red"))


def context(ctx: ScanContext) -> None:
    table = Table(box=box.SIMPLE, show_header=False)
    table.add_column("Campo", style="bold")
    table.add_column("Valor")
    table.add_row("Target", ctx.original_target)
    table.add_row("URL", ctx.url)
    table.add_row("Host", ctx.hostname)
    table.add_row("Domínio", ctx.registered_domain)
    if ctx.status_code is not None:
        table.add_row("Status", str(ctx.status_code))
    if ctx.final_url:
        table.add_row("Final URL", ctx.final_url)
    if ctx.title:
        table.add_row("Title", ctx.title)
    if ctx.server:
        table.add_row("Server", ctx.server)
    if ctx.powered_by:
        table.add_row("X-Powered-By", ctx.powered_by)
    if ctx.elapsed_ms is not None:
        table.add_row("Tempo", f"{ctx.elapsed_ms} ms")
    console.print(table)


def key_values(title: str, data: dict, limit: int = 25) -> None:
    table = Table(title=title, box=box.SIMPLE)
    table.add_column("Chave", style="bold red")
    table.add_column("Valor")
    count = 0
    for key, value in data.items():
        if count >= limit:
            table.add_row("...", f"+{len(data) - limit} itens")
            break
        if isinstance(value, list):
            rendered = "\n".join(map(str, value[:8]))
            if len(value) > 8:
                rendered += f"\n... +{len(value)-8}"
        else:
            rendered = str(value)
        table.add_row(str(key), rendered or "-")
        count += 1
    console.print(table)


def list_block(title: str, values: list, limit: int = 20) -> None:
    table = Table(title=title, box=box.SIMPLE)
    table.add_column("#", justify="right", style="dim")
    table.add_column("Valor")
    for index, value in enumerate(values[:limit], 1):
        table.add_row(str(index), str(value))
    if len(values) > limit:
        table.add_row("...", f"+{len(values)-limit} itens")
    console.print(table)


def alerts_table(alerts: list[Alert], title: str = "Alertas") -> None:
    table = Table(title=title, box=box.SIMPLE_HEAVY)
    table.add_column("Risco", style="bold")
    table.add_column("Conf.")
    table.add_column("CWE")
    table.add_column("Achado", overflow="fold")
    table.add_column("Evidência", overflow="fold")
    for alert in alerts:
        style = RISK_STYLE.get(alert.risk, "white")
        evidence = alert.evidence.replace("\n", " | ")
        if len(evidence) > 180:
            evidence = evidence[:177] + "..."
        cwe = ", ".join(alert.cwe[:3]) if alert.cwe else "-"
        table.add_row(f"[{style}]{alert.risk}[/{style}]", alert.confidence, cwe, alert.title, evidence)
    console.print(table)


def alert_details(alerts: list[Alert], limit: int = 20) -> None:
    for idx, alert in enumerate(alerts[:limit], 1):
        style = RISK_STYLE.get(alert.risk, "white")
        body = (
            f"[bold]Risco:[/bold] [{style}]{alert.risk}[/{style}]\n"
            f"[bold]Confiança:[/bold] {alert.confidence}\n"
            f"[bold]OWASP:[/bold] {alert.owasp or '-'}\n"
            f"[bold]CWE:[/bold] {', '.join(alert.cwe) if alert.cwe else '-'}\n"
            f"[bold]Evidência:[/bold] {alert.evidence}\n"
            f"[bold]Impacto:[/bold] {alert.impact}\n"
            f"[bold]Correção:[/bold] {alert.remediation}\n"
            f"[bold]Referências:[/bold] {', '.join(alert.references) if alert.references else '-'}\n"
            f"[bold]Tags:[/bold] {', '.join(alert.tags) if alert.tags else '-'}"
        )
        console.print(Panel(body, title=f"{idx}. {alert.title}", border_style=style))
    if len(alerts) > limit:
        console.print(f"[dim]+{len(alerts)-limit} alertas omitidos na visualização detalhada[/dim]")


def score_panel(score: dict) -> None:
    score_value = score.get("score", 0)
    style = "green" if score_value >= 85 else "yellow" if score_value >= 65 else "red"
    console.print(Panel(
        f"[bold]Score:[/bold] [{style}]{score_value}/100[/{style}]\n"
        f"[bold]Grade:[/bold] {score.get('grade')}\n"
        f"[bold]Nível:[/bold] {score.get('level')}",
        title="Resultado geral",
        border_style=style,
    ))


def endpoint_findings_table(findings: list[EndpointFinding], title: str = "Endpoint Intelligence") -> None:
    table = Table(title=title, box=box.SIMPLE_HEAVY)
    table.add_column("Prioridade", style="bold")
    table.add_column("Risco")
    table.add_column("Score")
    table.add_column("Endpoint", overflow="fold")
    table.add_column("Achado", overflow="fold")
    table.add_column("Evidência", overflow="fold")
    for item in findings[:60]:
        style = RISK_STYLE.get(item.risk, "white")
        evidence = (item.evidence or "-").replace("\n", " | ")
        if len(evidence) > 120:
            evidence = evidence[:117] + "..."
        endpoint = item.endpoint
        if len(endpoint) > 160:
            endpoint = endpoint[:157] + "..."
        table.add_row(item.priority, f"[{style}]{item.risk}[/{style}]", str(item.updated_score), endpoint, item.vulnerability, evidence)
    if len(findings) > 60:
        table.add_row("...", "...", "...", f"+{len(findings)-60} itens", "", "")
    console.print(table)


def ask_continue(auto_yes: bool = False) -> bool:
    if auto_yes:
        return True
    console.print()
    answer = console.input("[bold red]Continuar para a próxima etapa?[/bold red] [Y/N]: ").strip().lower()
    return answer in ("y", "yes", "s", "sim")



def subdomain_findings_table(findings: list[SubdomainFinding], title: str = "Subdomain Vulnerability Profile") -> None:
    table = Table(title=title, box=box.SIMPLE_HEAVY)
    table.add_column("Gravidade", style="bold")
    table.add_column("CVSS")
    table.add_column("Tipo", overflow="fold")
    table.add_column("Endpoint", overflow="fold")
    table.add_column("Evidência", overflow="fold")
    for item in findings[:80]:
        style = RISK_STYLE.get(item.risk, "white")
        endpoint = item.endpoint if len(item.endpoint) <= 150 else item.endpoint[:147] + "..."
        evidence = (item.evidence or "-").replace("\n", " | ")
        if len(evidence) > 130:
            evidence = evidence[:127] + "..."
        table.add_row(f"[{style}]{item.risk}[/{style}]", str(item.cvss), item.vulnerability_type, endpoint, evidence)
    if len(findings) > 80:
        table.add_row("...", "...", "...", f"+{len(findings)-80} itens", "")
    console.print(table)


def subdomain_finding_details(findings: list[SubdomainFinding], limit: int = 20) -> None:
    for idx, item in enumerate(findings[:limit], 1):
        style = RISK_STYLE.get(item.risk, "white")
        body = (
            f"[bold]Subdomínio:[/bold] {item.subdomain}\n"
            f"[bold]Endpoint:[/bold] {item.endpoint}\n"
            f"[bold]Gravidade:[/bold] [{style}]{item.risk}[/{style}]\n"
            f"[bold]CVSS:[/bold] {item.cvss}\n"
            f"[bold]Confiança:[/bold] {item.confidence}\n"
            f"[bold]Descrição:[/bold] {item.description}\n"
            f"[bold]Possível exploração:[/bold] {item.possible_exploitation}\n"
            f"[bold]Mitigação:[/bold] {item.recommendation}\n"
            f"[bold]Correção recomendada:[/bold] {item.recommended_fix}\n"
            f"[bold]OWASP:[/bold] {item.owasp or '-'}\n"
            f"[bold]CWE:[/bold] {', '.join(item.cwe) if item.cwe else '-'}"
        )
        console.print(Panel(body, title=f"{idx}. {item.vulnerability_type}", border_style=style))
    if len(findings) > limit:
        console.print(f"[dim]+{len(findings)-limit} achados de subdomínio omitidos na visualização detalhada[/dim]")
