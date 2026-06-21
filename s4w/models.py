from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Alert:
    title: str
    risk: str
    confidence: str
    evidence: str
    impact: str
    remediation: str
    tags: list[str] = field(default_factory=list)
    owasp: str | None = None
    cwe: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_structured(self) -> dict[str, Any]:
        return {
            "vulnerabilidade": self.title,
            "gravidade": risk_pt(self.risk),
            "impacto": self.impact,
            "remediacao": self.remediation,
            "referencias": self.references,
            "confianca": confidence_pt(self.confidence),
            "categoria_owasp": self.owasp or "Não classificado",
            "cwe": self.cwe,
            "evidencia": self.evidence,
            "tags": self.tags,
        }


@dataclass
class EndpointFinding:
    endpoint: str
    vulnerability: str
    risk: str
    impact: str
    remediation: str
    updated_score: int
    confidence: str = "Medium"
    evidence: str = ""
    priority: str = "Média"
    tags: list[str] = field(default_factory=list)
    owasp: str | None = None
    cwe: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_structured(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "vulnerabilidade": self.vulnerability,
            "gravidade": risk_pt(self.risk),
            "impacto": self.impact,
            "remediacao": self.remediation,
            "score_atualizado": self.updated_score,
            "confianca": confidence_pt(self.confidence),
            "evidencia": self.evidence,
            "prioridade": self.priority,
            "categoria_owasp": self.owasp or "Não classificado",
            "cwe": self.cwe,
            "referencias": self.references,
            "tags": self.tags,
        }



@dataclass
class SubdomainFinding:
    subdomain: str
    endpoint: str
    vulnerability_type: str
    risk: str
    description: str
    recommendation: str
    possible_exploitation: str
    recommended_fix: str
    cvss: float
    updated_score: int
    confidence: str = "Medium"
    evidence: str = ""
    owasp: str | None = None
    cwe: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_structured(self) -> dict[str, Any]:
        return {
            "subdominio": self.subdomain,
            "endpoint": self.endpoint,
            "tipo_vulnerabilidade": self.vulnerability_type,
            "gravidade": risk_pt(self.risk),
            "descricao": self.description,
            "recomendacoes_mitigacao": self.recommendation,
            "possivel_exploracao": self.possible_exploitation,
            "correcao_recomendada": self.recommended_fix,
            "score_cvss": self.cvss,
            "score_atualizado": self.updated_score,
            "confianca": confidence_pt(self.confidence),
            "evidencia": self.evidence,
            "categoria_owasp": self.owasp or "Não classificado",
            "cwe": self.cwe,
            "referencias": self.references,
        }

@dataclass
class ScanContext:
    original_target: str
    url: str
    scheme: str
    hostname: str
    registered_domain: str
    base_url: str
    started_at: str
    status_code: int | None = None
    final_url: str | None = None
    title: str | None = None
    server: str | None = None
    powered_by: str | None = None
    elapsed_ms: int | None = None


def risk_pt(value: str) -> str:
    return {
        "Critical": "Crítica",
        "High": "Alta",
        "Medium": "Média",
        "Low": "Baixa",
        "Informational": "Informativa",
    }.get(value, value)


def confidence_pt(value: str) -> str:
    return {
        "Critical": "Crítica",
        "High": "Alta",
        "Medium": "Média",
        "Low": "Baixa",
    }.get(value, value)
