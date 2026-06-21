from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Alert, EndpointFinding, SubdomainFinding


def save_json(path: str | Path, data: dict[str, Any]) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def alerts_to_dict(alerts: list[Alert]) -> list[dict[str, Any]]:
    return [a.to_dict() for a in alerts]


def alerts_to_structured(alerts: list[Alert]) -> list[dict[str, Any]]:
    return [a.to_structured() for a in alerts]



def endpoint_findings_to_dict(findings: list[EndpointFinding]) -> list[dict[str, Any]]:
    return [f.to_dict() for f in findings]


def endpoint_findings_to_structured(findings: list[EndpointFinding]) -> list[dict[str, Any]]:
    return [f.to_structured() for f in findings]



def subdomain_findings_to_dict(findings: list[SubdomainFinding]) -> list[dict[str, Any]]:
    return [f.to_dict() for f in findings]


def subdomain_findings_to_structured(findings: list[SubdomainFinding]) -> list[dict[str, Any]]:
    return [f.to_structured() for f in findings]
