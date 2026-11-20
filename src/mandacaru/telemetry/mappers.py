"""Mapeadores de eventos sanitizados do Mandacaru para MISP (CERT.br/CSIRTs) e MalwareBazaar."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .sanitizer import is_public_ip, sanitize_text


def build_misp_event(
    *,
    sha256: str,
    mime: str,
    size_bytes: int,
    yara_rules: list[str],
    mitre_techniques: list[str],
    cmdline: str = "",
    tlsh: str | None = None,
    dst_ips: list[str] | None = None,
    tlp: str = "tlp:clear",
    distribution: int = 0,  # 0 = Your org only (seguro por padrao) | 3 = All communities
) -> dict[str, Any]:
    """Gera payload pronto para POST /events/add na API REST do MISP."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    tags = [
        {"name": tlp.lower()},
        {"name": 'mandacaru:source="agent"'},
        {"name": "os:linux"},
    ]
    for tech in mitre_techniques:
        tags.append({"name": f'misp-galaxy:mitre-attack-pattern="{tech}"'})

    attributes: list[dict[str, Any]] = [
        {"type": "sha256", "category": "Payload delivery", "value": sha256.lower(), "to_ids": True},
        {"type": "mime-type", "category": "Artifacts dropped", "value": mime, "to_ids": False},
        {"type": "size-in-bytes", "category": "Other", "value": str(size_bytes), "to_ids": False},
    ]

    if tlsh:
        attributes.append(
            {"type": "tlsh", "category": "Payload delivery", "value": tlsh, "to_ids": True}
        )

    if cmdline:
        attributes.append(
            {
                "type": "text",
                "category": "Artifacts dropped",
                "value": sanitize_text(cmdline),
                "comment": "Sanitized execution command line",
                "to_ids": False,
            }
        )

    for ip in dst_ips or []:
        if is_public_ip(ip):
            attributes.append(
                {"type": "ip-dst", "category": "Network activity", "value": ip, "to_ids": True}
            )

    rule_summary = ", ".join(yara_rules) if yara_rules else "heuristic"
    return {
        "Event": {
            "date": today,
            "info": f"Mandacaru Linux Detection ({rule_summary})",
            "distribution": str(distribution),
            "threat_level_id": "2",  # 1=High, 2=Medium, 3=Low
            "analysis": "1",         # 0=Initial, 1=Ongoing, 2=Completed
            "Tag": tags,
            "Attribute": attributes,
        }
    }


def payload_to_misp_event(payload: dict[str, Any], *, distribution: int = 0) -> dict[str, Any]:
    """Converte um payload sanitizado da fila (outbox) diretamente para evento MISP."""
    ind = payload.get("indicator", {})
    det = payload.get("detection", {})
    dst_ips = [
        ioc["value"]
        for ioc in payload.get("network_iocs", [])
        if isinstance(ioc, dict) and ioc.get("type") == "ip-dst" and ioc.get("value")
    ]
    return build_misp_event(
        sha256=str(ind.get("sha256", "")),
        mime=str(ind.get("mime", "application/octet-stream")),
        size_bytes=int(ind.get("size_bytes", 0)),
        yara_rules=list(det.get("yara_rules", [])),
        mitre_techniques=list(det.get("mitre_attack", [])),
        cmdline=str(det.get("sanitized_cmdline", "")),
        tlsh=ind.get("tlsh"),
        dst_ips=dst_ips,
        tlp=str(payload.get("tlp", "TLP:CLEAR")).lower(),
        distribution=distribution,
    )


def build_malwarebazaar_metadata(payload: dict[str, Any]) -> dict[str, Any]:
    """Gera metadados normalizados para triagem/submissao via Threat Hub ao MalwareBazaar."""
    ind = payload.get("indicator", {})
    det = payload.get("detection", {})
    tags = ["linux", "mandacaru"]
    if ind.get("mime") == "application/x-elf":
        tags.append("elf")
    for tech in det.get("mitre_attack", []):
        tags.append(str(tech).lower())
    return {
        "sha256": str(ind.get("sha256", "")),
        "anonymous": 1,
        "tags": sorted(set(tags)),
        "context": {
            "yara_rules": list(det.get("yara_rules", [])),
            "tlp": str(payload.get("tlp", "TLP:CLEAR")),
        },
    }
