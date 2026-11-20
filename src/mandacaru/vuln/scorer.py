"""Calculo local de Base Score CVSS v3.1 e priorizacao contextual para alertas do Mandacaru."""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass

from ..events import Alert, Severity

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_PRIORITY_TO_SEVERITY = {
    "CRITICAL_ACTIVE": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


# sem vetor CVSS, o Ubuntu (e outras distros) informa so uma prioridade textual
_DISTRO_PRIORITY = {"critical": "HIGH", "high": "HIGH", "important": "HIGH", "medium": "MEDIUM",
                    "moderate": "MEDIUM", "low": "LOW", "negligible": "LOW"}
_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
_ADVISORY_PREFIXES = ("USN-", "DSA-", "DLA-", "DTSA-")


def _roundup_cvss31(value: float) -> float:
    int_input = round(value * 100000)
    if (int_input % 10000) == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def parse_cvss31_base_score(vector: str) -> float | None:
    """Calcula o Base Score oficial de um vetor CVSS:3.1/... (ou 3.0) sem dependencias externas."""
    if not vector.startswith(("CVSS:3.1/", "CVSS:3.0/")):
        return None
    parts = dict(item.split(":", 1) for item in vector.split("/")[1:] if ":" in item)
    try:
        scope = parts["S"]
        av = _AV[parts["AV"]]
        ac = _AC[parts["AC"]]
        pr = (_PR_C if scope == "C" else _PR_U)[parts["PR"]]
        ui = _UI[parts["UI"]]
        c, i, a = _CIA[parts["C"]], _CIA[parts["I"]], _CIA[parts["A"]]
    except KeyError:
        return None

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    raw = (impact + exploitability) if scope == "U" else 1.08 * (impact + exploitability)
    return _roundup_cvss31(min(raw, 10.0))


@dataclass(frozen=True)
class ScoredVulnerability:
    vuln_id: str
    cve_ids: tuple[str, ...]
    package: str
    version: str
    cvss_score: float
    in_kev: bool
    is_running: bool
    priority: str  # CRITICAL_ACTIVE | HIGH | MEDIUM | LOW
    summary: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["cve_ids"] = list(self.cve_ids)
        return d


def classify_finding(
    vuln_payload: dict,
    package_name: str,
    version: str,
    kev_cves: set[str],
    running_packages: set[str],
    alert_min_cvss: float = 7.0,
) -> ScoredVulnerability:
    vuln_id = str(vuln_payload.get("id", "UNKNOWN"))
    # avisos de distro (DSA, USN, UBUNTU-CVE-...) trazem as CVEs em upstream/related, nao em aliases
    aliases: list[str] = []
    for field in ("aliases", "upstream", "related"):
        for a in vuln_payload.get(field) or []:
            a = str(a).removeprefix("UBUNTU-").removeprefix("DEBIAN-")
            if a.startswith("CVE-") and a not in aliases:
                aliases.append(a)
    if vuln_id.startswith("CVE-") and vuln_id not in aliases:
        aliases.insert(0, vuln_id)

    best_score = 0.0
    has_cvss = False
    distro_priority: str | None = None
    for sev in vuln_payload.get("severity", []):
        if not isinstance(sev, dict):
            continue
        score_raw = str(sev.get("score", ""))
        parsed = parse_cvss31_base_score(score_raw)
        if parsed is not None:
            best_score = max(best_score, parsed)
            has_cvss = True
        elif score_raw.lower() in _DISTRO_PRIORITY:
            level = _DISTRO_PRIORITY[score_raw.lower()]
            if distro_priority is None or _RANK[level] > _RANK[distro_priority]:
                distro_priority = level

    in_kev = any(cve.upper() in kev_cves for cve in aliases)
    is_running = package_name in running_packages

    if has_cvss:
        high = best_score >= alert_min_cvss
        base = "MEDIUM" if best_score >= 4.0 else "LOW"
    else:
        high = distro_priority == "HIGH"
        if distro_priority in ("MEDIUM", "LOW"):
            base = distro_priority
        elif vuln_id.startswith(_ADVISORY_PREFIXES):
            base = "MEDIUM"  # aviso de seguranca da distro sem nota: ha atualizacao de seguranca pendente
        else:
            base = "LOW"

    if (high or in_kev) and is_running:
        priority = "CRITICAL_ACTIVE"
    elif high or in_kev:
        priority = "HIGH"
    else:
        priority = base

    summary = str(vuln_payload.get("summary") or "")
    return ScoredVulnerability(
        vuln_id=vuln_id,
        cve_ids=tuple(aliases),
        package=package_name,
        version=version,
        cvss_score=best_score,
        in_kev=in_kev,
        is_running=is_running,
        priority=priority,
        summary=summary,
    )


def finding_to_alert(finding: ScoredVulnerability) -> Alert:
    """Converte uma vulnerabilidade pontuada no formato padrao de Alert do Mandacaru."""
    cves = ", ".join(finding.cve_ids) if finding.cve_ids else finding.vuln_id
    flags = []
    if finding.in_kev:
        flags.append("CISA KEV")
    if finding.is_running:
        flags.append("em execucao")
    flag_txt = f" [{', '.join(flags)}]" if flags else ""
    score = f"CVSS {finding.cvss_score:.1f}" if finding.cvss_score else "sem CVSS"
    return Alert(
        rule="vuln.cve_local",
        severity=_PRIORITY_TO_SEVERITY.get(finding.priority, Severity.LOW),
        summary=f"{finding.package} {finding.version}: {cves} ({score}){flag_txt}",
        evidence=finding.to_dict(),
        mitre=["T1190"] if finding.is_running else [],
    )


def drop_redundant_advisories(findings: list[ScoredVulnerability]) -> list[ScoredVulnerability]:
    """Tira avisos agregados (USN, DSA...) sem nota propria cujas CVEs ja aparecem, no mesmo pacote,
    em outro achado: a mesma falha nao entra duas vezes na contagem nem no popup."""
    covered: dict[str, set[str]] = {}
    for f in findings:
        if f.cvss_score or not _is_aggregate(f):
            covered.setdefault(f.package, set()).update(f.cve_ids)
    return [
        f for f in findings
        if not (_is_aggregate(f) and not f.cvss_score and f.cve_ids
                and set(f.cve_ids) <= covered.get(f.package, set()))
    ]


def _is_aggregate(f: ScoredVulnerability) -> bool:
    return len(f.cve_ids) != 1 or f.cve_ids[0] not in f.vuln_id
