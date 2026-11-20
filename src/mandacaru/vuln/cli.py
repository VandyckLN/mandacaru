"""Subcomando `mandacaru vuln ...`: auditoria local de CVEs via OSV.dev e CISA KEV."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from ..config import load_config
from ..events import Severity
from .inventory import detect_ecosystem, find_running_packages, parse_dpkg_status
from .kev_cache import DEFAULT_KEV_DB, KevCache
from .osv_client import DEFAULT_OSV_DB, OsvClient
from .scorer import ScoredVulnerability, classify_finding, finding_to_alert


def add_parser(sub) -> None:
    p = sub.add_parser("vuln", help="auditoria local de vulnerabilidades (CVE/CVSS)")
    vs = p.add_subparsers(dest="vcmd", required=True)
    sc = vs.add_parser("scan", help="cruza pacotes instalados com OSV.dev e CISA KEV")
    sc.add_argument("--status-file", default="/var/lib/dpkg/status", help="arquivo dpkg/status")
    sc.add_argument("--ecosystem", default=None, help="ecossistema OSV (ex.: Debian:12, Ubuntu:24.04)")
    sc.add_argument("--cache-dir", default=None, help="pasta do cache SQLite")
    sc.add_argument("--json", dest="as_json", action="store_true", help="saida JSON em stdout")
    sc.add_argument("--emit-alerts", action="store_true", help="grava alertas criticos/altos em alerts.jsonl")
    sc.add_argument("--no-kev", action="store_true", help="nao enriquece com CISA KEV")
    sc.add_argument("--no-running", action="store_true", help="nao correlaciona com /proc")
    p.set_defaults(fn=cmd_vuln)


def run_vuln_scan(
    *,
    status_path: Path,
    ecosystem: str | None,
    cache_dir: Path | None,
    ttl_hours: int = 24,
    kev_enabled: bool = True,
    correlate_running: bool = True,
    alert_min_cvss: float = 7.0,
    osv_client: OsvClient | None = None,
    kev_cache: KevCache | None = None,
) -> list[ScoredVulnerability]:
    eco = ecosystem or detect_ecosystem()
    packages = parse_dpkg_status(status_path=status_path, ecosystem=eco)
    if not packages:
        return []

    osv_db = (cache_dir / "osv.db") if cache_dir else DEFAULT_OSV_DB
    kev_db = (cache_dir / "kev.db") if cache_dir else DEFAULT_KEV_DB

    client = osv_client or OsvClient(cache_db=osv_db, ttl_hours=ttl_hours)
    raw_findings = client.query_packages(packages)

    kev_cves = (kev_cache or KevCache(cache_db=kev_db, ttl_hours=ttl_hours)).get_cves() if kev_enabled else set()
    running = find_running_packages(packages) if correlate_running else set()

    scored: list[ScoredVulnerability] = []
    for pkg, vulns in raw_findings.items():
        for vuln in vulns:
            scored.append(
                classify_finding(
                    vuln_payload=vuln,
                    package_name=pkg.source_name,
                    version=pkg.version,
                    kev_cves=kev_cves,
                    running_packages=running,
                    alert_min_cvss=alert_min_cvss,
                )
            )

    order = {"CRITICAL_ACTIVE": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    scored.sort(key=lambda f: (order.get(f.priority, 9), -f.cvss_score, f.package))
    return scored


def cmd_vuln(args) -> int:
    cfg = load_config(args.config)
    if not cfg.vuln_enabled:
        print("[mandacaru] scanner de vulnerabilidades desligado na configuracao", file=sys.stderr)
        return 0

    cache_dir = Path(args.cache_dir) if args.cache_dir else None
    try:
        findings = run_vuln_scan(
            status_path=Path(args.status_file),
            ecosystem=args.ecosystem,
            cache_dir=cache_dir,
            ttl_hours=cfg.vuln_cache_ttl_hours,
            kev_enabled=cfg.vuln_kev_enrichment and not args.no_kev,
            correlate_running=cfg.vuln_correlate_running_procs and not args.no_running,
            alert_min_cvss=cfg.vuln_alert_min_cvss,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"mandacaru: erro no scanner de vulnerabilidades: {exc}", file=sys.stderr)
        return 1

    if args.as_json:
        print(json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2))
    else:
        for f in findings:
            cves = ",".join(f.cve_ids) if f.cve_ids else f.vuln_id
            flags = " ".join(x for x in ("KEV" if f.in_kev else "", "ACTIVE" if f.is_running else "") if x)
            print(f"[{f.priority:15}] CVSS {f.cvss_score:4.1f}  {f.package} ({f.version})  {cves}  {flags}".rstrip())
        print(f"{len(findings)} vulnerabilidade(s) encontrada(s).", file=sys.stderr)

    if args.emit_alerts and cfg.json_path:
        alerts = [finding_to_alert(f) for f in findings]
        emitted = [a for a in alerts if a.severity >= Severity.HIGH]
        if emitted:
            try:
                with open(cfg.json_path, "a", encoding="utf-8") as fh:
                    for alert in emitted:
                        fh.write(alert.to_json() + "\n")
            except OSError as exc:
                print(f"mandacaru: aviso: nao foi possivel gravar alertas em {cfg.json_path}: {exc}", file=sys.stderr)

    return 2 if any(f.priority in ("CRITICAL_ACTIVE", "HIGH") for f in findings) else 0
