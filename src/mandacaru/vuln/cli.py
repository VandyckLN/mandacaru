"""Subcomando `mandacaru vuln ...`: auditoria local de CVEs via OSV.dev e CISA KEV."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from ..config import load_config
from ..events import Severity
from ..fsutil import atomic_write_text
from .inventory import (
    detect_ecosystem,
    find_running_packages,
    load_running_snapshot,
    parse_dpkg_status,
    write_running_snapshot,
)
from .kev_cache import DEFAULT_KEV_DB, KevCache
from .osv_client import DEFAULT_OSV_DB, OsvClient
from .scorer import ScoredVulnerability, classify_finding, drop_redundant_advisories, finding_to_alert


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
    sc.add_argument("--running-file", default=None,
                    help="usa o snapshot de `vuln snapshot-running` em vez de ler o /proc")
    sc.add_argument("--alerts-file", default=None, help="destino do --emit-alerts (padrao: [alerts] json)")
    sc.add_argument("--report", default=None, help="grava o resultado completo em JSON neste arquivo (sobrescreve)")
    sn = vs.add_parser("snapshot-running",
                       help="grava os pacotes em execucao (rodar como root; o scan sem privilegio le o arquivo)")
    sn.add_argument("--status-file", default="/var/lib/dpkg/status", help="arquivo dpkg/status")
    sn.add_argument("--output", required=True, help="arquivo JSON de saida")
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
    running: set[str] | None = None,
) -> list[ScoredVulnerability]:
    """`running` pronto (snapshot feito como root) dispensa a leitura do /proc."""
    eco = ecosystem or detect_ecosystem()
    packages = parse_dpkg_status(status_path=status_path, ecosystem=eco)
    if not packages:
        return []

    osv_db = (cache_dir / "osv.db") if cache_dir else DEFAULT_OSV_DB
    kev_db = (cache_dir / "kev.db") if cache_dir else DEFAULT_KEV_DB

    client = osv_client or OsvClient(cache_db=osv_db, ttl_hours=ttl_hours)
    raw_findings = client.query_packages(packages)
    if client.errors:
        print(f"mandacaru: aviso: {len(client.errors)} vulnerabilidade(s) sem detalhes (rede e cache falharam); "
              f"ex.: {client.errors[0]}", file=sys.stderr)

    kev_cves = (kev_cache or KevCache(cache_db=kev_db, ttl_hours=ttl_hours)).get_cves() if kev_enabled else set()
    if not correlate_running:
        running = set()
    elif running is None:
        running = find_running_packages(packages)

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

    scored = drop_redundant_advisories(scored)
    order = {"CRITICAL_ACTIVE": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    scored.sort(key=lambda f: (order.get(f.priority, 9), -f.cvss_score, f.package))
    return scored


def cmd_vuln(args) -> int:
    cfg = load_config(args.config)
    if not cfg.vuln_enabled:
        print("[mandacaru] scanner de vulnerabilidades desligado na configuracao", file=sys.stderr)
        return 0
    if args.vcmd == "snapshot-running":
        return _cmd_snapshot(args, cfg)

    cache_dir = Path(args.cache_dir) if args.cache_dir else None
    running = None
    if args.running_file and cfg.vuln_correlate_running_procs and not args.no_running:
        try:
            running = load_running_snapshot(Path(args.running_file))
        except (OSError, ValueError) as exc:
            print(f"mandacaru: aviso: snapshot de processos ilegivel ({exc}); sem correlacao com processos",
                  file=sys.stderr)
            running = set()
    try:
        findings = run_vuln_scan(
            status_path=Path(args.status_file),
            ecosystem=args.ecosystem,
            cache_dir=cache_dir,
            ttl_hours=cfg.vuln_cache_ttl_hours,
            kev_enabled=cfg.vuln_kev_enrichment and not args.no_kev,
            correlate_running=cfg.vuln_correlate_running_procs and not args.no_running,
            alert_min_cvss=cfg.vuln_alert_min_cvss,
            running=running,
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
            score = f"CVSS {f.cvss_score:4.1f}" if f.cvss_score else "sem CVSS"
            print(f"[{f.priority:15}] {score:9}  {f.package} ({f.version})  {cves}  {flags}".rstrip())
        print(f"{len(findings)} vulnerabilidade(s) encontrada(s).", file=sys.stderr)

    if args.report:
        try:
            atomic_write_text(Path(args.report),
                              json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2),
                              mode=0o640)
        except OSError as exc:
            print(f"mandacaru: erro: nao foi possivel gravar o relatorio em {args.report}: {exc}", file=sys.stderr)
            return 1

    alerts_path = args.alerts_file or cfg.json_path
    if args.emit_alerts and alerts_path:
        alerts = [finding_to_alert(f) for f in findings]
        emitted = [a for a in alerts if a.severity >= Severity.HIGH]
        if emitted:
            try:
                with open(alerts_path, "a", encoding="utf-8") as fh:
                    for alert in emitted:
                        fh.write(alert.to_json() + "\n")
            except OSError as exc:
                print(f"mandacaru: aviso: nao foi possivel gravar alertas em {alerts_path}: {exc}", file=sys.stderr)

    return 2 if any(f.priority in ("CRITICAL_ACTIVE", "HIGH") for f in findings) else 0


def _cmd_snapshot(args, cfg) -> int:
    running: set[str] = set()
    if cfg.vuln_correlate_running_procs:
        try:
            packages = parse_dpkg_status(status_path=Path(args.status_file), ecosystem="-")
        except OSError as exc:
            print(f"mandacaru: erro: nao foi possivel ler {args.status_file}: {exc}", file=sys.stderr)
            return 1
        running = find_running_packages(packages)
    try:
        write_running_snapshot(running, Path(args.output))
    except OSError as exc:
        print(f"mandacaru: erro: nao foi possivel gravar {args.output}: {exc}", file=sys.stderr)
        return 1
    print(f"{len(running)} pacote(s) em execucao.", file=sys.stderr)
    return 0
