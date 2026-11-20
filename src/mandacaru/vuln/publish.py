"""Leva os achados do scan de CVEs (usuario sem privilegio) aos sinks do monitor: alerts.jsonl e socket.

O scan grava o relatorio na pasta do _mandacaru-net; o monitor (root) le esse arquivo sem seguir symlink e
com limite de tamanho, e so alerta o que e novo desde a ultima leitura, para o popup nao repetir a lista
inteira todo dia.
"""
from __future__ import annotations

import json
import os
import stat
import sys
import threading
from pathlib import Path
from typing import Callable

from ..events import Alert, Severity
from ..fsutil import atomic_write_text, read_text_nofollow
from .scorer import ScoredVulnerability, finding_to_alert

DEFAULT_REPORT = Path("/var/lib/mandacaru/vuln_cache/last-scan.json")
DEFAULT_SEEN = Path("/var/lib/mandacaru/vuln_seen.json")
MAX_REPORT_BYTES = 32 * 1024 * 1024
ALERT_PRIORITIES = ("CRITICAL_ACTIVE", "HIGH")
MAX_INDIVIDUAL = 5  # acima disso, um alerta-resumo em vez de uma rajada de popups


def _finding(d: object) -> ScoredVulnerability | None:
    if not isinstance(d, dict):
        return None
    try:
        return ScoredVulnerability(
            vuln_id=str(d["vuln_id"]),
            cve_ids=tuple(str(c) for c in d.get("cve_ids", [])),
            package=str(d["package"]),
            version=str(d["version"]),
            cvss_score=float(d.get("cvss_score", 0.0)),
            in_kev=d.get("in_kev") is True,
            is_running=d.get("is_running") is True,
            priority=str(d["priority"]),
            summary=str(d.get("summary", "")),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _key(f: ScoredVulnerability) -> str:
    return f"{f.vuln_id}|{f.package}|{f.version}"


class VulnReportPublisher:
    def __init__(self, emit: Callable[[Alert], object], report: Path = DEFAULT_REPORT,
                 seen_path: Path = DEFAULT_SEEN) -> None:
        self.emit = emit
        self.report = Path(report)
        self.seen_path = Path(seen_path)
        self._last_sig: tuple[int, int] | None = None

    def _load_seen(self) -> set[str]:
        try:
            data = json.loads(self.seen_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return set()
        return {k for k in data.get("seen", [])} if isinstance(data, dict) else set()

    def poll(self) -> int:
        """Le o relatorio se mudou desde a ultima chamada; devolve quantos alertas emitiu."""
        try:
            st = os.lstat(self.report)
        except FileNotFoundError:
            return 0
        if not stat.S_ISREG(st.st_mode):
            return 0
        sig = (st.st_mtime_ns, st.st_size)
        if sig == self._last_sig:
            return 0
        try:
            data = json.loads(read_text_nofollow(self.report, MAX_REPORT_BYTES))
        except (OSError, ValueError) as exc:
            print(f"[mandacaru] aviso: relatorio de CVEs ilegivel ({exc})", file=sys.stderr)
            return 0
        self._last_sig = sig
        if not isinstance(data, list):
            return 0

        current = [f for f in map(_finding, data) if f is not None and f.priority in ALERT_PRIORITIES]
        seen = self._load_seen()
        new = [f for f in current if _key(f) not in seen]
        # CRITICAL_ACTIVE primeiro, depois maior CVSS
        new.sort(key=lambda f: (f.priority != "CRITICAL_ACTIVE", -f.cvss_score, f.package))

        for f in new[:MAX_INDIVIDUAL]:
            self.emit(finding_to_alert(f))
        rest = new[MAX_INDIVIDUAL:]
        if rest:
            crit = sum(1 for f in rest if f.priority == "CRITICAL_ACTIVE")
            self.emit(Alert(
                rule="vuln.cve_local_resumo",
                severity=Severity.CRITICAL if crit else Severity.HIGH,
                summary=f"mais {len(rest)} vulnerabilidade(s) alta(s) em pacotes instalados"
                        f"{f' ({crit} em execucao)' if crit else ''}; veja `mandacaru vuln scan`",
                evidence={"count": len(rest), "pacotes": sorted({f.package for f in rest})[:50]},
            ))

        # so o que esta no relatorio atual: CVE corrigida sai da lista e, se voltar, alerta de novo
        try:
            atomic_write_text(self.seen_path, json.dumps({"v": 1, "seen": sorted(_key(f) for f in current)}),
                              mode=0o640)
        except OSError as exc:
            print(f"[mandacaru] aviso: nao foi possivel gravar {self.seen_path}: {exc}", file=sys.stderr)
        return min(len(new), MAX_INDIVIDUAL) + (1 if rest else 0)

    def run(self, stop: threading.Event, interval: float = 60.0) -> None:
        while not stop.is_set():
            try:
                self.poll()
            except Exception as exc:  # noqa: BLE001 - nunca derruba o monitor
                print(f"[mandacaru] aviso: publicacao de CVEs falhou: {exc}", file=sys.stderr)
            stop.wait(interval)
