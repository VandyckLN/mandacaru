"""Motor: recebe eventos dos coletores, passa pelos detectores e emite alertas."""
from __future__ import annotations

import queue
import sys
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Callable, TextIO

from .detectors.behavior import BehaviorEngine
from .detectors.static import StaticScanner
from .events import Alert, Event, Severity

if TYPE_CHECKING:
    from .quarantine import IsolateResult, Quarantine

AlertSink = Callable[[Alert], None]


def jsonl_sink(fh: TextIO) -> AlertSink:
    lock = threading.Lock()

    def _sink(a: Alert):
        with lock:
            fh.write(a.to_json() + "\n")
            fh.flush()
    return _sink


def console_sink(min_sev: Severity = Severity.LOW) -> AlertSink:
    colors = {Severity.LOW: "36", Severity.MEDIUM: "33", Severity.HIGH: "31", Severity.CRITICAL: "1;41"}

    def _sink(a: Alert):
        if a.severity < min_sev and not a.quarantine_id:
            return
        c = colors.get(a.severity, "0")
        print(f"\033[{c}m[{a.severity.name}]\033[0m {a.rule}: {a.summary}", file=sys.stderr)
    return _sink


class Engine:
    def __init__(self, sinks: list[AlertSink], scanner: StaticScanner | None = None,
                 behavior: BehaviorEngine | None = None, scan_new_files: bool = True,
                 quarantine: Quarantine | None = None, quarantine_min_severity: Severity = Severity.HIGH,
                 watch_paths: Sequence[str] = ()):
        self.q: queue.Queue[Event] = queue.Queue(maxsize=50_000)
        self.sinks = sinks
        self.scanner = scanner or StaticScanner()
        self.behavior = behavior or BehaviorEngine()
        self.scan_new_files = scan_new_files
        self._stop = threading.Event()
        self._recent: dict[tuple, float] = {}
        self.dedup_seconds = 30.0
        self.quarantine = quarantine
        self.quarantine_min_severity = quarantine_min_severity
        self.watch_paths = [Path(p).resolve(strict=False) for p in watch_paths]

    def emit(self, alert: Alert, force: bool = False) -> bool:
        """Entrega o alerta aos sinks. `force` pula o dedup (caso novo de quarentena sempre chega)."""
        # o mesmo arquivo costuma gerar create + modify em sequencia
        key = (alert.rule, alert.evidence.get("path"), alert.evidence.get("pid"))
        now = time.time()
        if not force and now - self._recent.get(key, 0) < self.dedup_seconds:
            return False
        self._recent[key] = now
        if len(self._recent) > 10_000:
            self._recent = {k: v for k, v in self._recent.items() if now - v < self.dedup_seconds}
        for s in self.sinks:
            s(alert)
        return True

    def _watched(self, path: str) -> bool:
        p = Path(path).resolve(strict=False)
        return any(p.is_relative_to(w) for w in self.watch_paths)

    def _quarantine(self, found: list[Alert]) -> None:
        """Isola os arquivos dos alertas do scanner que qualificam e anota o resultado em cada alerta."""
        if self.quarantine is None:
            return
        results: dict[str, IsolateResult] = {}  # um isolate por caminho: os alertas do arquivo dividem o caso
        for a in found:
            p = a.evidence.get("path")
            if p and p not in results and a.severity >= self.quarantine_min_severity and self._watched(p):
                results[p] = self.quarantine.isolate(p, a)
        # todos os alertas do arquivo herdam o resultado, inclusive os abaixo do min_severity
        for a in found:
            r = results.get(a.evidence.get("path"))
            if r is None:
                continue
            if r.status == "isolado":
                a.quarantine_id = r.case.id
                a.evidence["quarantine_id"] = r.case.id
            elif r.status == "confiavel":
                a.severity = Severity.INFO
                a.evidence["trusted"] = True
            else:
                a.evidence["quarantine"] = f"nao_isolado: {r.reason}"
                a.summary += f" (NAO isolado: {r.reason})"

    def process(self, ev: Event) -> list[Alert]:
        alerts = self.behavior.handle(ev)
        if self.scan_new_files and ev.kind in ("file_create", "file_write", "file_rename"):
            path = ev.data.get("dest") or ev.data.get("path")
            if path:
                found = self.scanner.scan_file(path)
                self._quarantine(found)
                alerts += found
        if ev.kind == "process_start":
            exe = ev.data.get("exe")
            if exe and Path(exe).suffix.lower() in {".py", ".ps1", ".sh", ".js", ".vbs", ".bat"}:
                alerts += self.scanner.scan_file(exe)
            # scripts passados como argumento (python x.py, bash y.sh, powershell -File z.ps1)
            for arg in (ev.data.get("cmdline") or [])[1:4]:
                if Path(arg).suffix.lower() in {".py", ".ps1", ".sh", ".js", ".vbs", ".bat"}:
                    alerts += self.scanner.scan_file(arg)
        return [a for a in alerts if self.emit(a, force=a.quarantine_id is not None)]

    def run(self):
        while not self._stop.is_set():
            try:
                ev = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.process(ev)
            except Exception as exc:  # um evento ruim nao derruba o agente
                print(f"[mandacaru] erro processando evento {ev.kind}: {exc}", file=sys.stderr)

    def stop(self):
        self._stop.set()
