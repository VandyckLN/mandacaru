"""Motor: recebe eventos dos coletores, passa pelos detectores e emite alertas."""
from __future__ import annotations

import os
import queue
import sys
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Callable, TextIO

from .detectors.behavior import BehaviorEngine
from .detectors.static import SCRIPT_EXT, StaticScanner
from .events import Alert, Event, Severity

if TYPE_CHECKING:
    from .quarantine import Case, IsolateResult, Quarantine

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


def _resolve(path) -> Path:
    """resolve() que nao levanta: laco de symlink (RuntimeError no Python 3.10-3.12) fica com o caminho lexico,
    e a quarentena recusa depois com caminho_com_symlink."""
    try:
        return Path(path).resolve(strict=False)
    except (RuntimeError, OSError):
        return Path(os.path.abspath(path))


class Engine:
    def __init__(self, sinks: list[AlertSink], scanner: StaticScanner | None = None,
                 behavior: BehaviorEngine | None = None, scan_new_files: bool = True,
                 quarantine: Quarantine | None = None, quarantine_min_severity: Severity = Severity.HIGH,
                 watch_paths: Sequence[str] = (),
                 on_isolated: Callable[[Case, list[Alert]], None] | None = None):
        self.q: queue.Queue[Event] = queue.Queue(maxsize=50_000)
        self.sinks = sinks
        self.scanner = scanner or StaticScanner()
        self.behavior = behavior or BehaviorEngine()
        self.scan_new_files = scan_new_files
        self._stop = threading.Event()
        self._recent: dict[tuple, float] = {}
        self.dedup_seconds = 30.0
        self.writing_debounce = 2.0
        self._writing: dict[str, float] = {}  # caminho -> ultima tentativa que parou em em_escrita
        self._dropped: set[str] = set()  # caminhos com file_write descartado pelo debounce (borda final)
        self.quarantine = quarantine
        self.quarantine_min_severity = quarantine_min_severity
        self.watch_paths = [_resolve(p) for p in watch_paths]
        self.on_isolated = on_isolated  # ex.: telemetria enfileira o caso recem-aberto

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
        p = _resolve(path)
        return any(p.is_relative_to(w) for w in self.watch_paths)

    def _quarantine(self, found: list[Alert]) -> None:
        """Isola os arquivos dos alertas do scanner que qualificam e anota o resultado em cada alerta."""
        if self.quarantine is None:
            return
        results: dict[str, IsolateResult] = {}  # um isolate por caminho: os alertas do arquivo dividem o caso
        for a in found:
            p = a.evidence.get("path")
            # alerta do classificador de IA so isola com ml_isolate (faixa, modo e portao decididos em ml.decision)
            if a.rule.startswith("ml.") and a.evidence.get("ml_isolate") is not True:
                continue
            if p and p not in results and a.severity >= self.quarantine_min_severity and self._watched(p):
                results[p] = self.quarantine.isolate(p, a)
                r = results[p]
                if r.status == "isolado" and r.case is not None and self.on_isolated is not None:
                    try:
                        self.on_isolated(r.case, [x for x in found if x.evidence.get("path") == p])
                    except Exception as exc:  # noqa: BLE001 - extra opcional nunca derruba o motor
                        print(f"[mandacaru] aviso: pos-isolamento falhou: {exc}", file=sys.stderr)
        # todos os alertas do arquivo herdam o resultado, inclusive os abaixo do min_severity
        for a in found:
            r = results.get(a.evidence.get("path"))
            if r is None:
                self._trust_ml(a)
                continue
            if r.reason == "em_escrita":
                self._writing.pop(a.evidence["path"], None)
                self._writing[a.evidence["path"]] = time.monotonic()
                while len(self._writing) > 10_000:  # descarta o mais antigo, nunca tudo
                    old = next(iter(self._writing))
                    del self._writing[old]
                    self._dropped.discard(old)
            else:
                self._writing.pop(a.evidence["path"], None)
                self._dropped.discard(a.evidence["path"])
            if r.status == "isolado":
                a.quarantine_id = r.case.id
                a.evidence["quarantine_id"] = r.case.id
            elif r.status == "confiavel":
                a.severity = Severity.INFO
                a.evidence["trusted"] = True
            else:
                a.evidence["quarantine"] = f"nao_isolado: {r.reason}"
                a.summary += f" (NAO isolado: {r.reason})"

    def _trust_ml(self, a: Alert) -> None:
        """Fora do isolamento (modo alert), alerta ml.* de hash da lista de confianca vira INFO, como nas regras."""
        sha = a.evidence.get("sha256")
        trust = getattr(self.quarantine, "trust", None)
        if a.rule.startswith("ml.") and sha and trust is not None and trust.contains(sha):
            a.severity = Severity.INFO
            a.evidence["trusted"] = True

    def _skip_file_event(self, ev: Event, path: str) -> bool:
        """Debounce do arquivo que parou em em_escrita: um IN_MODIFY por bloco de um download grande refaria a
        copia inteira. Dentro de writing_debounce s so o fechamento da escrita (data["closed"], IN_CLOSE_WRITE)
        tenta de novo, sem debounce. Um fechamento de arquivo que nao esta pendente ja foi tratado pelo
        IN_MODIFY que o precedeu e nao refaz a varredura."""
        pending = self._writing.get(path)
        if ev.data.get("closed"):
            self._writing.pop(path, None)
            return pending is None
        if pending is None or ev.kind != "file_write":
            return False
        if time.monotonic() - pending < self.writing_debounce:
            self._dropped.add(path)  # borda final: retry_dropped refaz quando a janela acabar
            return True
        del self._writing[path]
        self._dropped.discard(path)
        return False

    def retry_dropped(self) -> None:
        """Refaz a tentativa dos arquivos cujo ultimo file_write foi descartado pelo debounce e que nunca
        receberam fechamento (torrent, download pausado): chamado a cada volta do laco, sem timer por arquivo."""
        if not self._dropped:
            return
        now = time.monotonic()
        for path in [p for p in self._dropped if now - self._writing.get(p, 0.0) >= self.writing_debounce]:
            self._dropped.discard(path)
            if path in self._writing:
                self.process(Event("file_write", {"path": path}))

    def process(self, ev: Event) -> list[Alert]:
        # o fechamento (closed) repete um file_write ja contado: nao entra de novo na contagem de comportamento
        alerts = [] if ev.data.get("closed") else self.behavior.handle(ev)
        if self.scan_new_files and ev.kind in ("file_create", "file_write", "file_rename"):
            path = ev.data.get("dest") or ev.data.get("path")
            if path and self._skip_file_event(ev, path):
                path = None
            if path:
                found = self.scanner.scan_file(path)
                self._quarantine(found)
                alerts += found
        if ev.kind == "process_start":
            exe = ev.data.get("exe")
            if exe and Path(exe).suffix.lower() in SCRIPT_EXT:
                alerts += self.scanner.scan_file(exe)
            # scripts passados como argumento (python x.py, bash y.sh, powershell -File z.ps1, node z.mjs, ...)
            for arg in (ev.data.get("cmdline") or [])[1:4]:
                if Path(arg).suffix.lower() in SCRIPT_EXT:
                    alerts += self.scanner.scan_file(arg)
        return [a for a in alerts if self.emit(a, force=a.quarantine_id is not None)]

    def run(self):
        while not self._stop.is_set():
            try:
                ev = self.q.get(timeout=0.5)
            except queue.Empty:
                self._retry_safely()
                continue
            self._retry_safely()
            try:
                self.process(ev)
            except Exception as exc:  # um evento ruim nao derruba o agente
                print(f"[mandacaru] erro processando evento {ev.kind}: {exc}", file=sys.stderr)

    def _retry_safely(self):
        try:
            self.retry_dropped()
        except Exception as exc:
            print(f"[mandacaru] erro na nova tentativa de isolar: {exc}", file=sys.stderr)

    def stop(self):
        self._stop.set()
