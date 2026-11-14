"""CLI: `mandacaru scan CAMINHO` e `mandacaru monitor`."""
from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
from pathlib import Path

from . import __version__
from .collectors import ebpf
from .collectors.fsmon import FileMonitor
from .collectors.procmon import ProcessMonitor
from .detectors.static import StaticScanner
from .engine import Engine, console_sink, jsonl_sink
from .events import Severity


def default_watch_paths() -> list[str]:
    home = Path.home()
    cands = [home / "Downloads", home / "Documents", home / "Documentos", home / "Desktop", home / "Área de Trabalho"]
    if os.name == "posix":
        cands += [Path("/tmp"), Path("/dev/shm")]
    return [str(p) for p in cands if p.exists()]


def cmd_scan(args) -> int:
    scanner = StaticScanner(args.rules)
    sink = console_sink(Severity[args.min_severity])
    out = jsonl_sink(open(args.json, "a", encoding="utf-8")) if args.json else None
    worst = Severity.INFO
    n = 0
    for path in args.paths:
        for a in scanner.scan_tree(path):
            n += 1
            worst = max(worst, a.severity)
            sink(a)
            if out:
                out(a)
    print(f"{n} alerta(s). Pior severidade: {worst.name}", file=sys.stderr)
    return 0 if worst < Severity.HIGH else 2


def cmd_monitor(args) -> int:
    sinks = [console_sink(Severity[args.min_severity])]
    if args.json:
        sinks.append(jsonl_sink(open(args.json, "a", encoding="utf-8")))
    engine = Engine(sinks, scanner=StaticScanner(args.rules))
    paths = args.paths or default_watch_paths()

    stoppers = []
    if ebpf.available() and not args.no_ebpf:
        tracer = ebpf.ExecTracer(engine.q); tracer.start(); stoppers.append(tracer.stop)
        print("[mandacaru] processos: eBPF (kernel)", file=sys.stderr)
    else:
        pm = ProcessMonitor(engine.q); pm.start(); stoppers.append(pm.stop)
        print("[mandacaru] processos: psutil (polling)", file=sys.stderr)
    fm = FileMonitor(paths, engine.q); fm.start(); stoppers.append(fm.stop)
    print(f"[mandacaru] vigiando arquivos em: {', '.join(paths) or '(nenhuma pasta)'}", file=sys.stderr)

    done = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: done.set())
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: done.set())
    t = threading.Thread(target=engine.run, daemon=True); t.start()
    done.wait()
    for s in stoppers:
        s()
    engine.stop()
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="mandacaru", description="Antivirus/EDR GPLv3 contra ataques conduzidos por IA")
    ap.add_argument("--version", action="version", version=__version__)
    ap.add_argument("--rules", action="append", default=[], help="pasta extra com regras .yar")
    ap.add_argument("--json", help="grava alertas em JSON Lines neste arquivo")
    ap.add_argument("--min-severity", default="LOW", choices=[s.name for s in Severity])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="varre arquivos/pastas")
    s.add_argument("paths", nargs="+")
    s.set_defaults(fn=cmd_scan)
    m = sub.add_parser("monitor", help="monitora processos e arquivos em tempo real")
    m.add_argument("paths", nargs="*", help="pastas a vigiar (padrao: Downloads, Documentos, /tmp...)")
    m.add_argument("--no-ebpf", action="store_true")
    m.set_defaults(fn=cmd_monitor)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
