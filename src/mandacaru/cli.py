"""CLI: `mandacaru scan CAMINHO` e `mandacaru monitor`."""
from __future__ import annotations

import argparse
import os
import queue
import signal
import sys
import threading
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from . import __version__
from .collectors import ebpf
from .collectors.fsmon import FileMonitor
from .collectors.procmon import ProcessMonitor
from .config import DEFAULT_PATH, Config, ConfigError, load_config
from .detectors.static import StaticScanner
from .engine import Engine, console_sink, jsonl_sink
from .events import Severity


class CliError(Exception):
    """Erro de uso que vira uma linha em stderr e saida 1, sem traceback."""


USER_DIRS = ("Downloads", "Documents", "Documentos", "Desktop", "Área de Trabalho")


def default_watch_paths(euid: int | None = None, home_root: Path = Path("/home")) -> list[str]:
    """Pastas vigiadas por padrao. Como root (servico), as de cada usuario em /home, nao /root."""
    if euid is None and hasattr(os, "geteuid"):
        euid = os.geteuid()
    if euid == 0:
        homes = sorted(h for h in home_root.iterdir() if h.is_dir()) if home_root.is_dir() else []
    else:
        homes = [Path.home()]
    cands = [h / d for h in homes for d in USER_DIRS]
    if os.name == "posix":
        cands += [Path("/tmp"), Path("/dev/shm")]
    return [str(p) for p in cands if p.exists()]


def effective_config(args: argparse.Namespace) -> Config:
    """Config final: flag da CLI > arquivo > padrao."""
    cfg = load_config(args.config)
    changes: dict = {}
    if args.rules:
        changes["rule_dirs"] = cfg.rule_dirs + tuple(args.rules)
    if args.json:
        changes["json_path"] = args.json
    if args.min_severity:
        changes["min_severity"] = Severity[args.min_severity]
    if args.cmd == "monitor":
        if args.paths:
            changes["watch_paths"] = tuple(args.paths)
        if args.no_ebpf:
            changes["ebpf"] = False
    cfg = replace(cfg, **changes)
    if cfg.json_path:
        # o proprio arquivo de alertas nao pode gerar novos alertas (laco no monitor)
        cfg = replace(cfg, exclude=cfg.exclude + (os.path.abspath(cfg.json_path),))
    return cfg


def open_alert_log(path: str):
    try:
        return open(path, "a", encoding="utf-8")
    except OSError as exc:
        raise CliError(f"nao foi possivel gravar alertas em {path}: {exc.strerror or exc}") from exc


def cmd_scan(args) -> int:
    cfg = effective_config(args)
    scanner = StaticScanner(cfg.rule_dirs, cfg.exclude)
    sink = console_sink(cfg.min_severity)
    out = jsonl_sink(open_alert_log(cfg.json_path)) if cfg.json_path else None
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


def start_process_collector(q: queue.Queue, use_ebpf: bool) -> tuple[str, Callable[[], None]]:
    """Inicia o coletor de processos; eBPF que falha ao subir cai para psutil em vez de derrubar o agente."""
    if use_ebpf and ebpf.available():
        try:
            tracer = ebpf.ExecTracer(q)
            tracer.start()
            return "ebpf", tracer.stop
        except Exception as exc:  # BCC falha de varias formas: sem headers, WSL, conteiner
            print(f"[mandacaru] eBPF indisponivel ({exc}); usando psutil", file=sys.stderr)
    pm = ProcessMonitor(q)
    pm.start()
    return "psutil", pm.stop


def cmd_monitor(args) -> int:
    cfg = effective_config(args)
    sinks = [console_sink(cfg.min_severity)]
    if cfg.json_path:
        sinks.append(jsonl_sink(open_alert_log(cfg.json_path)))
    engine = Engine(sinks, scanner=StaticScanner(cfg.rule_dirs, cfg.exclude))
    paths = list(cfg.watch_paths) or default_watch_paths()

    kind, stop_procs = start_process_collector(engine.q, cfg.ebpf)
    stoppers = [stop_procs]
    print(f"[mandacaru] processos: {'eBPF (kernel)' if kind == 'ebpf' else 'psutil (polling)'}", file=sys.stderr)
    fm = FileMonitor(paths, engine.q)
    fm.start()
    stoppers.append(fm.stop)
    print(f"[mandacaru] vigiando arquivos em: {', '.join(paths) or '(nenhuma pasta)'}", file=sys.stderr)

    done = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: done.set())
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: done.set())
    t = threading.Thread(target=engine.run, daemon=True)
    t.start()
    done.wait()
    for s in stoppers:
        s()
    engine.stop()
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="mandacaru", description="Antivirus/EDR GPLv3 contra ataques conduzidos por IA")
    ap.add_argument("--version", action="version", version=__version__)
    ap.add_argument("--config", help=f"arquivo de configuracao TOML (padrao: {DEFAULT_PATH}, se existir)")
    ap.add_argument("--rules", action="append", default=[], help="pasta extra com regras .yar")
    ap.add_argument("--json", help="grava alertas em JSON Lines neste arquivo")
    ap.add_argument("--min-severity", default=None, choices=[s.name for s in Severity])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="varre arquivos/pastas")
    s.add_argument("paths", nargs="+")
    s.set_defaults(fn=cmd_scan)
    m = sub.add_parser("monitor", help="monitora processos e arquivos em tempo real")
    m.add_argument("paths", nargs="*", help="pastas a vigiar (padrao: Downloads, Documentos, /tmp...)")
    m.add_argument("--no-ebpf", action="store_true")
    m.set_defaults(fn=cmd_monitor)
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (ConfigError, CliError) as exc:
        print(f"mandacaru: erro: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
