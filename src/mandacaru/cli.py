"""CLI: `mandacaru scan CAMINHO`, `mandacaru monitor` e `mandacaru quarentena ...`."""
from __future__ import annotations

import argparse
import json
import os
import queue
import signal
import sqlite3
import sys
import threading
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from . import __version__, ml
from .alert_socket import socket_sink
from .collectors import ebpf
from .collectors.fsmon import FileMonitor
from .collectors.procmon import ProcessMonitor
from .config import DEFAULT_PATH, Config, ConfigError, load_config
from .decisions import DEFAULT_LOG, DecisionLog
from .detectors.static import StaticScanner
from .engine import AlertSink, Engine, console_sink, jsonl_sink
from .events import Alert, Severity
from .ml.cli import add_parser as add_ml_parser
from .quarantine import DEFAULT_DIR, DEFAULT_TRUST, Quarantine, TrustList
from .quarantine_cli import add_parser as add_quarantine_parser
from .telemetry.cli import add_parser as add_telemetry_parser
from .telemetry.outbox import DEFAULT_OUTBOX_DB, TelemetryOutbox
from .telemetry.producer import make_enqueuer
from .vuln.cli import add_parser as add_vuln_parser
from .vuln.publish import VulnReportPublisher


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
    elif args.cmd == "scan":
        # o json do arquivo e o log do servico (so root grava); scan avulso so grava com --json
        changes["json_path"] = None
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


def resolve_watch_paths(paths: list[str]) -> list[str]:
    """Avisa de cada pasta que nao existe; sem nenhuma, o monitor nao protegeria nada."""
    existing = [p for p in paths if Path(p).is_dir()]
    for p in paths:
        if p not in existing:
            print(f"[mandacaru] aviso: pasta vigiada nao existe: {p}", file=sys.stderr)
    if not existing:
        raise CliError("nenhuma pasta vigiada existe; confira [monitor] paths")
    return existing


def open_alert_log(path: str):
    try:
        return open(path, "a", encoding="utf-8")
    except OSError as exc:
        raise CliError(f"nao foi possivel gravar alertas em {path}: {exc.strerror or exc}") from exc


def effective_ml_mode(cfg: Config, *, for_scan: bool = False) -> str:
    """No scan avulso: shadow vira off (o registro e do monitor) e isolate vira alert (scan nunca isola)."""
    if not cfg.ml_enabled:
        return "off"
    if for_scan:
        return {"shadow": "off", "isolate": "alert"}.get(cfg.ml_mode, cfg.ml_mode)
    return cfg.ml_mode


def build_classifier(cfg: Config, *, for_scan: bool) -> tuple[ml.Classifier | None, Alert | None]:
    """(classificador, alerta ml.modelo_invalido). Sem modelo ou modo off, o resto segue igual."""
    mode = effective_ml_mode(cfg, for_scan=for_scan)
    if mode == "off":
        return None, None
    result = ml.load_default(mode)
    if result.classifier is not None:
        return result.classifier, None
    if for_scan:
        return None, None
    if result.invalid:
        return None, Alert("ml.modelo_invalido", Severity.HIGH, f"Classificador de IA desligado: {result.problem}",
                           {"problema": result.problem})
    print(f"[mandacaru] classificador de IA desligado: {result.problem}", file=sys.stderr)
    return None, None


def shadow_writer(path: str) -> Callable[[dict], None] | None:
    """Grava o modo sombra em JSON Lines (0640). Sem permissao, avisa e o modo sombra so nao registra."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o640)
        os.fchmod(fd, 0o640)
    except OSError as exc:
        print(f"[mandacaru] aviso: modo sombra sem registro ({path}: {exc.strerror or exc})", file=sys.stderr)
        return None
    fh = os.fdopen(fd, "a", encoding="utf-8")
    lock = threading.Lock()

    def _write(record: dict) -> None:
        with lock:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            fh.flush()
    return _write


def cmd_scan(args) -> int:
    cfg = effective_config(args)
    clf, _ = build_classifier(cfg, for_scan=True)
    scanner = StaticScanner(cfg.rule_dirs, cfg.exclude, classifier=clf)
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


def build_sinks(cfg: Config) -> tuple[list[AlertSink], list[Callable[[], None]]]:
    """Sinks do monitor (console, jsonl, socket) e as funcoes que os encerram."""
    sinks: list[AlertSink] = [console_sink(cfg.min_severity)]
    stops: list[Callable[[], None]] = []
    if cfg.json_path:
        sinks.append(jsonl_sink(open_alert_log(cfg.json_path)))
    if cfg.socket_path:
        try:
            sink, stop = socket_sink(cfg.socket_path, cfg.min_severity)
        except OSError as exc:
            # sem socket o EDR continua protegendo; so ninguem e avisado em tempo real
            print(f"[mandacaru] socket de alertas desligado: {exc}", file=sys.stderr)
        else:
            sinks.append(sink)
            stops.append(stop)
            print(f"[mandacaru] alertas em tempo real: {cfg.socket_path}", file=sys.stderr)
    return sinks, stops


def build_quarantine(cfg: Config, root: str = DEFAULT_DIR, log_path: str = DEFAULT_LOG,
                     trust_path: str = DEFAULT_TRUST) -> Quarantine | None:
    """Quarentena do monitor, ou None se desligada no config ou sem diretorio gravavel."""
    if not cfg.quarantine:
        return None
    if not os.path.isdir(root):
        motivo = f"{root} nao existe"
    elif not os.access(root, os.W_OK):
        motivo = f"sem permissao de escrita em {root}"
    else:
        mb = 1024 * 1024
        return Quarantine(root, DecisionLog(log_path), TrustList(trust_path), retention_days=cfg.retention_days,
                          max_file_bytes=cfg.max_file_mb * mb, max_total_bytes=cfg.max_total_mb * mb)
    # sem quarentena o EDR continua alertando; so nao isola
    print(f"[mandacaru] quarentena desligada: {motivo}", file=sys.stderr)
    return None


def build_telemetry_hook(cfg: Config, quarantine: Quarantine | None = None):
    """Com telemetria ligada, cada caso isolado entra na fila local (envio so depois de aprovado)."""
    if cfg.telemetry_level == "off":
        return None
    try:
        outbox = TelemetryOutbox(DEFAULT_OUTBOX_DB)
    except (OSError, sqlite3.Error) as exc:
        print(f"[mandacaru] telemetria desligada: fila indisponivel ({exc})", file=sys.stderr)
        return None
    print(f"[mandacaru] telemetria: casos isolados vao para {DEFAULT_OUTBOX_DB}", file=sys.stderr)
    return make_enqueuer(cfg, outbox, quarantine)


def cmd_monitor(args) -> int:
    cfg = effective_config(args)
    paths = resolve_watch_paths(list(cfg.watch_paths) or default_watch_paths())
    sinks, sink_stops = build_sinks(cfg)
    quarantine = build_quarantine(cfg)
    if quarantine is not None:
        print(f"[mandacaru] quarentena: {quarantine.root}", file=sys.stderr)
    clf, ml_alert = build_classifier(cfg, for_scan=False)
    if clf is not None:
        ids = ", ".join(m.model_id for m in clf.models.values())
        print(f"[mandacaru] classificador de IA: modo {clf.mode}, modelos: {ids}", file=sys.stderr)
    shadow = shadow_writer(ml.SHADOW_LOG) if clf is not None and clf.mode == "shadow" else None
    if ml_alert is not None:
        for s in sinks:
            s(ml_alert)
    engine = Engine(sinks, scanner=StaticScanner(cfg.rule_dirs, cfg.exclude, classifier=clf, shadow_sink=shadow),
                    quarantine=quarantine,
                    quarantine_min_severity=cfg.quarantine_min_severity, watch_paths=paths,
                    on_isolated=build_telemetry_hook(cfg, quarantine))

    kind, stop_procs = start_process_collector(engine.q, cfg.ebpf)
    stoppers = [stop_procs]
    print(f"[mandacaru] processos: {'eBPF (kernel)' if kind == 'ebpf' else 'psutil (polling)'}", file=sys.stderr)
    fm = FileMonitor(paths, engine.q)
    fm.start()
    stoppers.append(fm.stop)
    print(f"[mandacaru] vigiando arquivos em: {', '.join(paths)}", file=sys.stderr)

    done = threading.Event()
    if cfg.vuln_enabled:
        # achados do scan diario de CVEs (servico mandacaru-vuln-scan) entram nos mesmos sinks
        publisher = VulnReportPublisher(lambda a: [s(a) for s in sinks])
        threading.Thread(target=publisher.run, args=(done,), daemon=True).start()
    signal.signal(signal.SIGINT, lambda *_: done.set())
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: done.set())
    t = threading.Thread(target=engine.run, daemon=True)
    t.start()
    done.wait()
    for s in stoppers:
        s()
    engine.stop()
    for s in sink_stops:  # o socket fecha depois dos coletores
        s()
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
    add_quarantine_parser(sub)
    add_vuln_parser(sub)
    add_telemetry_parser(sub)
    add_ml_parser(sub)
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
