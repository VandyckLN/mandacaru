"""Subcomando `mandacaru telemetry ...`: status, revisao local, aprovacao e envio."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from ..config import load_config
from .dispatcher import TelemetryDispatcher
from .outbox import DEFAULT_OUTBOX_DB, TelemetryOutbox
from .spool import export_batch, import_results, send_batch


def add_parser(sub) -> None:
    p = sub.add_parser("telemetry", help="telemetria comunitaria e exportacao MISP (opt-in)")
    p.add_argument("--outbox-db", default=str(DEFAULT_OUTBOX_DB), help="caminho do banco SQLite da fila")
    ts = p.add_subparsers(dest="tcmd", required=True)
    ts.add_parser("status", help="mostra configuracao atual de privacidade e contadores da fila")
    rv = ts.add_parser("review", help="exibe itens da fila para inspecao antes do envio")
    rv.add_argument("--status", default="PENDING", help="filtra por estado (PENDING, APPROVED, SENT, FAILED, ALL)")
    rv.add_argument("--json", dest="as_json", action="store_true", help="imprime JSON completo sanitizado")
    ts.add_parser("approve", help="aprova um item pendente para envio").add_argument("id", type=int)
    ts.add_parser("reject", help="rejeita e descarta um item pendente").add_argument("id", type=int)
    ts.add_parser("flush", help="envia itens aprovados para os destinos configurados")
    for name, help_ in (("export", "root: copia os itens aprovados para o spool"),
                        ("send", "usuario de rede: envia o lote do spool e grava os resultados"),
                        ("import", "root: aplica os resultados do spool na fila")):
        ts.add_parser(name, help=help_).add_argument("--spool", required=True, help="pasta de troca")
    p.set_defaults(fn=cmd_telemetry)


def cmd_telemetry(args) -> int:
    cfg = load_config(args.config)
    if args.tcmd == "send":
        # roda como _mandacaru-net: nao abre a fila (dono root), so o spool
        res = send_batch(TelemetryDispatcher(cfg, None), Path(args.spool))
        print(f"enviados={res.sent} falhas={res.failed} ignorados={res.skipped}")
        return 0  # falhas viajam no results.json; saida != 0 impediria o import (ExecStartPost)

    outbox = TelemetryOutbox(Path(args.outbox_db))

    if args.tcmd == "export":
        n = export_batch(TelemetryDispatcher(cfg, outbox), Path(args.spool))
        print(f"{n} item(ns) exportado(s) para envio.", file=sys.stderr)
        return 0

    if args.tcmd == "import":
        sent, failed = import_results(outbox, Path(args.spool))
        print(f"enviados={sent} falhas={failed}")
        return 0

    if args.tcmd == "status":
        items = outbox.list_items()
        states = ("PENDING", "APPROVED", "SENT", "FAILED", "REJECTED")
        counts = {s: sum(1 for i in items if i.status == s) for s in states}
        print(
            f"nivel: {cfg.telemetry_level} | "
            f"aprovacao manual: {cfg.telemetry_require_approval} | TLP: {cfg.telemetry_tlp}"
        )
        hub_st = "on" if cfg.telemetry_hub_enabled else "off"
        misp_st = "on" if cfg.telemetry_misp_enabled else "off"
        print(f"destinos: hub={hub_st}, misp={misp_st}")
        print("fila: " + ", ".join(f"{k.lower()}={v}" for k, v in counts.items()))
        return 0

    if args.tcmd == "review":
        status_filter = None if args.status.upper() == "ALL" else args.status.upper()
        items = outbox.list_items(status=status_filter)
        if args.as_json:
            print(
                json.dumps(
                    [{"id": i.id, "status": i.status, "sha256": i.sha256, "payload": i.payload} for i in items],
                    ensure_ascii=False,
                    indent=2,
                )
            )
        else:
            for i in items:
                rules = ",".join(i.payload.get("detection", {}).get("yara_rules", [])) or "heuristic"
                print(f"#{i.id} [{i.status}] {i.sha256[:16]}... rules={rules}")
            if not items:
                print("Nenhum item na fila.", file=sys.stderr)
        return 0

    if args.tcmd == "approve":
        if not outbox.approve(args.id):
            print(f"mandacaru: item #{args.id} nao encontrado ou nao esta PENDING/FAILED", file=sys.stderr)
            return 3
        print(f"Item #{args.id} aprovado para envio.")
        return 0

    if args.tcmd == "reject":
        if not outbox.reject(args.id):
            print(f"mandacaru: item #{args.id} nao encontrado ou ja enviado/rejeitado", file=sys.stderr)
            return 3
        print(f"Item #{args.id} rejeitado.")
        return 0

    if args.tcmd == "flush":
        dispatcher = TelemetryDispatcher(cfg, outbox)
        res = dispatcher.flush()
        print(f"enviados={res.sent} falhas={res.failed} ignorados={res.skipped}")
        return 0 if res.failed == 0 else 1

    return 1
