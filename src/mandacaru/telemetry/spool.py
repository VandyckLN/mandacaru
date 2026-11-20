"""Troca de arquivos entre root (dono da fila) e _mandacaru-net (unico com rede).

1. `export` (root): copia os itens APPROVED para <spool>/batch.json.
2. `send` (_mandacaru-net): envia o lote e grava <spool>/results.json.
3. `import` (root): aplica os resultados na fila e limpa o spool.

O spool pertence ao usuario de rede, entao root escreve sem seguir symlink e le com limite de tamanho;
um results.json forjado so consegue marcar como SENT/FAILED itens que ja estavam APPROVED.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from ..fsutil import atomic_write_text, read_text_nofollow
from .dispatcher import DispatchResult, TelemetryDispatcher
from .outbox import TelemetryOutbox

BATCH = "batch.json"
RESULTS = "results.json"
MAX_SPOOL_BYTES = 16 * 1024 * 1024


def _unlink_quiet(path: Path) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def export_batch(dispatcher: TelemetryDispatcher, spool: Path) -> int:
    items = dispatcher.outbox.list_items("APPROVED") if dispatcher.enabled() else []
    _unlink_quiet(spool / RESULTS)  # resultado velho nao pode ser aplicado a um lote novo
    batch = [{"id": i.id, "payload": i.payload, "sample_eligible": dispatcher.sample_eligible(i)} for i in items]
    atomic_write_text(spool / BATCH, json.dumps({"v": 1, "items": batch}, ensure_ascii=False), mode=0o644)
    return len(batch)


def send_batch(dispatcher: TelemetryDispatcher, spool: Path) -> DispatchResult:
    try:
        data = json.loads(read_text_nofollow(spool / BATCH, MAX_SPOOL_BYTES))
    except FileNotFoundError:
        return DispatchResult(sent=0, failed=0, skipped=0)
    items = data.get("items", []) if isinstance(data, dict) else []
    if not dispatcher.enabled():
        return DispatchResult(sent=0, failed=0, skipped=len(items))

    results = []
    sent = failed = 0
    for entry in items:
        if not isinstance(entry, dict) or type(entry.get("id")) is not int:
            continue
        if not isinstance(entry.get("payload"), dict):
            continue
        try:
            dispatcher.send(entry["payload"], bool(entry.get("sample_eligible")))
            results.append({"id": entry["id"], "ok": True})
            sent += 1
        except Exception as exc:  # noqa: BLE001
            results.append({"id": entry["id"], "ok": False, "error": str(exc)[:500]})
            failed += 1
    atomic_write_text(spool / RESULTS, json.dumps({"v": 1, "results": results}, ensure_ascii=False), mode=0o644)
    return DispatchResult(sent=sent, failed=failed, skipped=0)


def import_results(outbox: TelemetryOutbox, spool: Path) -> tuple[int, int]:
    try:
        data = json.loads(read_text_nofollow(spool / RESULTS, MAX_SPOOL_BYTES))
    except FileNotFoundError:
        return 0, 0
    sent = failed = 0
    for r in data.get("results", []) if isinstance(data, dict) else []:
        if not isinstance(r, dict) or type(r.get("id")) is not int:
            continue
        if r.get("ok") is True:
            sent += outbox.mark_sent(r["id"])
        else:
            failed += outbox.mark_failed(r["id"], str(r.get("error", "falha sem detalhe")))
    _unlink_quiet(spool / RESULTS)
    _unlink_quiet(spool / BATCH)
    return sent, failed
