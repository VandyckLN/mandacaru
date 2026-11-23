"""Subcomando `mandacaru ml ...`: estado do classificador, avaliacao de arquivos e resumo do modo sombra."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from ..config import load_config
from . import SHADOW_LOG, load_default
from .decision import BANDS

MAX_BYTES = 8 * 1024 * 1024  # o mesmo limite do scanner estatico


def add_parser(sub) -> None:
    p = sub.add_parser("ml", help="classificador local de malware por IA")
    ms = p.add_subparsers(dest="mcmd", required=True)
    ms.add_parser("status", help="modelos instalados, tipos aprovados e modo")
    av = ms.add_parser("avaliar", help="nota, faixa e motivos de arquivos (nao isola)")
    av.add_argument("arquivos", nargs="*")
    av.add_argument("--json", dest="as_json", action="store_true", help="saida JSON (uma lista)")
    av.add_argument("--jsonl", action="store_true", help="um objeto JSON por linha (bom para listas grandes)")
    av.add_argument("--stdin", action="store_true",
                    help="le os caminhos da entrada padrao, separados por \\0 ou por linha (ex.: find -print0)")
    sb = ms.add_parser("sombra", help="resumo do que o modelo teria feito no modo sombra")
    sb.add_argument("--desde", default=None, help="so registros a partir desta data (AAAA-MM-DD)")
    sb.add_argument("--arquivo", default=None, help=f"registro do modo sombra (padrao: {SHADOW_LOG})")
    p.set_defaults(fn=cmd_ml)


def _load(args, mode: str):
    return load_default(mode, models_dir=getattr(args, "_models_dir", None), pinned=getattr(args, "_pinned", None))


def _status(args) -> int:
    cfg = load_config(args.config)
    mode = cfg.ml_mode if cfg.ml_enabled else "off"
    r = _load(args, "alert")
    print(f"modo: {mode}")
    if r.classifier is None:
        print(r.problem)
        return 4 if r.invalid else 0
    for fam, m in sorted(r.classifier.models.items()):
        tipos = ", ".join(f"{k} ({'aprovado' if p.gate_passed else 'reprovado: so alerta'})"
                          for k, p in sorted(m.kinds.items()))
        print(f"{fam}: {m.model_id} - {tipos}")
    return 0


def _safe_text(s: str) -> str:
    """Garante string UTF-8 valida para impressao/JSON, trocando bytes invalidos (surrogateescape) por U+FFFD."""
    return s.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def _caminhos(args) -> list[str]:
    caminhos = list(args.arquivos or [])
    if getattr(args, "stdin", False):
        if hasattr(sys.stdin, "buffer"):
            bruto = sys.stdin.buffer.read()
        else:
            bruto = sys.stdin.read().encode("utf-8", "surrogateescape")
        sep = b"\0" if b"\0" in bruto else b"\n"
        for item in bruto.split(sep):
            if sep == b"\n":
                item = item.rstrip(b"\r")
            if item.strip():
                caminhos.append(item.decode("utf-8", "surrogateescape"))
    return caminhos


def _avaliar_um(classifier, arquivo: str) -> tuple[dict, int]:
    """Avalia um unico arquivo e devolve (linha_resultado, codigo_saida)."""
    rotulo = _safe_text(arquivo)
    try:
        with open(arquivo, "rb") as fh:
            data = fh.read(MAX_BYTES)
    except OSError as exc:
        return {"path": rotulo, "erro": exc.strerror or str(exc)}, 0
    if len(data) >= MAX_BYTES:
        return {"path": rotulo, "nao_avaliado": "maior que 8 MB"}, 0
    v = classifier.score(data, path=str(Path(arquivo).resolve()))
    if v is None:
        return {"path": rotulo, "nao_avaliado": "tipo nao suportado"}, 0
    rc = 2 if v.band in ("alto", "reforco") else 0
    return {
        "path": rotulo, "band": v.band, "score": round(v.score, 4), "kind": v.kind,
        "model_id": v.model_id, "known_good": v.known_good,
        "motivos": [m.text for m in v.reasons[:3]],
    }, rc


def _imprimir_texto(row: dict) -> None:
    if "erro" in row:
        print(f"{row['path']}: erro ao ler ({row['erro']})")
    elif "nao_avaliado" in row:
        print(f"{row['path']}: nao avaliado ({row['nao_avaliado']})")
    else:
        extra = " [identico a arquivo de pacote instalado]" if row["known_good"] else ""
        motivos = "; ".join(row["motivos"]) or "-"
        print(f"{row['path']}: {row['band']} {round(row['score'] * 100)}% ({row['kind']}, {row['model_id']})"
              f" - {motivos}{extra}")


def _evaluate(args) -> int:
    as_json = bool(getattr(args, "as_json", False))
    as_jsonl = bool(getattr(args, "jsonl", False))
    if as_json and as_jsonl:
        print("mandacaru: use apenas --json ou --jsonl, nao ambos", file=sys.stderr)
        return 1
    caminhos = _caminhos(args)
    if not caminhos:
        print("mandacaru: informe arquivos ou use --stdin", file=sys.stderr)
        return 1
    r = _load(args, "alert")                       # carrega modelos e indice do dpkg uma vez para a lista toda
    if r.classifier is None:
        print(f"mandacaru: classificador indisponivel: {r.problem}", file=sys.stderr)
        return 1
    rows, worst = [], 0
    for arquivo in caminhos:
        row, rc = _avaliar_um(r.classifier, arquivo)
        if rc > worst:
            worst = rc
        if as_jsonl:
            print(json.dumps(row, ensure_ascii=False), flush=True)
        elif as_json:
            rows.append(row)
        else:
            _imprimir_texto(row)
    if as_json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    return worst


def _shadow(args) -> int:
    path = Path(args.arquivo or SHADOW_LOG)
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        print("sem registros do modo sombra")
        return 0
    except OSError as exc:
        print(f"mandacaru: nao foi possivel ler {path}: {exc.strerror or exc}", file=sys.stderr)
        return 1
    records = []
    for line in lines:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and (args.desde is None or str(rec.get("ts", ""))[:10] >= args.desde):
            records.append(rec)
    counts = {b: sum(1 for r in records if r.get("band") == b) for b in BANDS if b != "baixo"}
    print("registros: " + ", ".join(f"{b}: {n}" for b, n in counts.items()))
    seriam = sorted((r for r in records if r.get("would_isolate") is True),
                    key=lambda r: -float(r.get("score", 0)))[:20]
    if seriam:
        print("teria isolado:")
    for r in seriam:
        motivos = "; ".join(str(m.get("feature")) for m in r.get("motivos", []) if isinstance(m, dict)) or "-"
        print(f"  {r.get('path')}  {round(float(r.get('score', 0)) * 100)}%  {motivos}")
    return 0


def cmd_ml(args) -> int:
    if args.mcmd == "status":
        return _status(args)
    if args.mcmd == "avaliar":
        return _evaluate(args)
    return _shadow(args)
