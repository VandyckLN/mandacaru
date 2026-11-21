"""Instala um modelo treinado no repositorio (roda na Ubuntu-Dev; nao precisa de scikit-learn).

Le uma pasta com EXATAMENTE os 5 artefatos (elf.json, script.json, golden.json, relatorio-*.md, manifesto-*.txt),
valida tudo e so entao copia: modelos para src/mandacaru/ml/models/, golden para tests/fixtures/ml_golden.json,
relatorio e manifesto para docs/ml/, e reescreve MODEL_SHA256 em src/mandacaru/ml/__init__.py. Qualquer falha:
saida 1 e nada e copiado. Recusa symlinks, arquivos estranhos e texto com caracteres de controle (escapes ANSI).

Uso: python tools/instalar_modelo.py PASTA [--repo RAIZ_DO_REPOSITORIO]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

from mandacaru.ml.model import MAX_MODEL_BYTES, parse_model

MAX_JSON = 3 * 1024 * 1024
MAX_TEXTO = 2 * 1024 * 1024
TOL = 1e-9
_CONTROLE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_PINS = re.compile(r"^MODEL_SHA256: dict\[str, str\] = \{.*?\}$", re.M | re.S)


class Recusado(Exception):
    """Artefato invalido: nada e instalado."""


def _ler(path: Path, limite: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise Recusado(f"{path.name}: nao abre sem seguir link ({exc.strerror or exc})") from None
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise Recusado(f"{path.name}: nao e arquivo regular")
        dados = fh.read(limite + 1)
    if len(dados) > limite:
        raise Recusado(f"{path.name}: maior que {limite} bytes")
    return dados


def _texto(path: Path) -> bytes:
    dados = _ler(path, MAX_TEXTO)
    try:
        texto = dados.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise Recusado(f"{path.name}: nao e UTF-8 valido") from None
    if _CONTROLE.search(texto):
        raise Recusado(f"{path.name}: contem caracteres de controle (possivel escape ANSI)")
    return dados


def _strings(o):
    if isinstance(o, str):
        yield o
    elif isinstance(o, dict):
        for k, v in o.items():
            yield k
            yield from _strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from _strings(v)


def validar(pasta: Path) -> dict[str, tuple[str, bytes]]:
    """Destino relativo -> (nome, conteudo) dos 5 artefatos, todos validados."""
    if pasta.is_symlink() or not pasta.is_dir():
        raise Recusado(f"{pasta}: nao e uma pasta")
    itens = sorted(pasta.iterdir())
    for p in itens:
        if p.is_symlink():
            raise Recusado(f"{p.name}: symlink recusado")
    nomes = {p.name for p in itens}
    relatorios = [n for n in nomes if n.startswith("relatorio-") and n.endswith(".md")]
    manifestos = [n for n in nomes if n.startswith("manifesto-") and n.endswith(".txt")]
    esperados = {"elf.json", "script.json", "golden.json"}
    if not esperados <= nomes or len(relatorios) != 1 or len(manifestos) != 1 or len(nomes) != 5:
        raise Recusado(f"esperava exatamente elf.json, script.json, golden.json, um relatorio e um manifesto; "
                       f"encontrei: {', '.join(sorted(nomes))}")

    modelos = {}
    saida: dict[str, tuple[str, bytes]] = {}
    for fam in ("elf", "script"):
        dados = _ler(pasta / f"{fam}.json", min(MAX_JSON, MAX_MODEL_BYTES))
        try:
            m = parse_model(dados)
        except ValueError as exc:
            raise Recusado(f"{fam}.json: {exc}") from None
        if m.family != fam:
            raise Recusado(f"{fam}.json: familia {m.family!r} no arquivo errado")
        if any(len(s) > 64 for s in _strings(json.loads(dados)) if s not in m.feature_names):
            raise Recusado(f"{fam}.json: texto longo demais (parece conteudo, nao metrica)")
        modelos[fam] = m
        saida[f"src/mandacaru/ml/models/{fam}.json"] = (f"{fam}.json", dados)

    golden_raw = _ler(pasta / "golden.json", MAX_MODEL_BYTES)
    try:
        golden = json.loads(golden_raw)
    except ValueError:
        raise Recusado("golden.json: JSON invalido") from None
    for fam, m in modelos.items():
        g = golden.get(fam) if isinstance(golden, dict) else None
        if not isinstance(g, dict):
            raise Recusado(f"golden.json: falta a familia {fam}")
        for i, (x, raw, prob) in enumerate(zip(g["vetores"], g["raw"], g["prob"], strict=True)):
            if abs(m.raw_score(x) - raw) > TOL or abs(m.probability(x) - prob) > TOL:
                raise Recusado(f"golden.json: {fam} diverge do modelo no vetor {i}")
    saida["tests/fixtures/ml_golden.json"] = ("golden.json", golden_raw)
    saida[f"docs/ml/{relatorios[0]}"] = (relatorios[0], _texto(pasta / relatorios[0]))
    saida[f"docs/ml/{manifestos[0]}"] = (manifestos[0], _texto(pasta / manifestos[0]))
    return saida


def _pins(init_py: str, hashes: dict[str, str]) -> str:
    corpo = "".join(f'    "{fam}": "{h}",\n' for fam, h in sorted(hashes.items()))
    novo = "MODEL_SHA256: dict[str, str] = {\n" + corpo + "}"
    if not _PINS.search(init_py):
        raise Recusado("nao achei MODEL_SHA256 em src/mandacaru/ml/__init__.py")
    return _PINS.sub(lambda _: novo, init_py, count=1)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python tools/instalar_modelo.py", description="instala um modelo validado")
    ap.add_argument("pasta", type=Path)
    ap.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
    args = ap.parse_args(argv)
    try:
        artefatos = validar(args.pasta)
        init = args.repo / "src/mandacaru/ml/__init__.py"
        hashes = {fam: hashlib.sha256(artefatos[f"src/mandacaru/ml/models/{fam}.json"][1]).hexdigest()
                  for fam in ("elf", "script")}
        novo_init = _pins(init.read_text(encoding="utf-8"), hashes)
    except Recusado as exc:
        print(f"recusado: {exc}", file=sys.stderr)
        return 1
    for destino, (_nome, dados) in artefatos.items():
        alvo = args.repo / destino
        alvo.parent.mkdir(parents=True, exist_ok=True)
        alvo.write_bytes(dados)
    init.write_text(novo_init, encoding="utf-8")
    for fam, h in hashes.items():
        print(f"{fam}: {h}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
