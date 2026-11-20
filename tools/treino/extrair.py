"""Extracao das caracteristicas para um cache SQLite incremental, e montagem das tabelas de treino.

Usa o MESMO mandacaru.ml.features do produto (uma so fonte da verdade). Cada amostra e lida do zip em memoria,
vira um vetor float32 e recebe a marca do que as regras atuais do Mandacaru ja pegam (regra_alta/regra_media),
calculada pelo StaticScanner com uma extensao sintetica do tipo, para as heuristicas de script dispararem como
no runtime. O cache e indexado pela versao das caracteristicas e pelo hash do codigo e das regras: mudou, refaz.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import struct
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import numpy as np

import mandacaru
from mandacaru.detectors.static import StaticScanner
from mandacaru.events import Severity
from mandacaru.ml import features as _features
from mandacaru.ml.features import FAMILY, FEATURE_VERSION, ExtractionBudgetExceeded, extract
from mandacaru.ml.kind import detect_kind

from .corpus import Corpus
from .higiene import Divisao

EXTENSOES = {"elf": ".elf", "sh": ".sh", "python": ".py", "perl": ".pl", "js": ".js", "php": ".php"}
_FAMILIAS = ("elf", "script")


def _sha_arquivos(paths: list[Path]) -> str:
    h = hashlib.sha256()
    for p in sorted(paths):
        h.update(p.name.encode())
        h.update(p.read_bytes())
    return h.hexdigest()


def feature_code_sha() -> str:
    return _sha_arquivos([Path(_features.__file__)])


def yara_rules_sha() -> str:
    return _sha_arquivos(list((Path(mandacaru.__file__).parent / "rules" / "yara").glob("*.yar")))


def _abrir(cache_db: Path) -> sqlite3.Connection:
    con = sqlite3.connect(cache_db, timeout=30.0)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute("""CREATE TABLE IF NOT EXISTS features (
        sha256 TEXT, version INT, code_sha TEXT, yara_sha TEXT, family TEXT, kind TEXT,
        regra_alta INT, regra_media INT, vec BLOB,
        PRIMARY KEY (sha256, version, code_sha, yara_sha))""")
    return con


def extrair_cache(corpus: Corpus, cache_db: Path, *, budget_s: float = 2.0,
                  shard: tuple[int, int] | None = None) -> dict[str, int]:
    """Preenche o cache com o que ainda falta. Devolve contagens (extraidos, cacheados, sem_tipo, estouro, ilegivel)."""
    chave = (FEATURE_VERSION, feature_code_sha(), yara_rules_sha())
    scanner = StaticScanner()                              # uma vez so: compilar as regras e caro
    cont = {"extraidos": 0, "cacheados": 0, "sem_tipo": 0, "estouro": 0, "ilegivel": 0}
    con = _abrir(cache_db)
    try:
        for e in corpus.entries():
            if shard is not None and int(e.sha256[:8], 16) % shard[1] != shard[0]:
                continue
            if con.execute("SELECT 1 FROM features WHERE sha256=? AND version=? AND code_sha=? AND yara_sha=?",
                           (e.sha256, *chave)).fetchone():
                cont["cacheados"] += 1
                continue
            data = corpus.read(e)
            if data is None:
                cont["ilegivel"] += 1
                continue
            kind = detect_kind(data)
            if kind is None:
                cont["sem_tipo"] += 1
                continue
            try:
                x = extract(kind, data, budget_s=budget_s)
            except ExtractionBudgetExceeded:
                cont["estouro"] += 1
                continue
            alerts = scanner.scan_bytes(Path(f"{e.sha256}{EXTENSOES[kind]}"), data)
            alta = any(a.severity >= Severity.HIGH for a in alerts)
            media = any(a.severity >= Severity.MEDIUM for a in alerts)
            con.execute("INSERT OR REPLACE INTO features VALUES (?,?,?,?,?,?,?,?,?)",
                        (e.sha256, *chave, FAMILY[kind], kind, int(alta), int(media),
                         struct.pack(f"<{len(x)}f", *x)))
            cont["extraidos"] += 1
            if cont["extraidos"] % 500 == 0:
                con.commit()
        con.commit()
    finally:
        con.close()
    return cont


@dataclass
class Tabela:
    X: np.ndarray
    y: np.ndarray
    kind: tuple[str, ...]
    sha: tuple[str, ...]
    parte: tuple[str, ...]
    categoria: tuple[str, ...]
    regra_alta: np.ndarray
    regra_media: np.ndarray
    temporal_teste: np.ndarray


def montar_tabelas(corpus: Corpus, divisao: Divisao, cache_db: Path) -> dict[str, Tabela]:
    chave = (FEATURE_VERSION, feature_code_sha(), yara_rules_sha())
    parte_de = {s: p for p, hs in (("treino", divisao.treino), ("calibracao", divisao.calibracao),
                                   ("teste", divisao.teste)) for s in hs}
    temporal = set(divisao.corte_temporal_teste)
    entradas = {e.sha256: e for e in corpus.entries()}
    linhas: dict[str, list] = {f: [] for f in _FAMILIAS}
    con = _abrir(cache_db)
    try:
        cur = con.execute("SELECT sha256, family, kind, regra_alta, regra_media, vec FROM features "
                          "WHERE version=? AND code_sha=? AND yara_sha=? ORDER BY sha256", chave)
        for sha, fam, kind, alta, media, vec in cur:
            if sha not in parte_de or sha not in entradas:
                continue
            linhas[fam].append((sha, kind, alta, media, vec, entradas[sha]))
    finally:
        con.close()
    tabelas = {}
    for fam, rows in linhas.items():
        n = len(rows)
        dim = len(rows[0][4]) // 4 if rows else 0
        X = np.frombuffer(b"".join(r[4] for r in rows), dtype="<f4").reshape(n, dim).astype(np.float32) \
            if rows else np.zeros((0, 0), dtype=np.float32)
        tabelas[fam] = Tabela(
            X=X,
            y=np.array([r[5].label for r in rows], dtype=np.int8),
            kind=tuple(r[1] for r in rows),
            sha=tuple(r[0] for r in rows),
            parte=tuple(parte_de[r[0]] for r in rows),
            categoria=tuple(r[5].categoria for r in rows),
            regra_alta=np.array([bool(r[2]) for r in rows], dtype=bool),
            regra_media=np.array([bool(r[3]) for r in rows], dtype=bool),
            temporal_teste=np.array([r[0] in temporal for r in rows], dtype=bool),
        )
    return tabelas


def extrair(corpus: Corpus, divisao: Divisao, *, cache_db: Path | None = None,
            budget_s: float = 2.0) -> dict[str, Tabela]:
    if cache_db is not None:
        extrair_cache(corpus, cache_db, budget_s=budget_s)
        return montar_tabelas(corpus, divisao, cache_db)
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "cache.sqlite"
        extrair_cache(corpus, db, budget_s=budget_s)
        return montar_tabelas(corpus, divisao, db)


_META = ("kind", "sha", "parte", "categoria")
_ARRAYS = ("X", "y", "regra_alta", "regra_media", "temporal_teste")


def salvar(tabelas: dict[str, Tabela], pasta: Path) -> None:
    pasta.mkdir(parents=True, exist_ok=True)
    for fam, t in tabelas.items():
        np.savez_compressed(pasta / f"{fam}.npz", **{k: getattr(t, k) for k in _ARRAYS})
        (pasta / f"{fam}.json").write_text(json.dumps({k: list(getattr(t, k)) for k in _META}), encoding="ascii")


def carregar(pasta: Path) -> dict[str, Tabela]:
    tabelas = {}
    for npz in sorted(pasta.glob("*.npz")):
        fam = npz.stem
        with np.load(npz, allow_pickle=False) as arr:
            arrays = {k: arr[k] for k in _ARRAYS}
        meta = json.loads((pasta / f"{fam}.json").read_text(encoding="ascii"))
        tabelas[fam] = Tabela(**arrays, **{k: tuple(meta[k]) for k in _META})
    return tabelas


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m tools.treino.extrair", description="preenche o cache de features")
    ap.add_argument("--corpus", required=True, type=Path)
    ap.add_argument("--cache", required=True, type=Path)
    ap.add_argument("--shard", default=None, help="i/n: so as amostras deste pedaco (ex.: 0/4)")
    ap.add_argument("--budget", type=float, default=2.0)
    args = ap.parse_args(argv)
    shard = None
    if args.shard:
        i, n = (int(v) for v in args.shard.split("/"))
        shard = (i, n)
    cont = extrair_cache(Corpus(args.corpus), args.cache, budget_s=args.budget, shard=shard)
    print(" ".join(f"{k}={v}" for k, v in cont.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
