"""Higiene do corpus e divisoes em treino, calibracao e teste.

- Um hash com os dois rotulos sai dos dois lados (nunca vira rotulo contraditorio).
- Hashes maliciosos que o CIRCL reconhece como legitimos saem do lado malicioso (so hashes de amostras saem).
- Maliciosos: corte temporal (o teste simula "malware novo") e familias inteiras so no teste ("sem_familia" fica
  fora do sorteio, porque nao e uma familia de verdade).
- Legitimos: divisao deterministica pelo pacote de origem, para arquivos irmaos nao vazarem entre treino e teste.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .corpus import Corpus, Entry

HttpJson = Callable[[str, bytes], tuple[int, bytes]]
CIRCL_BULK = "https://hashlookup.circl.lu/bulk/sha256"
_SEM_FAMILIA = ("", "sem_familia")


def remover_conflitos(entries: list[Entry]) -> list[Entry]:
    rotulos: dict[str, set[int]] = {}
    for e in entries:
        rotulos.setdefault(e.sha256, set()).add(e.label)
    return [e for e in entries if len(rotulos[e.sha256]) == 1]


def remover_conhecidos(entries: list[Entry], conhecidos: set[str]) -> list[Entry]:
    return [e for e in entries if not (e.label == 1 and e.sha256 in conhecidos)]


@dataclass(frozen=True)
class Divisao:
    treino: tuple[str, ...]
    calibracao: tuple[str, ...]
    teste: tuple[str, ...]
    familias_teste: tuple[str, ...]
    corte_temporal_teste: tuple[str, ...]


def _parte_legitimo(e: Entry) -> str:
    chave = f"{e.categoria}:{e.package or e.sha256}".encode()
    n = int(hashlib.sha256(chave).hexdigest()[:8], 16) % 100
    return "treino" if n < 70 else "calibracao" if n < 85 else "teste"


def dividir(entries: list[Entry], *, corte_teste: str, corte_calibracao: str, frac_familias_teste: float = 0.1,
            semente: int = 7) -> Divisao:
    maliciosos = [e for e in entries if e.label == 1]
    nomeadas = sorted({e.family for e in maliciosos if e.family not in _SEM_FAMILIA})
    n_sorteio = max(1, round(frac_familias_teste * len(nomeadas))) if nomeadas and frac_familias_teste > 0 else 0
    familias_teste = tuple(sorted(random.Random(semente).sample(nomeadas, n_sorteio)))
    fam_set = set(familias_teste)

    treino: list[str] = []
    calib: list[str] = []
    teste: list[str] = []
    temporal: list[str] = []
    for e in entries:
        if e.label == 1:
            if e.first_seen >= corte_teste:
                teste.append(e.sha256)
                temporal.append(e.sha256)
            elif e.family in fam_set:
                teste.append(e.sha256)
            elif e.first_seen >= corte_calibracao:
                calib.append(e.sha256)
            else:
                treino.append(e.sha256)
        else:
            {"treino": treino, "calibracao": calib, "teste": teste}[_parte_legitimo(e)].append(e.sha256)
    return Divisao(tuple(treino), tuple(calib), tuple(teste), familias_teste, tuple(temporal))


def _http_json_padrao(url: str, corpo: bytes) -> tuple[int, bytes]:
    if not url.startswith("https://"):
        raise ValueError("so https")
    req = urllib.request.Request(url, data=corpo, method="POST",
                                 headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read(32 * 1024 * 1024)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(1024 * 1024)


def conhecidos_circl(hashes: list[str], *, http: HttpJson, lote: int = 1000) -> set[str]:
    """Hashes que o CIRCL hashlookup conhece (base de arquivos legitimos). So hashes saem da maquina."""
    achados: set[str] = set()
    for i in range(0, len(hashes), lote):
        parte = hashes[i:i + lote]
        status, corpo = http(CIRCL_BULK, json.dumps({"hashes": parte}).encode("ascii"))
        if status != 200:
            raise RuntimeError(f"CIRCL respondeu {status}")
        resposta = json.loads(corpo)
        for item in resposta if isinstance(resposta, list) else []:
            if isinstance(item, dict) and isinstance(item.get("SHA-256"), str):
                achados.add(item["SHA-256"].lower())
    return achados & set(hashes)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m tools.treino.higiene",
                                 description="grava os hashes maliciosos que o CIRCL conhece como legitimos")
    ap.add_argument("--corpus", required=True, type=Path)
    ap.add_argument("--saida", required=True, type=Path)
    args = ap.parse_args(argv)
    maliciosos = [e.sha256 for e in Corpus(args.corpus).entries() if e.label == 1]
    achados = conhecidos_circl(maliciosos, http=_http_json_padrao)
    args.saida.write_text("".join(f"{h}\n" for h in sorted(achados)), encoding="ascii")
    print(f"maliciosos consultados: {len(maliciosos)}; conhecidos como legitimos: {len(achados)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
