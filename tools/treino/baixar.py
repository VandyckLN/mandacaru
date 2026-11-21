"""Coleta de amostras maliciosas no MalwareBazaar (abuse.ch), incremental e retomavel.

Dois modos: o catalogo historico (full.csv.zip, lido em streaming) para ter uma janela temporal longa, ou a lista
dos mais recentes por tipo (get_file_type, no maximo 1.000). Os zips AES baixados vao direto para o Corpus, sem
nunca serem extraidos. A chave (MB_AUTH_KEY) so existe no ambiente; nunca e impressa, gravada ou repassada num
redirecionamento.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from .corpus import MAX_ZIP_BYTES, Corpus, Entry

API = "https://mb-api.abuse.ch/api/v1/"
TIPOS_MB = ("elf", "sh", "py", "pl", "js", "php")
HttpPost = Callable[[str, dict[str, str], dict[str, str]], tuple[int, bytes]]
_SEM_FAMILIA = "sem_familia"
_CSV_PADRAO = ("first_seen_utc", "sha256_hash", "md5_hash", "sha1_hash", "reporter", "file_name",
               "file_type_guess", "mime_type", "signature")


@dataclass
class Resultado:
    baixados: int
    pulados: int
    parou: str | None


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Recusa qualquer 30x: seguir o redirecionamento levaria o cabecalho Auth-Key para outro lugar."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(newurl, code, "redirecionamento recusado", headers, fp)


def _http_padrao(url: str, cabecalhos: dict[str, str], campos: dict[str, str]) -> tuple[int, bytes]:
    if not url.startswith("https://"):
        raise ValueError("so https")
    opener = urllib.request.build_opener(_NoRedirectHandler)
    data = urllib.parse.urlencode(campos).encode("ascii")
    for tentativa in range(3):
        req = urllib.request.Request(url, data=data, headers=cabecalhos, method="POST")
        try:
            with opener.open(req, timeout=60) as resp:
                return resp.status, resp.read(MAX_ZIP_BYTES + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 429 or 500 <= exc.code < 600:
                time.sleep(2 ** (tentativa + 1))
                continue
            return exc.code, exc.read(MAX_ZIP_BYTES + 1)
    return 503, b'{"query_status": "http_indisponivel"}'


def _dia(first_seen: str) -> str:
    return (first_seen or "")[:10]


def _familia(signature: str | None) -> str:
    s = (signature or "").strip()
    return _SEM_FAMILIA if s in ("", "n/a", "None") else s


def _status(corpo: bytes) -> str | None:
    """query_status de uma resposta JSON; None se a resposta nao for JSON."""
    if not corpo.lstrip().startswith(b"{"):
        return None
    try:
        return str(json.loads(corpo).get("query_status", "resposta_invalida"))
    except ValueError:
        return "resposta_invalida"


def listar(tipo: str, *, chave: str, http: HttpPost, limite: int = 1000) -> list[dict]:
    status, corpo = http(API, {"Auth-Key": chave}, {"query": "get_file_type", "file_type": tipo,
                                                     "limit": str(limite)})
    q = _status(corpo)
    if q == "no_results":
        return []
    if status != 200 or q != "ok":
        raise RuntimeError(q or f"http_{status}")
    return list(json.loads(corpo).get("data") or [])


def _linhas_catalogo(catalogo_zip: Path) -> Iterator[dict]:
    with zipfile.ZipFile(catalogo_zip) as z:
        nome = next(n for n in z.namelist() if n.endswith(".csv"))
        with z.open(nome) as raw:
            texto = io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline="")
            colunas = list(_CSV_PADRAO)
            for row in csv.reader(texto, skipinitialspace=True):  # aceita "," e ", "
                if not row:
                    continue
                if row[0].lstrip().startswith("#"):
                    cab = [c.strip().lstrip("#").strip().strip('"') for c in row]
                    if "sha256_hash" in cab:
                        colunas = cab
                    continue
                yield dict(zip(colunas, (c.strip() for c in row), strict=False))


class _Tetos:
    def __init__(self, corpus: Corpus, max_por_familia: int, max_por_remetente: int) -> None:
        maliciosos = [e for e in corpus.entries() if e.label == 1]
        self.familias = Counter(e.family for e in maliciosos)
        self.remetentes = Counter(e.reporter for e in maliciosos)
        self.max_familia = max_por_familia
        self.max_remetente = max_por_remetente

    def cabe(self, familia: str, remetente: str) -> bool:
        return self.familias[familia] < self.max_familia and self.remetentes[remetente] < self.max_remetente

    def conta(self, familia: str, remetente: str) -> None:
        self.familias[familia] += 1
        self.remetentes[remetente] += 1


def selecionar_catalogo(catalogo_zip: Path, corpus: Corpus, *, tipos=TIPOS_MB, desde: str | None = None,
                        cota: int = 500, max_por_familia: int = 300, max_por_remetente: int = 1000) -> list[dict]:
    """Candidatos do catalogo historico ainda fora do corpus, ja dentro dos tetos, ate a cota."""
    tetos = _Tetos(corpus, max_por_familia, max_por_remetente)
    escolhidos: list[dict] = []
    vistos: set[str] = set()
    for row in _linhas_catalogo(catalogo_zip):
        sha = row.get("sha256_hash", "").lower()
        tipo = row.get("file_type_guess", "")
        dia = _dia(row.get("first_seen_utc", ""))
        if len(sha) != 64 or sha in vistos or corpus.has(sha, 1) or tipo not in tipos:
            continue
        if desde is not None and dia < desde:
            continue
        fam, rem = _familia(row.get("signature")), row.get("reporter", "") or "desconhecido"
        if not tetos.cabe(fam, rem):
            continue
        tetos.conta(fam, rem)
        vistos.add(sha)
        escolhidos.append({"sha256_hash": sha, "signature": fam, "reporter": rem, "first_seen": dia,
                           "file_type": tipo})
        if len(escolhidos) >= cota:
            break
    return escolhidos


def _candidatos_recentes(corpus: Corpus, *, chave: str, http: HttpPost, tipos, cota: int, max_por_familia: int,
                         max_por_remetente: int) -> list[dict]:
    tetos = _Tetos(corpus, max_por_familia, max_por_remetente)
    escolhidos: list[dict] = []
    for tipo in tipos:
        for item in listar(tipo, chave=chave, http=http):
            sha = str(item.get("sha256_hash", "")).lower()
            if len(sha) != 64 or corpus.has(sha, 1) or any(c["sha256_hash"] == sha for c in escolhidos):
                continue
            fam, rem = _familia(item.get("signature")), str(item.get("reporter") or "desconhecido")
            if not tetos.cabe(fam, rem):
                continue
            tetos.conta(fam, rem)
            escolhidos.append({"sha256_hash": sha, "signature": fam, "reporter": rem,
                               "first_seen": _dia(str(item.get("first_seen", ""))), "file_type": tipo})
            if len(escolhidos) >= cota:
                return escolhidos
    return escolhidos


def coletar(corpus: Corpus, *, chave: str, http: HttpPost, tipos=TIPOS_MB, cota: int = 500,
            max_por_familia: int = 300, max_por_remetente: int = 1000, catalogo: Path | None = None,
            desde: str | None = None) -> Resultado:
    try:
        if catalogo is not None:
            candidatos = selecionar_catalogo(catalogo, corpus, tipos=tipos, desde=desde, cota=cota,
                                             max_por_familia=max_por_familia, max_por_remetente=max_por_remetente)
        else:
            candidatos = _candidatos_recentes(corpus, chave=chave, http=http, tipos=tipos, cota=cota,
                                              max_por_familia=max_por_familia, max_por_remetente=max_por_remetente)
    except RuntimeError as exc:
        return Resultado(0, 0, str(exc))

    baixados = pulados = 0
    for c in candidatos:
        if corpus.max_disk_bytes is not None and corpus.disk_usage_bytes() >= corpus.max_disk_bytes:
            return Resultado(baixados, pulados, "teto_de_disco")
        status, corpo = http(API, {"Auth-Key": chave}, {"query": "get_file", "sha256_hash": c["sha256_hash"]})
        q = _status(corpo)
        if q is not None:                      # JSON no lugar do zip: limite diario, sha desconhecido...
            if q in ("file_not_found", "illegal_sha256_hash"):
                pulados += 1
                continue
            return Resultado(baixados, pulados, q)
        if status != 200 or not corpo.startswith(b"PK\x03\x04"):
            pulados += 1
            continue
        entry = Entry(sha256=c["sha256_hash"], label=1, source="malwarebazaar", family=c["signature"],
                      first_seen=c["first_seen"], reporter=c["reporter"], categoria="malicioso")
        if corpus.add_zip(entry, corpo):
            baixados += 1
        else:
            pulados += 1
    return Resultado(baixados, pulados, None)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m tools.treino.baixar",
                                 description="coleta amostras do MalwareBazaar (chave em MB_AUTH_KEY)")
    ap.add_argument("--corpus", required=True, type=Path)
    ap.add_argument("--cota", type=int, default=500)
    ap.add_argument("--catalogo", type=Path, default=None, help="full.csv.zip do MalwareBazaar")
    ap.add_argument("--desde", default=None, help="AAAA-MM-DD (so com --catalogo)")
    ap.add_argument("--max-corpus-gb", type=float, default=20.0)
    args = ap.parse_args(argv)
    chave = os.environ.get("MB_AUTH_KEY", "")
    if not chave:
        print("erro: defina MB_AUTH_KEY no ambiente (a chave nunca vai para arquivo)", file=sys.stderr)
        return 1
    corpus = Corpus(args.corpus, max_disk_bytes=int(args.max_corpus_gb * 1024**3))
    r = coletar(corpus, chave=chave, http=_http_padrao, cota=args.cota, catalogo=args.catalogo, desde=args.desde)
    print(f"baixados={r.baixados} pulados={r.pulados} parou={r.parou or '-'} "
          f"corpus={len(corpus.entries())} disco_mb={corpus.disk_usage_bytes() // (1024 * 1024)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
