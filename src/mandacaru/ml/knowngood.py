"""Arquivos identicos a um de pacote instalado (md5 do dpkg): o modelo nao os isola.

md5 basta aqui: forjar um arquivo com o mesmo md5 de um arquivo ja existente do Debian (segunda pre-imagem) nao e
viavel. O indice so e carregado quando o modelo quer isolar algo, e recarregado quando o dpkg muda.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path


class DpkgKnownGood:
    def __init__(self, info_dir: Path = Path("/var/lib/dpkg/info")) -> None:
        self.info_dir = Path(info_dir)
        self._digests: set[bytes] = set()
        self._sig: int | None = None

    def _mtime(self) -> int:
        try:
            return os.stat(self.info_dir).st_mtime_ns
        except OSError:
            return -1

    def _load(self) -> None:
        digests: set[bytes] = set()
        try:
            files = list(self.info_dir.glob("*.md5sums"))
        except OSError:
            files = []
        for f in files:
            try:
                text = f.read_text(encoding="ascii", errors="ignore")
            except OSError:
                continue
            for line in text.splitlines():
                head = line[:32]
                if len(head) == 32:
                    try:
                        digests.add(bytes.fromhex(head))
                    except ValueError:
                        continue
        self._digests = digests

    def contains(self, data: bytes) -> bool:
        sig = self._mtime()
        if sig != self._sig:
            self._sig = sig
            self._load()
        return hashlib.md5(data, usedforsecurity=False).digest() in self._digests
