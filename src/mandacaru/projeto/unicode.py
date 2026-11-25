"""Familia 4: Unicode enganoso (Trojan Source e homoglifos) em codigo."""
from __future__ import annotations

import re
import unicodedata
from pathlib import Path

from ..detectors.static import SCRIPT_EXT
from ..events import Severity
from .achado import Achado
from .percurso import linha_de

EXT_CODIGO = frozenset(SCRIPT_EXT) | {
    ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".c", ".cpp", ".h", ".cs", ".kt", ".swift",
}

_TAGS = re.compile("[\U000e0000-\U000e007f]+")
_LARGURA_ZERO = re.compile("[​‌‍⁠﻿]{3,}")
_BIDI = re.compile("[‪-‮⁦-⁩]")
_BANDEIRA = "\U0001f3f4"
_MAX_TRECHO = 120

_IGNORAR = re.compile(
    r"""'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`[^`]*`|/\*.*?\*/|//.*|\#.*"""
)
_IDENT = re.compile(r"[^\W\d]\w*")


def mostrar_invisiveis(s: str) -> str:
    partes = [
        f"<U+{ord(c):04X}>" if c != "\t" and unicodedata.category(c) in ("Cf", "Cc") else c
        for c in s
    ]
    return "".join(partes)[:_MAX_TRECHO]


def trechos_tags(texto: str) -> list[int]:
    """Inicios de sequencias de Unicode Tags, exceto bandeiras curtas."""
    return [
        m.start()
        for m in _TAGS.finditer(texto)
        if len(m.group()) >= 12 or texto[m.start() - 1 : m.start()] != _BANDEIRA
    ]


def trechos_largura_zero(texto: str) -> list[int]:
    return [m.start() for m in _LARGURA_ZERO.finditer(texto)]


def trechos_bidi(texto: str) -> list[int]:
    return [m.start() for m in _BIDI.finditer(texto)]


def _escritas(palavra: str) -> set[str]:
    return {
        unicodedata.name(c, "").split(" ", 1)[0]
        for c in palavra
        if c.isalpha()
    } - {""}


def _mistura_escritas(linha: str) -> str | None:
    limpa = _IGNORAR.sub(" ", linha)
    for m in _IDENT.finditer(limpa):
        e = _escritas(m.group())
        if "LATIN" in e and e & {"CYRILLIC", "GREEK"}:
            return m.group()
    return None


def verificar(raiz: Path, rel: str, texto: str) -> list[Achado]:
    if Path(rel).suffix.lower() not in EXT_CODIGO:
        return []
    achados: list[Achado] = []
    vistas: set[int] = set()
    for pos in trechos_bidi(texto):
        linha = linha_de(texto, pos)
        if linha in vistas:
            continue
        vistas.add(linha)
        trecho = texto.splitlines()[linha - 1]
        achados.append(Achado(
            "projeto.unicode.bidi", Severity.HIGH, rel,
            "caracteres de controle bidirecional no código (Trojan Source): "
            "o texto exibido pode diferir do que é executado",
            linha, mostrar_invisiveis(trecho), ("T1027",),
        ))
    for i, trecho in enumerate(texto.splitlines(), start=1):
        palavra = _mistura_escritas(trecho)
        if palavra:
            achados.append(Achado(
                "projeto.unicode.homoglifo", Severity.MEDIUM, rel,
                f"identificador '{palavra}' mistura letras latinas com cirílicas ou "
                "gregas parecidas (homoglifo)",
                i, mostrar_invisiveis(trecho), ("T1036",),
            ))
    return achados
