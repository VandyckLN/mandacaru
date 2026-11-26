"""Familia 4: Unicode enganoso (Trojan Source e homoglifos) em codigo."""
from __future__ import annotations

import re
import unicodedata
from pathlib import Path

from ..detectors.static import SCRIPT_EXT
from ..events import Severity
from .achado import Achado, Limitador

EXT_CODIGO = frozenset(SCRIPT_EXT) | {
    ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".c", ".cpp", ".h", ".cs", ".kt", ".swift",
}

_TAGS = re.compile("[\U000e0000-\U000e007f]+")
_LARGURA_ZERO = re.compile("[\u200b\u200c\u200d\u2060\ufeff]{3,}")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
_BANDEIRA = "\U0001f3f4"

_IGNORAR = re.compile(
    r"""'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`[^`]*`|/\*.*?\*/|//.*|\#.*"""
)
_IDENT = re.compile(r"[^\W\d]\w*")


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
    lim = Limitador()
    for i, trecho in enumerate(texto.split("\n"), start=1):
        trecho = trecho.removesuffix("\r")
        if _BIDI.search(trecho) and lim.cabe(rel, "projeto.unicode.bidi"):
            lim.add(Achado(
                "projeto.unicode.bidi", Severity.HIGH, rel,
                "caracteres de controle bidirecional no código (Trojan Source): "
                "o texto exibido pode diferir do que é executado",
                i, trecho, ("T1027",),
            ))
        palavra = _mistura_escritas(trecho)
        if palavra and lim.cabe(rel, "projeto.unicode.homoglifo"):
            lim.add(Achado(
                "projeto.unicode.homoglifo", Severity.MEDIUM, rel,
                f"identificador '{palavra}' mistura letras latinas com cirílicas ou "
                "gregas parecidas (homoglifo)",
                i, trecho, ("T1036",),
            ))
    return lim.resultado()
