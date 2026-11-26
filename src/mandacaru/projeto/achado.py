"""Achado: um indicio encontrado em um arquivo do projeto."""
from __future__ import annotations

import unicodedata
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path

from ..events import Alert, Severity, safe_text

LIMITE_TRECHO = 120
MAX_POR_REGRA = 20  # achados por (arquivo, regra); o último mantido conta os demais
_ESCONDIDOS = frozenset({"Cc", "Cf", "Zl", "Zp", "Co", "Cs"})


def exibivel(s: str, limite: int | None = LIMITE_TRECHO) -> str:
    """Texto do projeto pronto para terminal ou interface, sempre em UMA linha.

    Tabulação vira espaço; quebras de linha, controles, invisíveis (Cf), separadores de linha
    e parágrafo, uso privado e surrogates (bytes inválidos em nomes de arquivo) viram `<U+XXXX>`.
    Com `limite`, o resultado tem no máximo `limite` caracteres; se precisar cortar, termina em "…".
    Linear (para de ler ao passar do limite) e idempotente.
    """
    partes: list[str] = []
    tamanho = 0
    corte = 0  # quantas partes cabem junto com o "…"
    for c in s:
        if c == "\t":
            p = " "
        elif unicodedata.category(c) in _ESCONDIDOS:
            p = f"<U+{ord(c):04X}>"
        else:
            p = c
        tamanho += len(p)
        if limite is not None:
            if tamanho > limite:
                return safe_text("".join(partes[:corte]) + "…")
            if tamanho <= limite - 1:
                corte = len(partes) + 1
        partes.append(p)
    return safe_text("".join(partes))


@dataclass(frozen=True)
class Achado:
    regra: str
    severidade: Severity
    caminho: str  # relativo a raiz, com "/"
    explicacao: str
    linha: int | None = None
    trecho: str = ""
    mitre: tuple[str, ...] = ()
    # Identidade estável do objeto do achado, independente do arquivo e do texto. Dependências:
    # (ecossistema, nome, versão, *ids ordenados) — base do "Ignorar sempre"; aviso novo muda a chave.
    chave: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # Mesmo formato em todas as famílias: uma linha, invisíveis à mostra, no máximo 120 caracteres.
        object.__setattr__(self, "trecho", exibivel(self.trecho))

    def to_alert(self, raiz: Path) -> Alert:
        onde = self.caminho if self.linha is None else f"{self.caminho}:{self.linha}"
        return Alert(
            rule=self.regra,
            severity=self.severidade,
            summary=f"{onde}: {self.explicacao}",
            evidence={"path": str(raiz / self.caminho), "linha": self.linha, "trecho": self.trecho},
            mitre=list(self.mitre),
        )


def _com_excedente(a: Achado, n: int) -> Achado:
    return replace(a, explicacao=f"{a.explicacao} · …e mais {n} ocorrências desta regra neste arquivo")


class Limitador:
    """Junta achados com teto de MAX_POR_REGRA por (arquivo, regra).

    Pergunte `cabe(caminho, regra)` ANTES de montar o achado (linha, trecho): o que não cabe
    só é contado, então um arquivo com milhares de ocorrências custa pouco.
    """

    def __init__(self) -> None:
        self._mantidos: list[Achado] = []
        self._vistos: Counter[tuple[str, str]] = Counter()

    def cabe(self, caminho: str, regra: str) -> bool:
        self._vistos[(caminho, regra)] += 1
        return self._vistos[(caminho, regra)] <= MAX_POR_REGRA

    def add(self, achado: Achado) -> None:
        self._mantidos.append(achado)

    def extend(self, achados: Iterable[Achado]) -> None:
        for a in achados:
            if self.cabe(a.caminho, a.regra):
                self.add(a)

    def resultado(self) -> list[Achado]:
        ultimo: dict[tuple[str, str], int] = {}
        for i, a in enumerate(self._mantidos):
            ultimo[(a.caminho, a.regra)] = i
        saida = list(self._mantidos)
        for chave, i in ultimo.items():
            excedente = self._vistos[chave] - MAX_POR_REGRA
            if excedente > 0:
                saida[i] = _com_excedente(saida[i], excedente)
        return saida


def limitar(achados: Iterable[Achado]) -> list[Achado]:
    """No máximo MAX_POR_REGRA por (arquivo, regra), na ordem dada; o último mantido conta os demais."""
    lim = Limitador()
    lim.extend(achados)
    return lim.resultado()


class ArquivoIlegivel(Exception):
    """Arquivo-alvo com sintaxe invalida; o orquestrador conta e segue."""
