"""Leitor YAML para entrada hostil: aliases e nos limitados, sem tipos arbitrarios.

Aliases sao aceitos (workflows usam ancoras), mas cada documento tem teto de MAX_ALIASES aliases
e de `max_nos` nos contando o que cada alias expande: a bomba "billion laughs" e recusada no
compose, antes de qualquer percurso da estrutura.
"""
from __future__ import annotations

import yaml
from yaml.events import AliasEvent

from .achado import ArquivoIlegivel

MAX_ALIASES = 100
MAX_NOS = 100_000


class _Limitado(yaml.SafeLoader):
    def __init__(self, stream: str, max_nos: int) -> None:
        super().__init__(stream)
        self._max_nos = max_nos
        self._nos = 0
        self._aliases = 0
        self._tamanho: dict[str, int] = {}  # ancora -> nos que ela expande

    def _somar(self, n: int) -> None:
        self._nos += n
        if self._nos > self._max_nos:
            raise yaml.YAMLError("YAML com nos demais")

    def compose_document(self):
        self._nos, self._aliases, self._tamanho = 0, 0, {}
        return super().compose_document()

    def compose_node(self, parent, index):
        evento = self.peek_event()
        if isinstance(evento, AliasEvent):
            self._aliases += 1
            if self._aliases > MAX_ALIASES:
                raise yaml.YAMLError("YAML com aliases demais")
            self._somar(self._tamanho.get(evento.anchor, 1))
            return super().compose_node(parent, index)
        ancora = getattr(evento, "anchor", None)
        antes = self._nos
        self._somar(1)
        no = super().compose_node(parent, index)
        if ancora is not None:
            self._tamanho[ancora] = self._nos - antes
        return no


def carregar(texto: str, rel: str = "", max_nos: int = MAX_NOS) -> object:
    """Le o YAML; erro de sintaxe, aliases ou nos demais, ou aninhamento absurdo vira ArquivoIlegivel."""
    try:
        carregador = _Limitado(texto, max_nos)
        try:
            return carregador.get_single_data()
        finally:
            carregador.dispose()
    except Exception as exc:  # noqa: BLE001 - tudo no parser/construtor e entrada do atacante
        raise ArquivoIlegivel(rel) from exc
