"""Leitor YAML para entrada hostil: sem aliases (bomba de bilhao de risadas) e sem tipos arbitrarios."""
from __future__ import annotations

import yaml
from yaml.events import AliasEvent

from .achado import ArquivoIlegivel


class _SemAlias(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(AliasEvent):
            raise yaml.YAMLError("alias YAML nao e aceito")
        return super().compose_node(parent, index)


def carregar(texto: str, rel: str = "") -> object:
    """Le o YAML; qualquer erro de sintaxe, alias ou aninhamento absurdo vira ArquivoIlegivel."""
    try:
        return yaml.load(texto, Loader=_SemAlias)  # noqa: S506 - SafeLoader, sem aliases
    except Exception as exc:  # noqa: BLE001 - tudo no parser/construtor e entrada do atacante
        raise ArquivoIlegivel(rel) from exc
