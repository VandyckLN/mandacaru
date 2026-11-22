"""Programas com atualizacao pendente (apt, Snap, Flatpak) e o risco de cada um pelos achados de CVE."""
from __future__ import annotations

from .fontes import Atualizacao, coletar, nome_valido
from .risco import aplicar_riscos, riscos_do_relatorio, riscos_dos_achados

__all__ = [
    "Atualizacao",
    "aplicar_riscos",
    "coletar",
    "nome_valido",
    "riscos_do_relatorio",
    "riscos_dos_achados",
]
