"""Risco de cada atualizacao apt: o pacote binario herda a pior prioridade dos achados OSV/KEV do seu fonte.

Os achados do `vuln scan` sao por pacote-fonte (`openssl`), mas o apt atualiza binarios (`libssl3`); a
ligacao vem do dpkg/status. Snap e Flatpak ficam DESCONHECIDO: o OSV nao cobre esses pacotes.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable

from ..fsutil import read_text_nofollow
from ..vuln.inventory import parse_dpkg_status
from ..vuln.publish import MAX_REPORT_BYTES
from ..vuln.publish import _finding as achado_do_relatorio  # mesmo leitor tolerante do publicador
from ..vuln.scorer import ScoredVulnerability
from .fontes import DESCONHECIDO, NENHUM, ORDEM_RISCO, Atualizacao


@dataclass(frozen=True)
class RiscoFonte:
    prioridade: str
    cves: tuple[str, ...]


# fonte -> versao do fonte -> risco
Riscos = dict[str, dict[str, RiscoFonte]]


def riscos_dos_achados(achados: Iterable[ScoredVulnerability]) -> Riscos:
    """Agrupa por (fonte, versao) com a pior prioridade e todas as CVEs (ou o id, se nao houver CVE)."""
    riscos: Riscos = {}
    for f in achados:
        por_versao = riscos.setdefault(f.package, {})
        atual = por_versao.get(f.version)
        ids = f.cve_ids or (f.vuln_id,)
        if atual is None:
            por_versao[f.version] = RiscoFonte(f.priority, tuple(sorted(set(ids))))
            continue
        pior = min(atual.prioridade, f.priority, key=lambda p: ORDEM_RISCO.get(p, 9))
        por_versao[f.version] = RiscoFonte(pior, tuple(sorted(set(atual.cves) | set(ids))))
    return riscos


def riscos_do_relatorio(caminho: Path) -> Riscos:
    """Le o last-scan.json sem seguir symlink. OSError/ValueError sobem para quem chamou avisar."""
    dados = json.loads(read_text_nofollow(caminho, MAX_REPORT_BYTES))
    if not isinstance(dados, list):
        raise ValueError(f"{caminho}: formato invalido")
    return riscos_dos_achados(f for f in map(achado_do_relatorio, dados) if f is not None)


def fontes_dos_binarios(status: Path) -> dict[str, tuple[str, str]]:
    """Pacote binario -> (pacote-fonte, versao do fonte), do dpkg/status."""
    return {b: (p.source_name, p.version)
            for p in parse_dpkg_status(status_path=status, ecosystem="-")
            for b in (p.binaries or (p.binary_name,))}


def aplicar_riscos(itens: list[Atualizacao], riscos: Riscos,
                   binario_fonte: dict[str, tuple[str, str]]) -> list[Atualizacao]:
    """So itens apt mudam. Fonte com achados de outra versao (relatorio velho) fica DESCONHECIDO."""
    saida = []
    for item in itens:
        ligacao = binario_fonte.get(item.nome) if item.gerenciador == "apt" else None
        if ligacao is not None:
            fonte, versao = ligacao
            if fonte not in riscos:
                item = replace(item, risco=NENHUM, cves=())
            elif (r := riscos[fonte].get(versao)) is not None:
                item = replace(item, risco=r.prioridade, cves=r.cves)
            else:
                item = replace(item, risco=DESCONHECIDO, cves=())
        saida.append(item)
    return saida
