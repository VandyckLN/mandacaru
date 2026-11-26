"""Verificacao de projeto: procura armadilhas para agentes e ferramentas em um repositorio."""
from __future__ import annotations

import os
import posixpath
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path

from ..events import Severity
from ..vuln import KevCache, OsvClient
from . import abrir, agentes, ci, instalar, jsonc, lockfiles
from . import unicode as unicode_
from .achado import Achado, limitar
from .dependencias import ResultadoDeps, verificar_dependencias
from .lockfiles import Dependencia
from .percurso import MAX_ARQUIVOS, ler_texto, listar, listar_prioritarios

MARCAS_PROJETO = (
    ".git", "package.json", "pyproject.toml", "setup.py", ".vscode", ".devcontainer", ".mcp.json",
    ".github", *lockfiles.LOCKFILES, "AGENTS.md", "CLAUDE.md", ".cursorrules",
)
_MCP_REL = (".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json")
_FAMILIAS = (agentes, unicode_, abrir, instalar, ci)
_INTERROMPIDO = "verificação interrompida"
# Alvos de caminho fixo: sempre lidos, fora do limite de arquivos (uma pasta inchada não os esconde).
_FIXOS = (*abrir.ALVOS, *agentes.ARQUIVOS_AGENTE)
_PASTAS_FIXAS = {".github/workflows": False, **agentes.PASTAS_AGENTE}
_NA_RAIZ = frozenset({"package.json", "setup.py", "pyproject.toml"})


def _fixo_na_raiz(nome: str) -> bool:
    return nome in _NA_RAIZ or nome.lower() in agentes.NOMES_AGENTE or lockfiles.eh_lockfile(nome)


def _milhar(n: int) -> str:
    return f"{n:,}".replace(",", ".")


def parece_projeto(pasta: Path) -> bool:
    """Pasta com alguma marca de projeto (ou requirements*.txt) no primeiro nível."""
    try:
        if not Path(pasta).is_dir():
            return False
        nomes = os.listdir(pasta)
    except OSError:
        return False
    return any(n in MARCAS_PROJETO or (n.startswith("requirements") and n.endswith(".txt")) for n in nomes)


@dataclass
class RelatorioProjeto:
    raiz: Path
    achados: list[Achado]
    arquivos: int
    cortado: bool
    completo: bool
    arquivos_ilegiveis: list[str] = field(default_factory=list)
    deps: ResultadoDeps = field(default_factory=lambda: ResultadoDeps([], 0, 0, None))
    limite: int = MAX_ARQUIVOS

    def avisos(self) -> list[str]:
        """O que ficou de fora da verificação, para o rodapé do CLI e a barra de status do app."""
        saida = []
        if self.cortado and self.completo:
            saida.append(f"Verificação incompleta: cortada em {_milhar(self.limite)} arquivos.")
        k = self.deps.detalhes_faltando
        if k == 1:
            saida.append("Aviso: 1 aviso do OSV.dev não pôde ser baixado.")
        elif k > 1:
            saida.append(f"Aviso: {_milhar(k)} avisos do OSV.dev não puderam ser baixados.")
        return saida


def _eh_mcp(rel: str) -> bool:
    return any(rel == s or rel.endswith("/" + s) for s in _MCP_REL)


def _pacotes_mcp(rel: str, texto: str) -> list[Dependencia]:
    try:
        dados = jsonc.carregar(texto)
        return [Dependencia(eco, nome, versao, rel) for eco, nome, versao in abrir.pacotes_mcp(dados)]
    except Exception:  # noqa: BLE001 - o `abrir` já informa JSON inválido
        return []


def _subir_mcp_malicioso(achados: list[Achado], mcp_deps: list[Dependencia]) -> list[Achado]:
    maliciosos = [a for a in achados if a.regra == "projeto.dep.malicioso"]
    if not maliciosos:
        return achados
    sobem: set[int] = set()
    for dep in mcp_deps:
        if not any(m.caminho == dep.origem and m.explicacao.startswith(f"{dep.nome} ") for m in maliciosos):
            continue
        for i, a in enumerate(achados):
            if a.regra == "projeto.abrir.mcp" and a.caminho == dep.origem and dep.nome in a.trecho:
                sobem.add(i)
    return [replace(a, severidade=Severity.HIGH) if i in sobem and a.severidade < Severity.HIGH else a
            for i, a in enumerate(achados)]


def verificar_projeto(
    raiz: Path,
    *,
    osv: OsvClient | None,
    kev: KevCache | None,
    excluir: Callable[[Path], bool] = lambda p: False,
    limite: int = MAX_ARQUIVOS,
    ao_progresso: Callable[[int, int], None] | None = None,
    ao_consultar: Callable[[int], None] | None = None,
    deve_parar: Callable[[], bool] = lambda: False,
) -> RelatorioProjeto:
    raiz = Path(raiz)
    fixos, fixos_cortado = listar_prioritarios(raiz, _FIXOS, _PASTAS_FIXAS, _fixo_na_raiz, excluir)
    outros, cortado = listar(raiz, excluir, limite, deve_parar)
    rels = sorted(set(fixos).union(outros))
    cortado = cortado or fixos_cortado
    pastas: dict[str, set[str]] = {}
    for rel in rels:
        pastas.setdefault(posixpath.dirname(rel), set()).add(posixpath.basename(rel))

    achados: list[Achado] = []
    ilegiveis: set[str] = set()
    deps: list[Dependencia] = []
    mcp_deps: list[Dependencia] = []
    sem_versao = 0
    arquivos = 0
    parou = False
    total = len(rels)

    for i, rel in enumerate(rels, 1):
        if deve_parar():
            parou = True
            break
        texto = ler_texto(raiz / rel)
        if texto is not None:
            arquivos += 1
            for familia in _FAMILIAS:
                try:
                    achados += familia.verificar(raiz, rel, texto)
                except Exception:  # noqa: BLE001 - ArquivoIlegivel ou falha inesperada: conta e segue
                    ilegiveis.add(rel)
            try:
                if lockfiles.eh_lockfile(rel):
                    d, s = lockfiles.ler_lockfile(rel, texto)
                    deps += d
                    sem_versao += s
                sem_versao += lockfiles.dependencias_sem_lockfile(rel, texto, pastas[posixpath.dirname(rel)])
            except Exception:  # noqa: BLE001
                ilegiveis.add(rel)
            if _eh_mcp(rel):
                mcp_deps += _pacotes_mcp(rel, texto)
        if ao_progresso is not None:
            ao_progresso(i, total)

    try:
        achados += abrir.verificar_git(raiz)
    except Exception:  # noqa: BLE001
        ilegiveis.add(".git")
    achados = limitar(achados)  # no máximo 20 por (arquivo, regra) em todas as famílias

    if parou or deve_parar():
        parou = True
        resultado = ResultadoDeps([], 0, sem_versao, _INTERROMPIDO)
    else:
        resultado = verificar_dependencias(deps + mcp_deps, sem_versao, osv, kev, ao_consultar)
        achados += resultado.achados
        achados = _subir_mcp_malicioso(achados, mcp_deps)

    achados.sort(key=lambda a: (-int(a.severidade), a.caminho, a.linha or 0))
    return RelatorioProjeto(
        raiz=raiz, achados=achados, arquivos=arquivos, cortado=cortado,
        completo=not parou, arquivos_ilegiveis=sorted(ilegiveis), deps=resultado, limite=limite,
    )
