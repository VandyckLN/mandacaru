"""Subcomando `mandacaru dev <pasta>`: verifica um projeto antes de abri-lo ou instalá-lo."""
from __future__ import annotations

import os
import sys
import unicodedata
from pathlib import Path

from ..config import ConfigError, load_config
from ..events import Severity
from . import RelatorioProjeto, verificar_projeto
from .achado import Achado
from .percurso import MAX_ARQUIVOS, excluir_por_globs

_SECOES = (
    (("agente", "texto"), "Instruções para agentes de IA"),
    (("abrir",), "Executa ao abrir a pasta"),
    (("instalar",), "Executa ao instalar dependências"),
    (("unicode",), "Código com Unicode enganoso"),
    (("ci",), "GitHub Actions"),
    (("dep",), "Bibliotecas"),
)


def cache_padrao() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "Mandacaru" / "cache"
    xdg = os.environ.get("XDG_CACHE_HOME")
    return Path(xdg) / "mandacaru" if xdg else Path.home() / ".cache" / "mandacaru"


def add_parser(sub) -> None:
    p = sub.add_parser("dev", help="verifica um projeto (agentes de IA, tarefas ao abrir, dependências)")
    p.add_argument("pasta", help="pasta do projeto")
    p.add_argument("--sem-rede", action="store_true", help="não consulta OSV.dev nem CISA KEV")
    p.add_argument("--cache-dir", default=None, help="pasta do cache SQLite (padrão: cache do usuário)")
    p.set_defaults(fn=cmd_dev)


def _limpo(texto: str) -> str:
    """Escapa controles e caracteres invisíveis: o conteúdo vem do projeto e não pode mexer no terminal."""
    return "".join(
        f"\\u{ord(c):04x}" if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") and c != " " else c
        for c in texto)


def _linha(a: Achado) -> list[str]:
    onde = a.caminho if a.linha is None else f"{a.caminho}:{a.linha}"
    saida = [f"  {a.severidade.name:<8}  {_limpo(onde)}  {_limpo(a.explicacao)}"]
    if a.trecho:
        saida.append(" " * 13 + _limpo(a.trecho))
    return saida


def formatar(rel: RelatorioProjeto) -> str:
    linhas = [f"Mandacaru · verificação de projeto: {_limpo(str(rel.raiz))}", ""]
    relevantes = [a for a in rel.achados if a.severidade > Severity.LOW]
    baixos = [a for a in rel.achados if a.severidade <= Severity.LOW]
    if not rel.achados:
        linhas += ["Nada suspeito encontrado.", ""]
    for familias, titulo in _SECOES:
        grupo = [a for a in relevantes if a.regra.split(".")[1:2] and a.regra.split(".")[1] in familias]
        if grupo:
            linhas.append(titulo)
            for a in grupo:
                linhas += _linha(a)
            linhas.append("")
    if baixos:
        linhas.append("Para conhecimento")
        for a in baixos:
            linhas += _linha(a)
        linhas.append("")
    rodape = [f"{rel.arquivos} arquivos lidos"]
    if rel.deps.erro:
        rodape.append(rel.deps.erro)
    else:
        rodape.append(f"{rel.deps.verificadas} bibliotecas verificadas")
    if rel.deps.sem_versao > 0:
        rodape.append(f"{rel.deps.sem_versao} sem versão fixa não verificadas")
    if rel.cortado:
        rodape.append(f"cortado em {MAX_ARQUIVOS:,}".replace(",", ".") + " arquivos")
    if rel.arquivos_ilegiveis:
        rodape.append(f"{len(rel.arquivos_ilegiveis)} arquivos ilegíveis")
    linhas.append(" · ".join(rodape))
    contagem = {s: sum(1 for a in rel.achados if a.severidade == s) for s in Severity}
    linhas.append(
        f"Resultado: {contagem[Severity.CRITICAL]} críticos, {contagem[Severity.HIGH]} altos, "
        f"{contagem[Severity.MEDIUM]} médios, {len(baixos)} para conhecimento")
    return "\n".join(linhas)


def cmd_dev(args) -> int:
    raiz = Path(args.pasta)
    if not raiz.is_dir():
        raise ConfigError(f"pasta não encontrada: {args.pasta}")
    globs = list(load_config(args.config).exclude)
    if args.json:
        globs.append(os.path.abspath(args.json))
    osv = kev = None
    if not args.sem_rede:
        from ..vuln import KevCache, OsvClient
        cache = Path(args.cache_dir) if args.cache_dir else cache_padrao()
        try:
            osv = OsvClient(cache_db=cache / "osv.db")
            kev = KevCache(cache_db=cache / "kev.db")
        except OSError as exc:
            raise ConfigError(f"não foi possível usar o cache {cache}: {exc.strerror or exc}") from exc

    def consultando(n: int) -> None:
        print(f"Consultando {n} bibliotecas no OSV.dev...", file=sys.stderr)

    rel = verificar_projeto(raiz, osv=osv, kev=kev, excluir=excluir_por_globs(globs), ao_consultar=consultando)
    if args.json:
        try:
            with open(args.json, "a", encoding="utf-8") as fh:
                for a in rel.achados:
                    fh.write(a.to_alert(rel.raiz).to_json() + "\n")
        except OSError as exc:
            raise ConfigError(f"não foi possível gravar alertas em {args.json}: {exc.strerror or exc}") from exc
    print(formatar(rel))
    return 2 if any(a.severidade >= Severity.HIGH for a in rel.achados) else 0
