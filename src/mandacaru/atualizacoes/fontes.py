"""O que o apt, o Snap e o Flatpak atualizariam, consultado sem root e sem shell.

Cada fonte so e consultada se o comando existir. Os comandos rodam com LC_ALL=C: a saida fica em ingles e
o parse nao depende do idioma da pessoa. Nome que nao passa na regra do gerenciador e descartado, para
nunca chegar a um comando de atualizacao.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

# (codigo de saida, stdout, stderr)
Runner = Callable[[list[str]], tuple[int, str, str]]
Which = Callable[[str], "str | None"]

APT_LISTS = Path("/var/lib/apt/lists")
TIMEOUT = 180  # snap e flatpak consultam a loja/remoto pela rede

DESCONHECIDO = "DESCONHECIDO"  # sem dados de CVE para o item (Snap, Flatpak ou sem relatorio)
NENHUM = "NENHUM"  # relatorio consultado e nenhuma CVE conhecida para o pacote-fonte
PRE_SELECIONADOS = ("CRITICAL_ACTIVE", "HIGH")
ORDEM_RISCO = {"CRITICAL_ACTIVE": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, NENHUM: 4, DESCONHECIDO: 5}

# Regras de nome por gerenciador:
# - apt: politica Debian (minusculas, digitos, + . -; comeca por alfanumerico)
_APT = re.compile(r"[a-z0-9][a-z0-9+.-]*")
# - snap: regra do snapd (minusculas, digitos e hifens nao repetidos, ao menos uma letra, ate 40) e a
#   chave opcional de instancia paralela "_chave" (ate 10 minusculas/digitos)
_SNAP = re.compile(r"((?:[a-z0-9]+-?)*[a-z](?:-?[a-z0-9])*)(?:_[a-z0-9]{1,10})?")
# - flatpak: id reverso-DNS com 3+ partes de [A-Za-z0-9_-] sem comecar por digito, ate 255; o nome
#   mostrado e "ID//RAMO" (ramo sem barra, sem comecar por hifen), que o `flatpak update` aceita
_FLATPAK_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*){2,}")
_FLATPAK_RAMO = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")

# libssl3/jammy-updates,jammy-security 3.0.2-0ubuntu1.15 amd64 [upgradable from: 3.0.2-0ubuntu1.14]
_APT_LINHA = re.compile(r"^(?P<nome>\S+?)/\S+\s+(?P<disp>\S+)\s+\S+\s+\[upgradable from:\s*(?P<inst>[^\]\s]+)\s*\]")
_APT_AVISO = "WARNING: apt does not have a stable CLI interface"
_CONTROLE = re.compile(r"[\x00-\x1f\x7f]")


def nome_valido(gerenciador: str, nome: str) -> bool:
    if gerenciador == "apt":
        return len(nome) <= 128 and _APT.fullmatch(nome) is not None
    if gerenciador == "snap":
        m = _SNAP.fullmatch(nome)
        return m is not None and len(m.group(1)) <= 40
    if gerenciador.startswith("flatpak"):
        app, sep, ramo = nome.partition("//")
        if len(app) > 255 or _FLATPAK_ID.fullmatch(app) is None:
            return False
        return not sep or (len(ramo) <= 255 and _FLATPAK_RAMO.fullmatch(ramo) is not None)
    return False


def _limpo(texto: str) -> str | None:
    """Versao vinda de comando externo: sem caracteres de controle; vazia vira None."""
    texto = _CONTROLE.sub("", texto).strip()
    return texto or None


@dataclass(frozen=True)
class Atualizacao:
    gerenciador: str  # apt | snap | flatpak-sistema | flatpak-usuario
    nome: str
    instalada: str | None
    disponivel: str | None
    risco: str = DESCONHECIDO
    cves: tuple[str, ...] = ()

    @property
    def selecionado(self) -> bool:
        return self.risco in PRE_SELECIONADOS

    def to_dict(self) -> dict:
        d = asdict(self)
        d["cves"] = list(self.cves)
        d["selecionado"] = self.selecionado
        return d


@dataclass
class Coleta:
    itens: list[Atualizacao] = field(default_factory=list)
    fontes: list[str] = field(default_factory=list)  # comandos que existiam e foram consultados
    erros: list[str] = field(default_factory=list)
    apt_atualizado_em: float | None = None  # mtime de /var/lib/apt/lists (ultimo `apt update`)


def executar(argv: list[str]) -> tuple[int, str, str]:
    """Roda sem shell, sem stdin e com LC_ALL=C (LANGUAGE sai: o gettext o leria antes do LC_ALL)."""
    env = {k: v for k, v in os.environ.items() if k != "LANGUAGE"}
    env["LC_ALL"] = "C"
    try:
        r = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
                           stdin=subprocess.DEVNULL, timeout=TIMEOUT, check=False)
    except FileNotFoundError:
        return 127, "", f"{argv[0]}: comando nao encontrado"
    except subprocess.TimeoutExpired:
        return 124, "", f"{argv[0]}: sem resposta em {TIMEOUT} s"
    except OSError as exc:
        return 126, "", f"{argv[0]}: {exc.strerror or exc}"
    return r.returncode, r.stdout, r.stderr


def _motivo(stderr: str, rc: int) -> str:
    linhas = [ln.strip() for ln in stderr.splitlines() if ln.strip() and not ln.startswith(_APT_AVISO)]
    return _CONTROLE.sub("", linhas[0])[:200] if linhas else f"saiu com codigo {rc}"


def parse_apt(saida: str) -> list[Atualizacao]:
    """`apt list --upgradable`; ignora "Listing..." e o aviso de CLI instavel (se vier misturado)."""
    itens = []
    for linha in saida.splitlines():
        m = _APT_LINHA.match(linha.strip())
        if not m or not nome_valido("apt", m["nome"]):
            continue
        item = Atualizacao("apt", m["nome"], _limpo(m["inst"]), _limpo(m["disp"]))
        if item not in itens:  # multiarch: o mesmo pacote em amd64 e i386 vira uma linha so
            itens.append(item)
    return itens


def _colunas_snap(saida: str) -> dict[str, str]:
    """Nome -> versao das tabelas do snap (cabecalho "Name Version ..." cai na regra de nome)."""
    versoes = {}
    for linha in saida.splitlines():
        partes = linha.split()
        if len(partes) >= 2 and nome_valido("snap", partes[0]):
            versoes[partes[0]] = partes[1]
    return versoes


def parse_snap(refresh: str, instalados: str = "") -> list[Atualizacao]:
    """`snap refresh --list` (versao nova) + `snap list` (versao instalada).

    Sem nada pendente o snap escreve "All snaps up to date." no stderr e nada no stdout.
    """
    atual = _colunas_snap(instalados)
    return [Atualizacao("snap", nome, _limpo(atual.get(nome, "")), _limpo(versao))
            for nome, versao in _colunas_snap(refresh).items()]


def _colunas_flatpak(saida: str) -> list[tuple[str, str, str]]:
    """Linhas "application<TAB>branch<TAB>version" (sem terminal o flatpak nao imprime cabecalho)."""
    linhas = []
    for linha in saida.splitlines():
        partes = linha.split("\t") if "\t" in linha else linha.split()
        if len(partes) < 2:
            continue
        app, ramo = partes[0].strip(), partes[1].strip()
        versao = partes[2] if len(partes) > 2 else ""
        if nome_valido("flatpak", f"{app}//{ramo}"):
            linhas.append((app, ramo, versao))
    return linhas


def parse_flatpak(atualizacoes: str, instalados: str, gerenciador: str) -> list[Atualizacao]:
    """`flatpak remote-ls --updates` + `flatpak list`, os dois com --columns=application,branch,version."""
    atual = {(app, ramo): versao for app, ramo, versao in _colunas_flatpak(instalados)}
    vistos: set[str] = set()
    itens = []
    for app, ramo, versao in _colunas_flatpak(atualizacoes):
        nome = f"{app}//{ramo}"
        if nome not in vistos:
            vistos.add(nome)
            itens.append(Atualizacao(gerenciador, nome, _limpo(atual.get((app, ramo), "")), _limpo(versao)))
    return itens


_COLUNAS = "--columns=application,branch,version"


def coletar(runner: Runner = executar, which: Which = shutil.which, apt_lists: Path = APT_LISTS) -> Coleta:
    c = Coleta()

    if which("apt"):
        c.fontes.append("apt")
        try:
            c.apt_atualizado_em = apt_lists.stat().st_mtime
        except OSError:
            pass
        rc, out, err = runner(["apt", "list", "--upgradable"])
        if rc == 0:
            c.itens += parse_apt(out)
        else:
            c.erros.append(f"apt: {_motivo(err, rc)}")

    if which("snap"):
        c.fontes.append("snap")
        rc, out, err = runner(["snap", "refresh", "--list"])
        if rc != 0:
            c.erros.append(f"snap: {_motivo(err, rc)}")
        elif out.strip():
            rc2, inst, _ = runner(["snap", "list"])
            c.itens += parse_snap(out, inst if rc2 == 0 else "")

    if which("flatpak"):
        c.fontes.append("flatpak")
        for escopo, gerenciador in (("--system", "flatpak-sistema"), ("--user", "flatpak-usuario")):
            rc, out, err = runner(["flatpak", "remote-ls", "--updates", escopo, _COLUNAS])
            if rc != 0:
                c.erros.append(f"{gerenciador}: {_motivo(err, rc)}")
            elif out.strip():
                rc2, inst, _ = runner(["flatpak", "list", escopo, _COLUNAS])
                c.itens += parse_flatpak(out, inst if rc2 == 0 else "", gerenciador)
    return c
