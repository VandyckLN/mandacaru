"""Familia 3: o que executa ao instalar dependencias (npm, setup.py, backend local)."""
from __future__ import annotations

import ast
import json
import os
import re
import stat
from itertools import islice
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

from ..detectors.static import script_heuristics
from ..events import Severity
from . import jsonc
from .abrir import baixa_e_executa, linha_perigosa
from .achado import Achado, ArquivoIlegivel
from .percurso import Linhas, ler_texto

MITRE_NPM = ("T1195.002", "T1059")
MITRE_PY = ("T1195.002",)
_GANCHOS = ("preinstall", "install", "postinstall", "prepare")
_MAX_CMD = 10_000
_MAX_CANDIDATOS = 200

_NODE_E = re.compile(r"\bnode\s{1,20}(?:-{1,2}[\w-]{1,30}\s{1,20}){0,5}?(?:-e|--eval|-p)\b")
_NODE_E_B64 = re.compile(r"base64|atob|Buffer\.from")
_NODE_ARQ = re.compile(
    r"\bnode\s{1,20}(?:-{1,2}[\w-]{1,30}\s{1,20}){0,5}[\"']?([^\s\"';&|<>]{1,300}\.(?:[mc]?js))\b")

_SH_ARQ = re.compile(
    r"(?:\b(?:ba|z|da|k)?sh\s{1,20}(?:-{1,2}[\w-]{1,30}\s{1,20}){0,5}[\"']?|(?<![\w./-])(?=\./))"
    r"([^\s\"';&|<>]{1,300})")

_PY_REDE = {"urllib", "requests", "socket", "httpx"}
_PY_CHAMADA_CMD = {"os.system", "os.popen"}
_PY_DECODERS = {"b64decode", "decompress", "fromhex"}
_PY_CMD_ALVO = re.compile(r"curl|wget|http", re.IGNORECASE)

_RE_IMPORT = re.compile(
    r"^[ \t]{0,40}(?:import|from)[ \t]{1,20}(?:urllib|requests|socket|httpx|http\.client)\b", re.MULTILINE)
_RE_IMPORT_HTTP = re.compile(r"^[ \t]{0,40}from[ \t]{1,20}http[ \t]{1,20}import[ \t]{1,20}client\b", re.MULTILINE)
_RE_CHAMADA_CMD = re.compile(r"\b(?:subprocess\.\w{1,20}|os\.(?:system|popen))[ \t]{0,10}\(")
_RE_EXEC = re.compile(r"\b(?:exec|eval)[ \t]{0,10}\(")
_RE_DECODER = re.compile(r"b64decode|decompress|fromhex|codecs\.decode")


def verificar(raiz: Path, rel: str, texto: str) -> list[Achado]:
    nome = rel.rsplit("/", 1)[-1]
    if nome == "package.json":
        return _npm(Path(raiz), rel, texto)
    if nome == "setup.py":
        return _setup_py(rel, texto)
    if nome == "pyproject.toml":
        return _backend_local(rel, texto)
    return []


# --- npm -------------------------------------------------------------------

def _linha(ln: Linhas, valor: str, chave: str) -> int | None:
    for v in (valor, json.dumps(valor)[1:-1]):
        if v and (n := ln.do_trecho(v)) is not None:
            return n
    return ln.do_trecho(f'"{chave}"')


def _sem_links(raiz: str, alvo: str) -> bool:
    """True se nenhum componente entre `raiz` e `alvo` e link simbolico."""
    atual = raiz
    for parte in os.path.relpath(alvo, raiz).split(os.sep):
        atual = os.path.join(atual, parte)
        try:
            if stat.S_ISLNK(os.lstat(atual).st_mode):
                return False
        except (OSError, ValueError):
            return False
    return True


def _ler_do_projeto(raiz: Path, rel: str, caminho: str) -> str | None:
    """Arquivo citado num script do package.json: só dentro da raiz, sem links em nenhum componente."""
    if "\x00" in caminho:
        return None
    base = os.path.abspath(raiz)
    pasta = os.path.join(base, *rel.split("/")[:-1])
    alvo = os.path.normpath(os.path.join(pasta, caminho))
    try:
        if os.path.commonpath([base, alvo]) != base or alvo == base or not _sem_links(base, alvo):
            return None
    except ValueError:
        return None
    return ler_texto(Path(alvo))


def _script_node_suspeito(raiz: Path, rel: str, cmd: str) -> bool:
    for m in islice(_NODE_ARQ.finditer(cmd), 5):
        conteudo = _ler_do_projeto(raiz, rel, m.group(1))
        if conteudo and script_heuristics(Path("alvo.js"), conteudo.encode("utf-8", "replace")):
            return True
    return False


def _script_shell_suspeito(raiz: Path, rel: str, cmd: str) -> bool:
    """`bash x.sh`, `sh x.sh`, `./x.sh`: lê o script e procura, linha a linha, baixa-e-executa."""
    for m in islice(_SH_ARQ.finditer(cmd), 5):
        conteudo = _ler_do_projeto(raiz, rel, m.group(1))
        if conteudo and linha_perigosa(conteudo) is not None:
            return True
    return False


def _npm(raiz: Path, rel: str, texto: str) -> list[Achado]:
    try:
        dados = jsonc.carregar(texto)
    except (ValueError, RecursionError, MemoryError) as exc:
        raise ArquivoIlegivel(rel) from exc
    scripts = dados.get("scripts") if isinstance(dados, dict) else None
    if not isinstance(scripts, dict):
        return []
    saida = []
    ln = Linhas(texto)
    for gancho in _GANCHOS:
        cmd = scripts.get(gancho)
        if not isinstance(cmd, str):
            continue
        avaliado = cmd[:_MAX_CMD]
        perigoso = (
            baixa_e_executa(cmd)
            or bool(_NODE_E.search(avaliado) and _NODE_E_B64.search(avaliado))
            or _script_node_suspeito(raiz, rel, avaliado)
            or _script_shell_suspeito(raiz, rel, avaliado)
        )
        saida.append(Achado(
            "projeto.instalar.script_npm",
            Severity.HIGH if perigoso else Severity.LOW,
            rel,
            f"script '{gancho}' roda automaticamente ao instalar as dependências"
            + (" e baixa ou decodifica código para executar" if perigoso else ""),
            _linha(ln, cmd, gancho), cmd, MITRE_NPM))
    return saida


# --- setup.py --------------------------------------------------------------

def _nome_ponto(no: ast.AST) -> str:
    partes = []
    while isinstance(no, ast.Attribute):
        partes.append(no.attr)
        no = no.value
    if isinstance(no, ast.Name):
        partes.append(no.id)
    return ".".join(reversed(partes))


def _ast_gatilho(arvore: ast.AST) -> int | None:
    """Linha do primeiro gatilho (a) ou (b), ou None."""
    achou: list[int] = []
    for no in ast.walk(arvore):
        linha = getattr(no, "lineno", 0)
        if isinstance(no, ast.Import):
            if any(a.name.split(".")[0] in _PY_REDE or a.name.startswith("http.client") for a in no.names):
                achou.append(linha)
        elif isinstance(no, ast.ImportFrom) and no.module and not no.level:
            raiz_mod = no.module.split(".")[0]
            if (raiz_mod in _PY_REDE or no.module.startswith("http.client")
                    or (no.module == "http" and any(a.name == "client" for a in no.names))):
                achou.append(linha)
        elif isinstance(no, ast.Call):
            nome = _nome_ponto(no.func)
            args = [*no.args, *(k.value for k in no.keywords)]
            if nome.startswith("subprocess.") or nome in _PY_CHAMADA_CMD:
                if any(isinstance(n, ast.Constant) and isinstance(n.value, str) and _PY_CMD_ALVO.search(n.value)
                       for a in args for n in ast.walk(a)):
                    achou.append(linha)
            elif nome in ("exec", "eval"):
                for a in args:
                    for n in ast.walk(a):
                        if isinstance(n, ast.Call):
                            alvo = _nome_ponto(n.func)
                            if alvo.rsplit(".", 1)[-1] in _PY_DECODERS or alvo == "codecs.decode":
                                achou.append(linha)
    return min(achou) if achou else None


def _regex_gatilho(texto: str) -> int | None:
    pos: list[int] = []
    for rx in (_RE_IMPORT, _RE_IMPORT_HTTP):
        m = rx.search(texto)
        if m:
            pos.append(m.start())
    for m in islice(_RE_CHAMADA_CMD.finditer(texto), _MAX_CANDIDATOS):
        resto = texto[m.end():m.end() + 500].split("\n", 1)[0]
        if _PY_CMD_ALVO.search(resto):
            pos.append(m.start())
            break
    for m in islice(_RE_EXEC.finditer(texto), _MAX_CANDIDATOS):
        if _RE_DECODER.search(texto, m.end(), m.end() + 300):
            pos.append(m.start())
            break
    return Linhas(texto).de(min(pos)) if pos else None


def _setup_py(rel: str, texto: str) -> list[Achado]:
    try:
        linha = _ast_gatilho(ast.parse(texto))
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        linha = _regex_gatilho(texto)
    if linha is None:
        return []
    linhas = texto.split("\n")
    trecho = linhas[linha - 1].strip()[:300] if linha <= len(linhas) else ""
    return [Achado(
        "projeto.instalar.setup_py", Severity.HIGH, rel,
        "setup.py acessa a rede, executa comandos de download ou executa código decodificado ao instalar",
        linha, trecho, MITRE_PY)]


# --- pyproject -------------------------------------------------------------

def _backend_local(rel: str, texto: str) -> list[Achado]:
    try:
        dados = tomllib.loads(texto)
    except (tomllib.TOMLDecodeError, RecursionError, MemoryError, ValueError) as exc:
        raise ArquivoIlegivel(rel) from exc
    build = dados.get("build-system")
    caminhos = build.get("backend-path") if isinstance(build, dict) else None
    if not isinstance(caminhos, list) or not caminhos:
        return []
    return [Achado(
        "projeto.instalar.backend_local", Severity.LOW, rel,
        "o build usa um backend local (backend-path): código do próprio projeto roda ao instalar",
        Linhas(texto).do_trecho("backend-path"), "backend-path", MITRE_PY)]
