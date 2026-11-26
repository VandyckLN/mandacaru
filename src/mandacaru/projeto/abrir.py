"""Familia 2: o que executa ao abrir a pasta (VS Code, agente, MCP, devcontainer, git)."""
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

from ..events import Severity
from . import jsonc
from .achado import Achado, ArquivoIlegivel
from .percurso import ler_texto, linha_do_trecho

MITRE = ("T1204", "T1059")
_MAX_CMD = 10_000
_MAX_HOOKS_GIT = 200

_BAIXADOR = re.compile(
    r"\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|bitsadmin)\b"
    r"|\bcertutil\s+-urlcache|Net\.WebClient|DownloadString|DownloadFile",
    re.IGNORECASE,
)
_EXECUTOR = re.compile(
    r"\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|python3?|node|pwsh|powershell|iex)\b"
    r"|\b(?:iex|Invoke-Expression)\b"
    r"|(?:&&|;)\s*(?:(?:sh|bash)\b|chmod\s+\+x|\./)",
    re.IGNORECASE,
)
_B64_SHELL = re.compile(
    r"base64\s+(?:-d|--decode)[^|]{0,300}\|\s*(?:sh|bash|python|node)", re.IGNORECASE)
_B64_PS = re.compile(r"FromBase64String", re.IGNORECASE)
_B64_PS_EXEC = re.compile(r"\b(?:iex|Invoke-Expression)\b", re.IGNORECASE)
_B64_NODE = re.compile(r"Buffer\.from\([^)]{0,300}base64", re.IGNORECASE)
_B64_NODE_EXEC = re.compile(r"eval|Function\(|node\s+-e", re.IGNORECASE)
_CREDENCIAIS = re.compile(r"\.ssh|\.aws|\.env|id_rsa|credentials", re.IGNORECASE)
_GIT_CONFIG = re.compile(r"^[ \t]*(hooksPath|fsmonitor|sshCommand)[ \t]*=[ \t]*(.*)$",
                         re.IGNORECASE | re.MULTILINE)
_UNIDADE = re.compile(r"^[A-Za-z]:")


def baixa_e_executa(cmd: str) -> bool:
    """Baixa e executa, ou decodifica e executa. Avalia so os primeiros 10 000 caracteres."""
    cmd = cmd[:_MAX_CMD]
    if _BAIXADOR.search(cmd) and _EXECUTOR.search(cmd):
        return True
    if _B64_SHELL.search(cmd):
        return True
    if _B64_PS.search(cmd) and _B64_PS_EXEC.search(cmd):
        return True
    return bool(_B64_NODE.search(cmd) and _B64_NODE_EXEC.search(cmd))


def _comando_texto(cmd: object, args: object) -> str:
    partes = [cmd] if isinstance(cmd, str) else []
    if isinstance(args, list):
        partes += [a for a in args if isinstance(a, str)]
    return " ".join(partes)


def _linha(texto: str, valor: str, chave: str = "") -> int | None:
    for v in (valor, json.dumps(valor)[1:-1]):
        if v and (n := linha_do_trecho(texto, v)) is not None:
            return n
    return linha_do_trecho(texto, f'"{chave}"') if chave else None


def _achado(regra, sev, rel, expl, texto, valor, chave="", trecho=None) -> Achado:
    return Achado(regra, sev, rel, expl, _linha(texto, valor, chave),
                  (valor if trecho is None else trecho)[:300], MITRE)


# --- MCP -------------------------------------------------------------------

def _servidores(dados: object):
    if not isinstance(dados, dict):
        return
    for chave in ("mcpServers", "servers"):
        grupo = dados.get(chave)
        if isinstance(grupo, dict):
            for nome, srv in grupo.items():
                if isinstance(srv, dict):
                    yield str(nome), srv


def _nome_versao(ecossistema: str, arg: str) -> tuple[str, str]:
    if ecossistema == "npm":
        pos = arg.rfind("@")
        return (arg[:pos], arg[pos + 1:]) if pos > 0 else (arg, "")
    nome, sep, versao = arg.partition("==")
    return (nome, versao) if sep else (arg, "")


def pacotes_mcp(texto_json: object) -> list[tuple[str, str, str]]:
    """(ecossistema, nome, versao) dos servidores `npx` (npm) e `uvx` (PyPI)."""
    achados: list[tuple[str, str, str]] = []
    for _, srv in _servidores(texto_json):
        eco = {"npx": "npm", "uvx": "PyPI"}.get(srv.get("command"))
        args = srv.get("args")
        if eco is None or not isinstance(args, list):
            continue
        pacote = next((a for a in args if isinstance(a, str) and a and not a.startswith("-")), None)
        if pacote is not None:
            achados.append((eco, *_nome_versao(eco, pacote)))
    return achados


def _mcp(rel: str, texto: str, dados: object) -> list[Achado]:
    saida = []
    for nome, srv in _servidores(dados):
        linha_cmd = _comando_texto(srv.get("command"), srv.get("args"))
        if not linha_cmd:
            continue
        sev = Severity.HIGH if baixa_e_executa(linha_cmd) else Severity.LOW
        saida.append(_achado(
            "projeto.abrir.mcp", sev, rel,
            f"servidor MCP '{nome}' declarado: o agente o inicia ao abrir o projeto",
            texto, str(srv.get("command") or ""), nome, trecho=linha_cmd))
    return saida


# --- VS Code ---------------------------------------------------------------

def _tarefas(rel: str, texto: str, dados: object) -> list[Achado]:
    tarefas = dados.get("tasks") if isinstance(dados, dict) else None
    if not isinstance(tarefas, list):
        return []
    saida = []
    for t in tarefas:
        if not isinstance(t, dict):
            continue
        opcoes = t.get("runOptions")
        if not isinstance(opcoes, dict) or opcoes.get("runOn") != "folderOpen":
            continue
        variantes = [t] + [t[k] for k in ("windows", "linux", "osx") if isinstance(t.get(k), dict)]
        cmds = [c for v in variantes if (c := _comando_texto(v.get("command"), v.get("args")))]
        perigoso = any(baixa_e_executa(c) for c in cmds)
        principal = next((c for c in cmds if baixa_e_executa(c)), cmds[0] if cmds else "")
        valor = t.get("command") if isinstance(t.get("command"), str) else ""
        if perigoso:
            valor = next((v["command"] for v in variantes
                          if isinstance(v.get("command"), str) and baixa_e_executa(
                              _comando_texto(v.get("command"), v.get("args")))), valor)
        saida.append(_achado(
            "projeto.abrir.tarefa_automatica",
            Severity.HIGH if perigoso else Severity.MEDIUM, rel,
            "tarefa configurada para rodar sozinha ao abrir a pasta",
            texto, valor, "folderOpen", trecho=principal))
    return saida


def _caminho_do_projeto(valor: str) -> bool:
    if valor.startswith(("./", "../", ".\\", "${workspaceFolder}")):
        return True
    if not valor or valor.startswith(("/", "\\", "~", "${")) or _UNIDADE.match(valor):
        return False
    return "/" in valor or "\\" in valor


def _settings_vscode(rel: str, texto: str, dados: object) -> list[Achado]:
    if not isinstance(dados, dict):
        return []
    saida = []
    for chave, valor in dados.items():
        if not isinstance(chave, str):
            continue
        if isinstance(valor, str) and (
                chave == "python.defaultInterpreterPath"
                or chave.endswith((".path", "Path"))) and _caminho_do_projeto(valor):
            saida.append(_achado(
                "projeto.abrir.executavel_do_projeto", Severity.MEDIUM, rel,
                f"'{chave}' aponta um executável para dentro do projeto", texto, valor, chave))
        elif chave.startswith("terminal.integrated.env.") and isinstance(valor, dict):
            for var in valor:
                if isinstance(var, str) and var.upper() in {"PATH", "NODE_OPTIONS", "PYTHONSTARTUP"}:
                    saida.append(_achado(
                        "projeto.abrir.executavel_do_projeto", Severity.MEDIUM, rel,
                        f"o terminal do VS Code define {var} para o projeto", texto, str(var), chave))
    return saida


# --- Claude ----------------------------------------------------------------

def _claude(rel: str, texto: str, dados: object) -> list[Achado]:
    if not isinstance(dados, dict):
        return []
    saida = []
    hooks = dados.get("hooks")
    if isinstance(hooks, dict):
        for evento, regras in hooks.items():
            if not isinstance(regras, list):
                continue
            for regra in regras:
                lista = regra.get("hooks") if isinstance(regra, dict) else None
                if not isinstance(lista, list):
                    continue
                for h in lista:
                    cmd = h.get("command") if isinstance(h, dict) else None
                    if not isinstance(cmd, str):
                        continue
                    grave = baixa_e_executa(cmd) or bool(_CREDENCIAIS.search(cmd))
                    saida.append(_achado(
                        "projeto.abrir.hook_agente",
                        Severity.HIGH if grave else Severity.MEDIUM, rel,
                        f"hook '{evento}' do agente executa um comando do projeto", texto, cmd,
                        str(evento)))
    perm = dados.get("permissions")
    allow = perm.get("allow") if isinstance(perm, dict) else None
    if isinstance(allow, list) and any(a in ("Bash", "Bash(*)") for a in allow if isinstance(a, str)):
        saida.append(_achado(
            "projeto.abrir.permissao_ampla", Severity.MEDIUM, rel,
            "o projeto libera qualquer comando Bash para o agente", texto, "Bash", "allow"))
    if dados.get("enableAllProjectMcpServers") is True:
        saida.append(_achado(
            "projeto.abrir.permissao_ampla", Severity.MEDIUM, rel,
            "o projeto aprova sozinho todos os servidores MCP", texto, "",
            "enableAllProjectMcpServers"))
    return saida


# --- devcontainer ----------------------------------------------------------

_DEV_SEV = {
    "initializeCommand": Severity.MEDIUM,  # roda no host
    "postCreateCommand": Severity.LOW,
    "postStartCommand": Severity.LOW,
    "postAttachCommand": Severity.LOW,
}


def _achatar(valor: object) -> str:
    if isinstance(valor, str):
        return valor
    if isinstance(valor, list):
        return " ".join(v for v in valor if isinstance(v, str))
    if isinstance(valor, dict):
        return "; ".join(_achatar(v) for v in valor.values() if isinstance(v, (str, list)))
    return ""


def _devcontainer(rel: str, texto: str, dados: object) -> list[Achado]:
    if not isinstance(dados, dict):
        return []
    saida = []
    for chave, base in _DEV_SEV.items():
        cmd = _achatar(dados.get(chave))
        if not cmd:
            continue
        sev = Severity.HIGH if baixa_e_executa(cmd) else base
        onde = "no computador (host)" if chave == "initializeCommand" else "no container"
        saida.append(_achado(
            "projeto.abrir.devcontainer", sev, rel,
            f"'{chave}' executa um comando {onde} ao abrir o projeto", texto,
            dados[chave] if isinstance(dados[chave], str) else "", chave, trecho=cmd))
    return saida


_POR_REL = {
    ".vscode/tasks.json": _tarefas,
    ".vscode/settings.json": _settings_vscode,
    ".claude/settings.json": _claude,
    ".claude/settings.local.json": _claude,
    ".mcp.json": _mcp,
    ".cursor/mcp.json": _mcp,
    ".vscode/mcp.json": _mcp,
    ".devcontainer/devcontainer.json": _devcontainer,
    ".devcontainer.json": _devcontainer,
}


def verificar(raiz: Path, rel: str, texto: str) -> list[Achado]:
    tratador = _POR_REL.get(rel)
    if tratador is None:
        return []
    try:
        dados = jsonc.carregar(texto)
    except ValueError as exc:
        raise ArquivoIlegivel(rel) from exc
    return tratador(rel, texto, dados)


# --- git -------------------------------------------------------------------

def verificar_git(raiz: Path) -> list[Achado]:
    saida: list[Achado] = []
    pasta = Path(raiz) / ".git" / "hooks"
    try:
        nomes = sorted(os.listdir(pasta))[:_MAX_HOOKS_GIT]
    except OSError:
        nomes = []
    for nome in nomes:
        if nome.endswith(".sample"):
            continue
        alvo = pasta / nome
        try:
            if not stat.S_ISREG(os.lstat(alvo).st_mode):
                continue
        except OSError:
            continue
        conteudo = ler_texto(alvo) or ""
        sev = Severity.HIGH if baixa_e_executa(conteudo) else Severity.MEDIUM
        saida.append(Achado(
            "projeto.abrir.git_hook", sev, f".git/hooks/{nome}",
            "hook do git presente: roda em comandos como commit, checkout e push",
            None, conteudo[:300].strip(), MITRE))
    config = ler_texto(Path(raiz) / ".git" / "config")
    if config:
        for m in _GIT_CONFIG.finditer(config):
            chave, valor = m.group(1), m.group(2).strip()
            if chave.lower() == "fsmonitor" and valor.lower() in ("true", "false"):
                continue
            saida.append(Achado(
                "projeto.abrir.git_hook", Severity.MEDIUM, ".git/config",
                f"'{chave}' em .git/config faz o git executar um programa",
                linha_do_trecho(config, m.group(0)), m.group(0).strip()[:300], MITRE))
    return saida
