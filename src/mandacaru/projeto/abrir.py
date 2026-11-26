"""Familia 2: o que executa ao abrir a pasta (VS Code, agente, MCP, devcontainer, git)."""
from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import replace
from pathlib import Path

from ..events import Severity
from . import jsonc
from .achado import Achado, ArquivoIlegivel, limitar
from .percurso import Linhas, ler_texto

MITRE = ("T1204", "T1059")
_MAX_CMD = 10_000
_MAX_HOOKS_GIT = 200

_BAIXADOR = re.compile(
    r"\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|bitsadmin)\b"
    r"|\bcertutil\s+-urlcache|Net\.WebClient|DownloadString|DownloadFile",
    re.IGNORECASE,
)
_CAMINHO = r"(?:/[\w.-]{1,100}){0,10}/"  # /bin/, /usr/bin/
# sudo -E, env A=1, /usr/bin/env ... entre o pipe e o interpretador
_PREFIXO = (rf"(?:{_CAMINHO})?(?:sudo|env|exec|command|nohup|doas)"
            r"(?:\s+(?:-{1,2}[\w=-]{1,30}|\w{1,30}=\S{0,200})){0,10}\s+")
_INTERPRETADOR = r"(?:sh|bash|zsh|dash|ksh|python[\d.]{0,5}|node|perl|ruby|pwsh|powershell|iex)\b"
_EXECUTOR = re.compile(
    rf"\|\s*(?:{_PREFIXO}){{0,3}}(?:{_CAMINHO})?{_INTERPRETADOR}"
    r"|\b(?:iex|Invoke-Expression)\b"
    r"|(?:&&|;)\s*(?:(?:sh|bash)\b|chmod\s+\+x|\./)"
    # bash -c "$(curl ...)", sh <(curl ...), source <(curl ...)
    r"|\b(?:sh|bash|zsh|dash|ksh|source)\s+(?:-[a-zA-Z]{1,10}\s+){0,5}(?:<\(|[\"']?\$\(|[\"']?`)",
    re.IGNORECASE,
)
_B64_SHELL = re.compile(
    r"base64\s+(?:-d|--decode)[^|]{0,300}\|\s*(?:sh|bash|python|node)", re.IGNORECASE)
_B64_PS = re.compile(r"FromBase64String", re.IGNORECASE)
_B64_PS_EXEC = re.compile(r"\b(?:iex|Invoke-Expression)\b", re.IGNORECASE)
_B64_NODE = re.compile(r"Buffer\.from\([^)]{0,300}base64", re.IGNORECASE)
_B64_NODE_EXEC = re.compile(r"eval|Function\(|node\s+-e", re.IGNORECASE)
_CREDENCIAIS = re.compile(r"\.ssh|\.aws|\.env|id_rsa|credentials", re.IGNORECASE)
_VERSAO_EXATA = re.compile(r"\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?")
_GIT_CONFIG = re.compile(r"^[ \t]*(?:\[[^\]\n]*\][ \t]*)?(hooksPath|fsmonitor|sshCommand)[ \t]*=[ \t]*(.*)$",
                         re.IGNORECASE | re.MULTILINE)
_UNIDADE = re.compile(r"^[A-Za-z]:")


def baixa_e_executa(cmd: str) -> bool:
    """Baixa e executa, ou decodifica e executa.

    Comando com mais de 10 000 caracteres e ofuscacao por si so (True); os demais sao avaliados inteiros.
    """
    if len(cmd) > _MAX_CMD:
        return True
    if _BAIXADOR.search(cmd) and _EXECUTOR.search(cmd):
        return True
    if _B64_SHELL.search(cmd):
        return True
    if _B64_PS.search(cmd) and _B64_PS_EXEC.search(cmd):
        return True
    return bool(_B64_NODE.search(cmd) and _B64_NODE_EXEC.search(cmd))


def _logicas(texto: str):
    """Linhas logicas de um script: junta continuacoes com barra invertida e linhas que terminam
    em `|`, `&&` ou `||` (o shell continua o comando na linha seguinte)."""
    acc: list[str] = []
    for linha in texto.split("\n"):
        linha = linha.removesuffix("\r")
        if linha.endswith("\\"):
            acc.append(linha[:-1])
            continue
        if linha.rstrip().endswith(("|", "&&")):
            acc.append(linha + " ")
            continue
        acc.append(linha)
        yield "".join(acc)
        acc = []
    if acc:
        yield "".join(acc)


def linha_perigosa(texto: str) -> str | None:
    """Primeira linha (logica) de um arquivo de script que baixa e executa, ou None.

    Um arquivo e avaliado linha a linha: um hook grande nao vira suspeito so pelo tamanho, e um
    `curl` numa linha nao se junta a um `| python` em outra.
    """
    for linha in _logicas(texto):
        if baixa_e_executa(linha):
            return linha
    return None


def _comando_texto(cmd: object, args: object) -> str:
    partes = [cmd] if isinstance(cmd, str) else []
    if isinstance(args, list):
        partes += [a for a in args if isinstance(a, str)]
    return " ".join(partes)


def _linha(ln: Linhas, valor: str, chave: str = "") -> int | None:
    for v in (valor, json.dumps(valor)[1:-1]):
        if v and (n := ln.do_trecho(v)) is not None:
            return n
    return ln.do_trecho(f'"{chave}"') if chave else None


def _achado(regra, sev, rel, expl, ln, valor, chave="", trecho=None) -> Achado:
    return Achado(regra, sev, rel, expl, _linha(ln, valor, chave),
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
        nome, versao = (arg[:pos], arg[pos + 1:]) if pos > 0 else (arg, "")
    else:
        nome, _, versao = arg.partition("==")
    return nome, versao if _VERSAO_EXATA.fullmatch(versao) else ""


def _programa(comando: str) -> str:
    """`C:\\...\\npx.cmd` -> `npx`."""
    nome = re.split(r"[/\\]", comando)[-1].lower()
    for ext in (".cmd", ".exe", ".bat", ".ps1"):
        if nome.endswith(ext):
            return nome[: -len(ext)]
    return nome


def _sem_cmd_c(comando: object, args: object) -> tuple[object, object]:
    """`cmd /c npx ...` (Windows) -> `npx ...`."""
    if (isinstance(comando, str) and _programa(comando) == "cmd" and isinstance(args, list) and len(args) >= 2
            and isinstance(args[0], str) and args[0].lower() == "/c"):
        return args[1], args[2:]
    return comando, args


def pacotes_mcp(texto_json: object) -> list[tuple[str, str, str]]:
    """(ecossistema, nome, versao) dos servidores `npx` (npm) e `uvx` (PyPI)."""
    achados: list[tuple[str, str, str]] = []
    for _, srv in _servidores(texto_json):
        pacote = _pacote_do_servidor(srv)
        if pacote is not None:
            achados.append(pacote)
    return achados


def _pacote_do_servidor(srv: dict) -> tuple[str, str, str] | None:
    comando, args = _sem_cmd_c(srv.get("command"), srv.get("args"))
    eco = {"npx": "npm", "uvx": "PyPI"}.get(_programa(comando)) if isinstance(comando, str) else None
    if eco is None or not isinstance(args, list):
        return None
    pacote = next((a for a in args if isinstance(a, str) and a and not a.startswith("-")), None)
    return None if pacote is None else (eco, *_nome_versao(eco, pacote))


def _mcp(rel: str, ln: Linhas, dados: object) -> list[Achado]:
    saida = []
    for nome, srv in _servidores(dados):
        linha_cmd = _comando_texto(srv.get("command"), srv.get("args"))
        if not linha_cmd:
            continue
        sev = Severity.HIGH if baixa_e_executa(linha_cmd) else Severity.LOW
        achado = _achado(
            "projeto.abrir.mcp", sev, rel,
            f"servidor MCP '{nome}' declarado: o agente o inicia ao abrir o projeto",
            ln, str(srv.get("command") or ""), nome, trecho=linha_cmd)
        pacote = _pacote_do_servidor(srv)  # (ecossistema, nome, versão): liga ao achado de dependência
        saida.append(replace(achado, chave=pacote) if pacote else achado)
    return saida


# --- VS Code ---------------------------------------------------------------

def _tarefas(rel: str, ln: Linhas, dados: object) -> list[Achado]:
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
            ln, valor, "folderOpen", trecho=principal))
    return saida


def _caminho_do_projeto(valor: str) -> bool:
    if valor.startswith(("./", "../", ".\\", "${workspaceFolder}")):
        return True
    if not valor or valor.startswith(("/", "\\", "~", "${")) or _UNIDADE.match(valor):
        return False
    return "/" in valor or "\\" in valor


_NAO_VERSIONADAS = frozenset({".venv", "venv", "node_modules"})


def _em_pasta_nao_versionada(valor: str) -> bool:
    """Aponta para .venv/venv/node_modules: pastas que a instalação cria e não vêm no repositório."""
    return any(p in _NAO_VERSIONADAS for p in re.split(r"[/\\]", valor))


def _settings_vscode(rel: str, ln: Linhas, dados: object) -> list[Achado]:
    if not isinstance(dados, dict):
        return []
    saida = []
    for chave, valor in dados.items():
        if not isinstance(chave, str):
            continue
        if isinstance(valor, str) and (
                chave == "python.defaultInterpreterPath"
                or chave.endswith((".path", "Path"))) and _caminho_do_projeto(valor):
            fora_do_repo = _em_pasta_nao_versionada(valor)
            saida.append(_achado(
                "projeto.abrir.executavel_do_projeto", Severity.LOW if fora_do_repo else Severity.MEDIUM, rel,
                f"'{chave}' aponta um executável para dentro do projeto"
                + (" (em pasta criada na instalação, não no repositório)" if fora_do_repo else ""),
                ln, valor, chave))
        elif chave.startswith("terminal.integrated.env.") and isinstance(valor, dict):
            for var in valor:
                if isinstance(var, str) and var.upper() in {"PATH", "NODE_OPTIONS", "PYTHONSTARTUP"}:
                    saida.append(_achado(
                        "projeto.abrir.executavel_do_projeto", Severity.MEDIUM, rel,
                        f"o terminal do VS Code define {var} para o projeto", ln, str(var), chave))
    return saida


# --- Claude ----------------------------------------------------------------

_BASH_AMPLO = frozenset({"Bash", "Bash(*)", "Bash(*:*)", "Bash(sh:*)", "Bash(bash:*)", "Bash(curl:*)",
                         "Bash(wget:*)"})

def _claude(rel: str, ln: Linhas, dados: object) -> list[Achado]:
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
                        f"hook '{evento}' do agente executa um comando do projeto", ln, cmd,
                        str(evento)))
    # Rodam sozinhos, sem pedir: a linha de status a cada resposta e o apiKeyHelper ao autenticar.
    status = dados.get("statusLine")
    automaticos = [("statusLine", status.get("command") if isinstance(status, dict) else None),
                   ("apiKeyHelper", dados.get("apiKeyHelper"))]
    for chave, cmd in automaticos:
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        grave = baixa_e_executa(cmd) or bool(_CREDENCIAIS.search(cmd))
        saida.append(_achado(
            "projeto.abrir.hook_agente", Severity.HIGH if grave else Severity.MEDIUM, rel,
            f"'{chave}' do agente executa um comando do projeto automaticamente", ln, cmd, chave))
    perm = dados.get("permissions")
    allow = perm.get("allow") if isinstance(perm, dict) else None
    amplas = [a for a in allow if isinstance(a, str) and a.replace(" ", "") in _BASH_AMPLO] \
        if isinstance(allow, list) else []
    if amplas:
        saida.append(_achado(
            "projeto.abrir.permissao_ampla", Severity.MEDIUM, rel,
            "o projeto libera para o agente comandos Bash amplos (shell, download ou qualquer comando)",
            ln, amplas[0], "allow"))
    if isinstance(perm, dict) and perm.get("defaultMode") == "bypassPermissions":
        saida.append(_achado(
            "projeto.abrir.permissao_ampla", Severity.MEDIUM, rel,
            "o projeto desliga os pedidos de permissão do agente (bypassPermissions)", ln,
            "bypassPermissions", "defaultMode"))
    if dados.get("enableAllProjectMcpServers") is True:
        saida.append(_achado(
            "projeto.abrir.permissao_ampla", Severity.MEDIUM, rel,
            "o projeto aprova sozinho todos os servidores MCP", ln, "",
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


def _devcontainer(rel: str, ln: Linhas, dados: object) -> list[Achado]:
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
            f"'{chave}' executa um comando {onde} ao abrir o projeto", ln,
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


ALVOS = tuple(_POR_REL)


def verificar(raiz: Path, rel: str, texto: str) -> list[Achado]:
    tratador = _POR_REL.get(rel)
    if tratador is None:
        return []
    try:
        dados = jsonc.carregar(texto)
    except ValueError as exc:
        raise ArquivoIlegivel(rel) from exc
    return limitar(tratador(rel, Linhas(texto), dados))


# --- git -------------------------------------------------------------------

def _dir_real(caminho: Path) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(caminho).st_mode)
    except OSError:
        return False


def verificar_git(raiz: Path) -> list[Achado]:
    saida: list[Achado] = []
    dotgit = Path(raiz) / ".git"
    pasta = dotgit / "hooks"
    if not _dir_real(dotgit):
        return saida
    try:
        nomes = sorted(os.listdir(pasta))[:_MAX_HOOKS_GIT] if _dir_real(pasta) else []
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
        perigosa = linha_perigosa(conteudo)
        saida.append(Achado(
            "projeto.abrir.git_hook", Severity.HIGH if perigosa else Severity.MEDIUM, f".git/hooks/{nome}",
            "hook do git presente: roda em comandos como commit, checkout e push",
            None, (perigosa or conteudo[:300]).strip(), MITRE))
    config = ler_texto(Path(raiz) / ".git" / "config")
    if config:
        linhas = Linhas(config)
        for m in _GIT_CONFIG.finditer(config):
            chave, valor = m.group(1), m.group(2).strip()
            if chave.lower() == "fsmonitor" and valor.lower() in ("true", "false"):
                continue
            saida.append(Achado(
                "projeto.abrir.git_hook", Severity.MEDIUM, ".git/config",
                f"'{chave}' em .git/config faz o git executar um programa",
                linhas.de(m.start()), m.group(0).strip(), MITRE))
    return saida
