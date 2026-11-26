"""Leitura de lockfiles (npm, pnpm, yarn, poetry, uv, Pipfile.lock, requirements*.txt)."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

from . import jsonc, yamlseguro
from .achado import ArquivoIlegivel

LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
             "poetry.lock", "uv.lock", "Pipfile.lock")
_LOCKFILES_NPM = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock")
_LOCKFILES_PY = ("poetry.lock", "uv.lock")

_PROFUNDIDADE_MAX = 64
_NOS_MAX = 200_000

_EXATA = re.compile(r"[0-9][0-9A-Za-z.+!_-]*")
_REQ_LINHA = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)")
_REQ_IGUAL = re.compile(r"==\s*([0-9][0-9A-Za-z.+!_-]*)")
_REQ_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
_PNPM_V5 = re.compile(r"(@[^/@]+/[^/@]+|[^/@]+)/(\d[^/_@]*)(?:_.*)?")
_REQ_HASH = re.compile(r"\s--")
_BERRY = re.compile(r"^__metadata:", re.M)


@dataclass(frozen=True)
class Dependencia:
    ecossistema: str  # "npm" ou "PyPI"
    nome: str
    versao: str  # vazio = sem versao
    origem: str  # rel do arquivo


def _basename(rel: str) -> str:
    return rel.replace("\\", "/").rsplit("/", 1)[-1]


def eh_lockfile(rel: str) -> bool:
    b = _basename(rel)
    return b in LOCKFILES or (b.startswith("requirements") and b.endswith(".txt"))


def _pep503(nome: str) -> str:
    return re.sub(r"[-_.]+", "-", nome).lower()


def _exata(v: str) -> bool:
    return _EXATA.fullmatch(v) is not None


class _Coletor:
    """Acumula dependencias sem repetir tuplas identicas."""

    def __init__(self, eco: str, rel: str) -> None:
        self.eco, self.rel = eco, rel
        self.vistos: dict[Dependencia, None] = {}
        self.sem = 0

    def add(self, nome: str, versao: object) -> None:
        """versao nao-str e ignorada; ausente ou nao exata conta como sem versao."""
        if not isinstance(nome, str) or not nome:
            return
        if versao is not None and not isinstance(versao, str):
            return
        if versao is None or not _exata(versao):
            self.sem += 1
            return
        n = _pep503(nome) if self.eco == "PyPI" else nome
        self.vistos[Dependencia(self.eco, n, versao, self.rel)] = None

    def resultado(self) -> tuple[list[Dependencia], int]:
        return list(self.vistos), self.sem


def _json(rel: str, texto: str) -> object:
    try:
        return json.loads(texto)  # caminho rapido (C): lockfiles grandes sao JSON puro
    except Exception:  # noqa: BLE001 - talvez JSONC; tenta o leitor tolerante
        pass
    try:
        return jsonc.carregar(texto)
    except Exception as exc:  # noqa: BLE001 - entrada do atacante
        raise ArquivoIlegivel(rel) from exc


def _toml(rel: str, texto: str) -> object:
    try:
        return tomllib.loads(texto)
    except Exception as exc:  # noqa: BLE001 - entrada do atacante
        raise ArquivoIlegivel(rel) from exc


def _package_lock(rel: str, texto: str):
    c = _Coletor("npm", rel)
    dados = _json(rel, texto)
    if not isinstance(dados, dict):
        return c.resultado()
    pacotes = dados.get("packages")
    if isinstance(pacotes, dict):
        for chave, ent in pacotes.items():
            if not isinstance(chave, str) or not chave or not isinstance(ent, dict):
                continue
            if ent.get("link") is True or "node_modules/" not in chave:
                continue
            nome = chave.rsplit("node_modules/", 1)[1]
            real = ent.get("name")
            if isinstance(real, str) and real:
                nome = real
            c.add(nome, ent.get("version"))
        return c.resultado()
    deps = dados.get("dependencies")
    if isinstance(deps, dict):
        pilha = [(deps, 1)]
        nos = 0
        while pilha and nos < _NOS_MAX:
            atual, prof = pilha.pop()
            for nome, ent in atual.items():
                nos += 1
                if nos >= _NOS_MAX:
                    break
                if not isinstance(nome, str) or not isinstance(ent, dict):
                    continue
                c.add(nome, ent.get("version"))
                filhos = ent.get("dependencies")
                if isinstance(filhos, dict) and prof < _PROFUNDIDADE_MAX:
                    pilha.append((filhos, prof + 1))
    return c.resultado()


def _nos_yaml(texto: str) -> int:
    """Lockfile grande tem muitos nos legitimos; o teto acompanha o tamanho (cada no ocupa caracteres)."""
    return max(yamlseguro.MAX_NOS, len(texto))


def _pnpm(rel: str, texto: str):
    c = _Coletor("npm", rel)
    dados = yamlseguro.carregar(texto, rel, max_nos=_nos_yaml(texto))
    pacotes = dados.get("packages") if isinstance(dados, dict) else None
    if not isinstance(pacotes, dict):
        return c.resultado()
    for chave in pacotes:
        if not isinstance(chave, str):
            continue
        k = chave.split("(", 1)[0].lstrip("/")
        m = _PNPM_V5.fullmatch(k)
        if m:  # v5: /nome/versao[_peers]
            nome, ver = m.group(1), m.group(2)
        elif "@" in k[1:]:  # v6/v9: nome@versao
            nome, ver = k.rsplit("@", 1)
        else:
            continue
        c.add(nome, ver)
    return c.resultado()


def _aspas(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


def _nome_da_spec(spec: str) -> str:
    """Nome real do pacote; em alias `a@npm:b@^1` e `b`."""
    i = spec.find("@", 1)
    if i < 0:
        return spec
    resto = spec[i + 1:]
    if resto.startswith("npm:") and len(resto) > 4:
        real = resto[4:]
        j = real.find("@", 1)
        if j > 0:
            return real[:j]
    return spec[:i]


def _yarn_v1(rel: str, texto: str):
    c = _Coletor("npm", rel)
    nome = ""
    for linha in texto.splitlines():
        if not linha or linha[0] == "#":
            continue
        if linha[0] not in " \t":
            if linha.rstrip().endswith(":"):
                primeira = linha.rstrip()[:-1].split(",", 1)[0]
                nome = _nome_da_spec(_aspas(primeira))
            else:
                nome = ""
        elif nome and linha.startswith("  version "):
            c.add(nome, _aspas(linha[len("  version "):]))
            nome = ""
    return c.resultado()


def _yarn_berry(rel: str, texto: str):
    c = _Coletor("npm", rel)
    dados = yamlseguro.carregar(texto, rel, max_nos=_nos_yaml(texto))
    if not isinstance(dados, dict):
        return c.resultado()
    for chave, ent in dados.items():
        if not isinstance(chave, str) or not isinstance(ent, dict):
            continue
        versao = ent.get("version")
        if not isinstance(versao, str):
            continue
        for spec in chave.split(","):
            spec = _aspas(spec)
            if spec.find("@npm:", 1) > 0:
                c.add(_nome_da_spec(spec), versao)
                break
    return c.resultado()


def _yarn(rel: str, texto: str):
    return _yarn_berry(rel, texto) if _BERRY.search(texto) else _yarn_v1(rel, texto)


def _toml_pacotes(rel: str, texto: str, uv: bool):
    c = _Coletor("PyPI", rel)
    dados = _toml(rel, texto)
    pacotes = dados.get("package") if isinstance(dados, dict) else None
    if not isinstance(pacotes, list):
        return c.resultado()
    for p in pacotes:
        if not isinstance(p, dict):
            continue
        fonte = p.get("source")
        if uv and isinstance(fonte, dict) and ("editable" in fonte or "virtual" in fonte):
            continue
        c.add(p.get("name"), p.get("version"))
    return c.resultado()


def _pipfile(rel: str, texto: str):
    c = _Coletor("PyPI", rel)
    dados = _json(rel, texto)
    if not isinstance(dados, dict):
        return c.resultado()
    for secao in ("default", "develop"):
        pacotes = dados.get(secao)
        if not isinstance(pacotes, dict):
            continue
        for nome, ent in pacotes.items():
            if not isinstance(nome, str) or not isinstance(ent, dict):
                continue
            versao = ent.get("version")
            if isinstance(versao, str):
                m = _REQ_IGUAL.fullmatch(versao.strip())
                versao = m.group(1) if m else ""
            c.add(nome, versao)
    return c.resultado()


def _logicas(texto: str):
    """Linhas logicas de um requirements (junta continuacoes com barra invertida)."""
    acc: list[str] = []
    for linha in texto.splitlines():
        if linha.endswith("\\"):
            acc.append(linha[:-1])
            continue
        acc.append(linha)
        yield "".join(acc)
        acc = []
    if acc:
        yield "".join(acc)


def _sem_comentario(s: str) -> str:
    i = s.find("#")
    while i > 0 and not s[i - 1].isspace():
        i = s.find("#", i + 1)
    return s if i < 0 else s[:i]


def _requirements(rel: str, texto: str):
    c = _Coletor("PyPI", rel)
    for linha in _logicas(texto):
        s = _sem_comentario(linha).strip()
        if not s or s[0] == "-" or _REQ_URL.match(s):
            continue
        s = s.split(";", 1)[0]
        s = _REQ_HASH.split(s, 1)[0]
        m = _REQ_LINHA.fullmatch(s.strip())
        if not m:
            continue
        v = _REQ_IGUAL.fullmatch(m.group(2).strip())
        c.add(m.group(1), v.group(1) if v else None)
    return c.resultado()


def ler_lockfile(rel: str, texto: str) -> tuple[list[Dependencia], int]:
    """Dependencias fixadas e quantas ficaram sem versao fixa; formato invalido -> ArquivoIlegivel."""
    b = _basename(rel)
    if b in ("package-lock.json", "npm-shrinkwrap.json"):
        return _package_lock(rel, texto)
    if b == "pnpm-lock.yaml":
        return _pnpm(rel, texto)
    if b == "yarn.lock":
        return _yarn(rel, texto)
    if b == "poetry.lock":
        return _toml_pacotes(rel, texto, uv=False)
    if b == "uv.lock":
        return _toml_pacotes(rel, texto, uv=True)
    if b == "Pipfile.lock":
        return _pipfile(rel, texto)
    if b.startswith("requirements") and b.endswith(".txt"):
        return _requirements(rel, texto)
    return [], 0


def dependencias_sem_lockfile(rel: str, texto: str, irmaos: set[str]) -> int:
    """Declaradas num package.json/pyproject.toml que nao tem lockfile na mesma pasta."""
    b = _basename(rel)
    if b == "package.json":
        if any(n in irmaos for n in _LOCKFILES_NPM):
            return 0
        dados = _json(rel, texto)
        if not isinstance(dados, dict):
            return 0
        return sum(len(d) for k in ("dependencies", "devDependencies")
                   if isinstance(d := dados.get(k), dict))
    if b == "pyproject.toml":
        if any(n in irmaos for n in _LOCKFILES_PY):
            return 0
        dados = _toml(rel, texto)
        projeto = dados.get("project") if isinstance(dados, dict) else None
        deps = projeto.get("dependencies") if isinstance(projeto, dict) else None
        return sum(1 for d in deps if isinstance(d, str)) if isinstance(deps, list) else 0
    return 0
