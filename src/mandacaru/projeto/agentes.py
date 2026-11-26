"""Familia 1: instrucoes escondidas para agentes de IA (prompt injection)."""
from __future__ import annotations

import re
import unicodedata
from pathlib import Path, PurePosixPath

from ..events import Severity
from .achado import Achado
from .percurso import linha_de
from .unicode import mostrar_invisiveis, trechos_largura_zero, trechos_tags

_NOMES_AGENTE = frozenset({
    "agents.md", "claude.md", "gemini.md",
    ".cursorrules", ".windsurfrules", ".clinerules",
})

FRASES: tuple[str, ...] = (
    "ignore all previous instructions",
    "ignore previous instructions",
    "ignore the above instructions",
    "disregard previous instructions",
    "disregard all prior instructions",
    "ignore as instrucoes anteriores",
    "ignore todas as instrucoes anteriores",
    "desconsidere as instrucoes anteriores",
    "you are now in developer mode",
    "do not tell the user",
    "don't tell the user",
    "nao conte ao usuario",
    "nao mencione ao usuario",
    "nao avise o usuario",
)

_EXFIL = re.compile(
    r"(send|upload|exfiltrate|envie|post|mande)\b.{0,80}"
    r"(ssh|\.env|token|api[_ ]?key|password|senha|credential|credencia)",
    re.I,
)
_ASSISTENTE = re.compile(
    r"\b(assistant|assistente|ai agent|agente de ia|llm|language model|"
    r"modelo de linguagem|claude|chatgpt|copilot|cursor|gemini)\b",
    re.I,
)
_COMANDO = re.compile(
    r"\b(execute|run|rode|rodar|curl|wget|n[aã]o mencione|"
    r"do not mention|don'?t mention)\b|(?<![-:])\bignor(?:e|a)\b",
    re.I,
)
_JANELA = 300
_MAX_TRECHO = 120


def _segmentos(rel: str) -> list[str]:
    return [p for p in PurePosixPath(rel).parts]


def eh_arquivo_agente(rel: str) -> bool:
    partes = _segmentos(rel)
    if not partes:
        return False
    if partes[-1].lower() in _NOMES_AGENTE:
        return True
    caminho = "/" + "/".join(p.lower() for p in partes)
    return (
        "/.cursor/rules/" in caminho
        or caminho == "/.github/copilot-instructions.md"
        or caminho.endswith("/.github/copilot-instructions.md")
        or "/.github/instructions/" in caminho
    )


def eh_lido_por_agente(rel: str) -> bool:
    partes = [p.lower() for p in _segmentos(rel)]
    if not partes:
        return False
    nome = partes[-1]
    if nome.startswith(("readme", "contributing")):
        return True
    if partes[0] == "docs" and len(partes) > 1 and nome.endswith(".md"):
        return True
    if partes[0] == ".github" and len(partes) > 1:
        return (
            partes[1] == "issue_template"
            or nome.startswith("pull_request_template")
        )
    return False


def rebaixado(rel: str) -> bool:
    partes = _segmentos(rel)
    if any(p.lower() in ("tests", "test", "docs") for p in partes[:-1]):
        return True
    return PurePosixPath(rel).suffix.lower() in (".yar", ".yara")


def _normalizar(texto: str) -> tuple[str, list[int]]:
    """Texto sem acento, minusculo, espacos colapsados; mapa para o indice original."""
    saida: list[str] = []
    mapa: list[int] = []
    for i, c in enumerate(texto):
        if c.isspace():
            if saida and saida[-1] != " ":
                saida.append(" ")
                mapa.append(i)
            continue
        for d in unicodedata.normalize("NFKD", c):
            if unicodedata.combining(d) or unicodedata.category(d) == "Cf":
                continue
            if d in "\u2019\u2018":
                d = "'"
            for m in d.lower():
                saida.append(m)
                mapa.append(i)
    return "".join(saida), mapa


def _trecho(texto: str, pos: int) -> str:
    ini = texto.rfind("\n", 0, pos) + 1
    fim = texto.find("\n", pos)
    linha = texto[ini : fim if fim >= 0 else len(texto)].rstrip("\r")
    return mostrar_invisiveis(linha[:_MAX_TRECHO])


def verificar(raiz: Path, rel: str, texto: str) -> list[Achado]:
    agente = eh_arquivo_agente(rel)
    lido = eh_lido_por_agente(rel)
    baixo = rebaixado(rel)
    achados: list[Achado] = []
    vistos: set[tuple[str, int]] = set()

    def add(regra: str, sev: Severity, pos: int, explicacao: str, mitre: tuple[str, ...]) -> None:
        linha = linha_de(texto, pos)
        if (regra, linha) in vistos:
            return
        vistos.add((regra, linha))
        achados.append(Achado(regra, sev, rel, explicacao, linha, _trecho(texto, pos), mitre))

    if agente or lido:
        sev = Severity.HIGH if agente else Severity.MEDIUM
        for pos in sorted(trechos_tags(texto) + trechos_largura_zero(texto)):
            add("projeto.agente.unicode_oculto", sev, pos,
                "caracteres Unicode invisíveis em arquivo lido por agentes de IA: "
                "podem esconder instruções que o humano não vê", ("T1027", "T1204"))

    norm, mapa = _normalizar(texto)
    for frase in FRASES:
        for m in re.finditer(re.escape(frase), norm):
            pos = mapa[m.start()]
            if agente:
                add("projeto.agente.injecao", Severity.HIGH, pos,
                    "instrução para o agente ignorar regras ou esconder algo do usuário "
                    "(prompt injection)", ("T1204",))
            else:
                add("projeto.texto.injecao", Severity.LOW if baixo else Severity.MEDIUM, pos,
                    "frase típica de prompt injection no texto", ("T1204",))

    for m in _EXFIL.finditer(texto):
        janela = texto[max(0, m.start() - _JANELA) : m.end() + _JANELA]
        if _ASSISTENTE.search(janela):
            sev = Severity.HIGH if agente else (Severity.LOW if baixo else Severity.MEDIUM)
            add("projeto.agente.exfiltracao", sev, m.start(),
                "pedido a um assistente de IA para enviar segredos ou credenciais "
                "para fora", ("T1204",))

    if PurePosixPath(rel).suffix.lower() == ".md":
        pos = 0
        while (ini := texto.find("<!--", pos)) >= 0:
            fim = texto.find("-->", ini + 4)
            if fim < 0:
                break
            if _COMANDO.search(texto[ini + 4 : fim]):
                add("projeto.agente.comentario_oculto", Severity.MEDIUM, ini,
                    "comentário HTML escondido com instrução para agentes de IA "
                    "(invisível na página renderizada)", ("T1204",))
            pos = fim + 3

    achados.sort(key=lambda a: (a.linha or 0, a.regra))
    return achados
