"""JSON com comentarios e virgula final (JSONC), em varredura unica linear."""
from __future__ import annotations

import json


def _limpar(texto: str) -> str:
    saida: list[str] = []
    ultimo = -1  # indice em `saida` do ultimo token significativo
    i, n = 0, len(texto)
    while i < n:
        c = texto[i]
        if c == '"':
            j = i + 1
            while j < n and texto[j] != '"':
                j += 2 if texto[j] == "\\" else 1
            saida.append(texto[i:j + 1])
            ultimo = len(saida) - 1
            i = j + 1
        elif c == "/" and texto.startswith("//", i):
            j = i
            while j < n and texto[j] not in "\r\n":
                j += 1
            i = j
        elif c == "/" and texto.startswith("/*", i):
            fim = texto.find("*/", i + 2)
            i = n if fim < 0 else fim + 2
            saida.append(" ")
        elif c in "}]":
            if ultimo >= 0 and saida[ultimo] == ",":
                saida[ultimo] = ""
            saida.append(c)
            ultimo = len(saida) - 1
            i += 1
        else:
            saida.append(c)
            if not c.isspace():
                ultimo = len(saida) - 1
            i += 1
    return "".join(saida)


def carregar(texto: str) -> object:
    """Remove comentarios e virgulas finais fora de strings e faz json.loads.

    Levanta ValueError se o resultado nao for JSON valido.
    """
    try:
        return json.loads(_limpar(texto))
    except RecursionError as exc:
        raise ValueError("JSON aninhado demais") from exc
