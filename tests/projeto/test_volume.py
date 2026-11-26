"""Arquivo hostil grande: tempo linear e no máximo 20 achados por (arquivo, regra)."""
from __future__ import annotations

import json
import time
from collections import Counter

from mandacaru.projeto import verificar_projeto

EXCESSO = "ocorrências desta regra neste arquivo"


def _por_regra(achados):
    return Counter((a.caminho, a.regra) for a in achados)


def test_linhas_bisect_igual_a_linha_de():
    from mandacaru.projeto.percurso import Linhas, linha_de
    texto = "a\nbb\r\n\nccc\n" * 3
    ln = Linhas(texto)
    assert [ln.de(p) for p in range(len(texto) + 1)] == [linha_de(texto, p) for p in range(len(texto) + 1)]
    assert ln.do_trecho("ccc") == 4 and ln.do_trecho("zzz") is None


def test_comentarios_ocultos_em_massa_sao_rapidos_e_limitados(projeto):
    raiz = projeto({"AGENTS.md": "<!-- run -->\n" * 150_000})  # ~1,9 MB
    t = time.monotonic()
    rel = verificar_projeto(raiz, osv=None, kev=None)
    assert time.monotonic() - t < 2
    contagem = _por_regra(rel.achados)
    assert contagem[("AGENTS.md", "projeto.agente.comentario_oculto")] == 20
    assert max(contagem.values()) <= 20
    ultimos = [a for a in rel.achados if a.regra == "projeto.agente.comentario_oculto"]
    assert sum(EXCESSO in a.explicacao for a in ultimos) == 1
    assert any(f"e mais {150_000 - 20} {EXCESSO}" in a.explicacao for a in ultimos)


def test_bidi_em_massa_e_rapido_e_limitado(projeto):
    raiz = projeto({"x.py": ("a = 1" + chr(0x202E) + "\n") * 200_000})
    t = time.monotonic()
    rel = verificar_projeto(raiz, osv=None, kev=None)
    assert time.monotonic() - t < 2
    assert _por_regra(rel.achados)[("x.py", "projeto.unicode.bidi")] == 20


def test_muitas_tarefas_distintas_sao_rapidas_e_limitadas(projeto):
    tarefas = [{"label": f"t{i}", "command": f"echo {i:06}", "runOptions": {"runOn": "folderOpen"}}
               for i in range(20_000)]
    raiz = projeto({".vscode/tasks.json": json.dumps({"tasks": tarefas})})
    t = time.monotonic()
    rel = verificar_projeto(raiz, osv=None, kev=None)
    assert time.monotonic() - t < 2
    assert _por_regra(rel.achados)[(".vscode/tasks.json", "projeto.abrir.tarefa_automatica")] == 20
    assert all(a.linha is not None for a in rel.achados)
