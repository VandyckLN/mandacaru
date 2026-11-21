"""Avaliacao, portao e relatorio sobre dados sinteticos."""
import json

import pytest

pytest.importorskip("sklearn")
from helpers import sintetico_script
from ml_model import model_dict, stump

from mandacaru.ml.features import SCRIPT_FEATURE_NAMES
from mandacaru.ml.model import parse_model
from tools.treino import avaliar as av
from tools.treino.avaliar import avaliar, relatorio
from tools.treino.treinar import treinar


def test_tipo_com_poucos_dados_reprova_com_motivo():
    t = sintetico_script(n=2000, semente=4)
    p = avaliar(treinar(t, max_iter=30), t)["sh"]
    assert p.aprovado is False and any("6000" in m for m in p.motivos)


def test_aprova_quando_todas_as_metas_batem(monkeypatch):
    monkeypatch.setattr(av, "MIN_LEGITIMOS_TESTE", 100)
    monkeypatch.setattr(av, "MIN_MALICIOSOS_TESTE", 50)
    t = sintetico_script(n=6000, semente=5, separavel=True)
    p = av.avaliar(treinar(t, max_iter=60), t)["sh"]
    assert p.aprovado, p.motivos


def test_regressao_contra_modelo_json_anterior(monkeypatch):
    monkeypatch.setattr(av, "MIN_LEGITIMOS_TESTE", 100)
    monkeypatch.setattr(av, "MIN_MALICIOSOS_TESTE", 50)
    t = sintetico_script(n=6000, semente=7, separavel=False)
    tr = treinar(t, max_iter=30)
    tr.limiares["sh"]["alto"] = 0.0                          # forca FP=100% no novo
    d = model_dict(family="script", kinds={"sh": {"gate_passed": True, "alto": 0.99, "alto_tmp": 0.99,
                                                  "reforco": 0.99, "medio": 0.9}},
                   trees=[stump(SCRIPT_FEATURE_NAMES.index("baixa_e_executa"), 0.5, -5.0, -5.0)])
    anterior = parse_model(json.dumps(d).encode())
    p = av.avaliar(tr, t, anterior=anterior, legitimos_anteriores=t)["sh"]
    assert p.aprovado is False and any("anterior" in m for m in p.motivos)


def test_regressao_mede_o_anterior_so_nos_legitimos_do_teste(monkeypatch):
    import numpy as np

    monkeypatch.setattr(av, "MIN_LEGITIMOS_TESTE", 100)
    monkeypatch.setattr(av, "MIN_MALICIOSOS_TESTE", 50)
    t = sintetico_script(n=6000, semente=8, separavel=True)
    col = SCRIPT_FEATURE_NAMES.index("baixa_e_executa")
    treino_leg = (np.array(t.parte) == "treino") & (t.y == 0)
    t.X[:, col] = 0.0
    t.X[treino_leg, col] = 1.0                                # o anterior so erra no que o novo treinou
    tr = treinar(t, max_iter=30)
    d = model_dict(family="script", kinds={"sh": {"gate_passed": True, "alto": 0.99, "alto_tmp": 0.99,
                                                  "reforco": 0.99, "medio": 0.9}},
                   trees=[stump(col, 0.5, -5.0, 9.0)])
    anterior = parse_model(json.dumps(d).encode())
    p = av.avaliar(tr, t, anterior=anterior, legitimos_anteriores=t)["sh"]
    assert p.extras["fp_anterior"] == 0.0


def test_relatorio_so_com_numeros():
    t = sintetico_script(n=2000, semente=6)
    md = relatorio(avaliar(treinar(t, max_iter=20), t), model_id="script-teste", contagens={"script": 2000})
    assert "script-teste" in md and "| sh |" in md and "exemplo.invalid" not in md
