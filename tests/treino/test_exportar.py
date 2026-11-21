"""Exportacao do modelo treinado para o JSON estrito do runtime."""
import pytest

pytest.importorskip("sklearn")
from helpers import sintetico_script

from mandacaru.ml.model import parse_model
from tools.treino.avaliar import avaliar
from tools.treino.exportar import conferir, exportar, golden, serializar_json
from tools.treino.treinar import treinar


def test_exportado_carrega_reproduz_sklearn_e_soma_contribuicoes():
    t = sintetico_script(n=3000, semente=8)
    tr = treinar(t, max_iter=40)
    port = avaliar(tr, t)
    m = exportar(tr, port, family="script", model_id="script-teste", feature_code_sha="0" * 40,
                 manifesto_sha256="0" * 64, metricas={"fp": 0.0})
    g = golden(tr, t.X)
    conferir(m, g)
    raw_bytes = serializar_json(m)
    modelo = parse_model(raw_bytes)
    assert modelo.kinds["sh"].gate_passed is False
    assert len(raw_bytes) <= 3 * 1024 * 1024
    x0 = g["vetores"][0]
    soma_raizes = sum(ar.value[0] for ar in modelo.trees)
    assert modelo.base_score + soma_raizes + sum(modelo.contributions(x0)) == pytest.approx(modelo.raw_score(x0))


def test_conferir_pega_divergencia():
    t = sintetico_script(n=2000, semente=9)
    tr = treinar(t, max_iter=20)
    m = exportar(tr, avaliar(tr, t), family="script", model_id="x", feature_code_sha="0" * 40,
                 manifesto_sha256="0" * 64, metricas={})
    g = golden(tr, t.X)
    g["raw"][0] += 1e-3
    with pytest.raises(AssertionError):
        conferir(m, g)
