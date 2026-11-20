"""Treino, calibracao e limiares sobre dados sinteticos."""
import numpy as np
import pytest

pytest.importorskip("sklearn")
from helpers import probs_calibracao_legitimos, sintetico_script

from tools.treino.treinar import PESO_DIFICIL, pesos_amostra, treinar


def test_limiares_respeitam_o_orcamento_e_a_ordem():
    t = sintetico_script(n=4000, semente=1)
    tr = treinar(t, max_iter=50)
    lim = tr.limiares["sh"]
    assert 0.0 <= lim["medio"] <= lim["reforco"] <= lim["alto"] <= lim["alto_tmp"] <= 1.0
    assert len(tr.calib_x) >= 2 and all(a < b for a, b in zip(tr.calib_x, tr.calib_x[1:], strict=False))
    probs = probs_calibracao_legitimos(tr, t)
    assert sum(p >= lim["alto"] for p in probs) / len(probs) <= 0.0005 + 1e-12


def test_reforco_sem_dados_vira_alto():
    t = sintetico_script(n=3000, semente=2, regra_media=False)
    tr = treinar(t, max_iter=30)
    assert tr.limiares["sh"]["reforco"] == tr.limiares["sh"]["alto"]


def test_calibracao_colapsada_mantem_dois_pontos_e_peso_dificil():
    t = sintetico_script(n=1000, semente=4, separavel=True, categoria_dificil="go_rust_estatico")
    tr = treinar(t, max_iter=10)
    assert len(tr.calib_x) >= 2 and tr.calib_x[0] < tr.calib_x[-1]
    w = pesos_amostra(t, np.array(t.parte) == "treino")    # tupla == str daria um False so
    assert float(w.max()) == pytest.approx(PESO_DIFICIL)


def test_deterministico():
    t = sintetico_script(n=2000, semente=3)
    assert treinar(t, max_iter=20).limiares == treinar(t, max_iter=20).limiares


def test_treino_em_float64_mantem_ponto_de_massa_do_lado_certo():
    """Corte em cima de um valor que nao cabe em float32 (log2(3)): o runtime calcula em float64."""
    import math

    import numpy as np

    t = sintetico_script(n=3000, semente=12)
    rnd = np.random.default_rng(12)
    v = math.log2(3)
    n = len(t.y)
    X = np.zeros((n, t.X.shape[1]))
    grupo = rnd.integers(0, 10, n)
    massa = grupo < 4                                          # 40% exatamente em log2(3): legitimos
    abaixo, acima = (grupo >= 4) & (grupo < 7), grupo >= 7
    X[massa, 0] = v
    X[abaixo, 0] = v - rnd.uniform(0.001, 3, abaixo.sum())
    X[acima, 0] = v + rnd.uniform(0.001, 3, acima.sum())
    t.X = X
    t.y = acima.astype(np.int8)
    tr = treinar(t, max_iter=20)
    assert tr.clf.decision_function(X[massa]).max() < 0
