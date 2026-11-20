"""Treino do gradient boosting (CPU, float32), calibracao e escolha dos limiares por tipo.

A parte "calibracao" e dividida em duas metades deterministicas: cal_fit ajusta a calibracao isotonica e
cal_limiar escolhe os limiares. Assim os limiares nao sao escolhidos sobre os mesmos dados que moldaram as
probabilidades. Os limiares respeitam o orcamento de falso positivo do spec e a ordem
0 <= medio <= reforco <= alto <= alto_tmp <= 1.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression

from .extrair import Tabela

FP_ALTO = 0.0005
FP_ALTO_TMP = 0.00025
FP_MEDIO = 0.01
MIN_REFORCO = 300
PESO_DIFICIL = 4.0          # inteiro: aplicado repetindo linhas (ver treinar)
CATEGORIAS_TMP = ("build_tmp", "pip_tmp", "instalador_curl_sh", "instalador_run")
# teto da probabilidade calibrada: sempre existe um limiar <= 1 acima de qualquer legitimo
P_MAX = 1.0 - 1e-6


@dataclass
class Treinado:
    clf: HistGradientBoostingClassifier
    calib_x: list[float]
    calib_y: list[float]
    limiares: dict[str, dict[str, float]]


def _sigmoide(raw: np.ndarray) -> np.ndarray:
    raw = np.asarray(raw, dtype=np.float64)
    out = np.zeros_like(raw)
    ok = raw >= -700
    out[ok] = 1.0 / (1.0 + np.exp(-raw[ok]))
    return out


def pesos_amostra(t: Tabela, mascara: np.ndarray) -> np.ndarray:
    """Peso PESO_DIFICIL para legitimos de categorias dificeis (o erro neles e o que mais custa ao usuario)."""
    cat = np.array(t.categoria)[mascara]
    y = t.y[mascara]
    return np.where((y == 0) & (cat != "geral"), PESO_DIFICIL, 1.0).astype(np.float64)


def dividir_calibracao(t: Tabela) -> tuple[np.ndarray, np.ndarray]:
    """(cal_fit, cal_limiar): metades deterministicas da parte "calibracao" pelo hash; com poucos dados (ou uma
    metade sem as duas classes), as duas mascaras ficam iguais a calibracao inteira."""
    calib = np.array(t.parte) == "calibracao"
    paridade = np.array([int(s[:8], 16) % 2 == 0 for s in t.sha], dtype=bool)
    fit, limiar = calib & paridade, calib & ~paridade
    for m in (fit, limiar):
        if len(set(t.y[m].tolist())) < 2:
            return calib, calib
    return fit, limiar


def _calibrar(raw: np.ndarray, y: np.ndarray) -> tuple[list[float], list[float]]:
    p = _sigmoide(raw)
    if len(set(y.tolist())) == 2:
        iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0).fit(p, y)
        xs, ys = _limpar(iso.X_thresholds_, iso.y_thresholds_)
        if len(xs) >= 2 and ys[-1] > ys[0]:
            return xs, ys
        # isotonica colapsou: Platt (logistica sobre a nota bruta), amostrada em 200 pontos
        lr = LogisticRegression().fit(raw.reshape(-1, 1), y)
        a, b = float(lr.coef_[0][0]), float(lr.intercept_[0])
        if a > 0:
            grade = np.linspace(1e-6, 1 - 1e-6, 200)
            logit = np.log(grade / (1 - grade))
            xs, ys = _limpar(grade, _sigmoide(a * logit + b))
            if len(xs) >= 2:
                return xs, ys
    return [0.0, 1.0], [0.0, P_MAX]                    # identidade: nunca pior que a nota crua


def _limpar(xs, ys) -> tuple[list[float], list[float]]:
    """x estritamente crescente em [0, 1]; y nao decrescente em [0, P_MAX]."""
    pontos: list[tuple[float, float]] = []
    for x, y in zip(np.asarray(xs, dtype=float), np.asarray(ys, dtype=float), strict=True):
        x = min(1.0, max(0.0, x))
        y = min(P_MAX, max(0.0, y))
        if pontos and x <= pontos[-1][0]:
            pontos[-1] = (pontos[-1][0], max(pontos[-1][1], y))
            continue
        if pontos and y < pontos[-1][1]:
            y = pontos[-1][1]
        pontos.append((x, y))
    return [x for x, _ in pontos], [y for _, y in pontos]


def probabilidade(tr: Treinado, X: np.ndarray) -> np.ndarray:
    """O mesmo calculo do runtime: sigmoide da nota bruta, depois a tabela de calibracao (presa nas pontas)."""
    if len(X) == 0:
        return np.zeros(0)
    return np.interp(_sigmoide(tr.clf.decision_function(X)), tr.calib_x, tr.calib_y)


def limiar_fp(probs_legitimos: np.ndarray, meta: float) -> float:
    """Menor limiar com no maximo floor(meta * N) legitimos >= limiar. Sem legitimos: 1.0 (conservador)."""
    p = np.sort(np.asarray(probs_legitimos, dtype=float))[::-1]
    if len(p) == 0:
        return 1.0
    k = math.floor(meta * len(p))
    if k >= len(p):
        return 0.0
    return float(min(1.0, np.nextafter(p[k], np.inf)))


def treinar(t: Tabela, *, semente: int = 7, max_iter: int = 300) -> Treinado:
    treino = np.array(t.parte) == "treino"
    clf = HistGradientBoostingClassifier(
        max_iter=max_iter, max_depth=8, max_leaf_nodes=31, min_samples_leaf=30, l2_regularization=1.0,
        learning_rate=0.1, early_stopping=True, validation_fraction=0.1, n_iter_no_change=20, random_state=semente)
    # peso inteiro por repeticao de linhas: o sample_weight do scikit-learn 1.9 troca o binning por quantis
    # ponderados ~60x mais lentos (9,7 s contra 0,16 s em 2.400 linhas); repetir da o mesmo peso na perda
    reps = np.rint(pesos_amostra(t, treino)).astype(np.int64)
    clf.fit(np.repeat(t.X[treino].astype(np.float32), reps, axis=0), np.repeat(t.y[treino], reps))

    fit, limiar = dividir_calibracao(t)
    calib_x, calib_y = _calibrar(clf.decision_function(t.X[fit]), t.y[fit].astype(int))
    tr = Treinado(clf=clf, calib_x=calib_x, calib_y=calib_y, limiares={})

    probs = probabilidade(tr, t.X[limiar]) if limiar.any() else np.zeros(0)
    kinds = np.array(t.kind)[limiar]
    y = t.y[limiar]
    cat = np.array(t.categoria)[limiar]
    media = t.regra_media[limiar]
    for kind in sorted(set(t.kind)):
        leg = (kinds == kind) & (y == 0)
        alto = limiar_fp(probs[leg], FP_ALTO)
        alto_tmp = max(alto, limiar_fp(probs[leg & np.isin(cat, CATEGORIAS_TMP)], FP_ALTO_TMP)) \
            if (leg & np.isin(cat, CATEGORIAS_TMP)).any() else alto
        medio = min(limiar_fp(probs[leg], FP_MEDIO), alto)
        leg_regra = leg & media
        reforco = limiar_fp(probs[leg_regra], FP_ALTO) if leg_regra.sum() >= MIN_REFORCO else alto
        reforco = min(max(reforco, medio), alto)
        tr.limiares[kind] = {"alto": alto, "alto_tmp": alto_tmp, "reforco": reforco, "medio": medio}
    return tr
