"""Avaliacao no conjunto de teste, portao de qualidade por tipo e relatorio (so numeros).

"Isolaria" segue a mesma regra do runtime: nota >= alto, ou uma regra MEDIUM disparou e nota >= reforco. O FP e a
fracao de legitimos do teste que seriam isolados; a deteccao, a fracao de maliciosos isolados.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np

from mandacaru.ml.model import Model

from .extrair import Tabela
from .treinar import Treinado, probabilidade

MIN_LEGITIMOS_TESTE = 6000
MIN_MALICIOSOS_TESTE = 500
META_FP = 0.0005
META_FP_CATEGORIA = 0.005
META_DETECCAO = 0.80


@dataclass
class Portao:
    kind: str
    aprovado: bool
    motivos: list[str]
    fp: float
    fp_categorias: dict[str, float]
    deteccao_regras_perdem: float
    deteccao_geral: float
    deteccao_temporal: float
    deteccao_familias_ineditas: float
    duplicatas_treino_teste: int
    n_legitimos: int
    n_maliciosos: int
    extras: dict = field(default_factory=dict)


def _isolaria(p: np.ndarray, regra_media: np.ndarray, lim: dict[str, float]) -> np.ndarray:
    return (p >= lim["alto"]) | (regra_media & (p >= lim["reforco"]))


def _fracao(mascara: np.ndarray, sel: np.ndarray) -> float:
    return float(mascara[sel].mean()) if sel.any() else math.nan


def _duplicatas(x_teste: np.ndarray, x_treino: np.ndarray) -> int:
    treino = {np.ascontiguousarray(r).tobytes() for r in x_treino}
    return sum(1 for r in x_teste if np.ascontiguousarray(r).tobytes() in treino)


def _fp_anterior(anterior: Model, kind: str, t: Tabela) -> tuple[np.ndarray, float] | None:
    pol = anterior.kinds.get(kind)
    if pol is None or t.X.shape[1] != len(anterior.feature_names):
        return None
    sel = (np.array(t.kind) == kind) & (t.y == 0)
    if not sel.any():
        return None
    probs = np.array([anterior.probability(x.astype(float).tolist()) for x in t.X[sel]])
    iso = (probs >= pol.alto) | (t.regra_media[sel] & (probs >= pol.reforco))
    return sel, float(iso.mean())


def avaliar(tr: Treinado, t: Tabela, *, anterior: Model | None = None,
            legitimos_anteriores: Tabela | None = None) -> dict[str, Portao]:
    parte = np.array(t.parte)
    kinds = np.array(t.kind)
    cats = np.array(t.categoria)
    teste, treino = parte == "teste", parte == "treino"
    probs = np.full(len(t.y), np.nan)
    if teste.any():
        probs[teste] = probabilidade(tr, t.X[teste])

    portoes: dict[str, Portao] = {}
    for kind, lim in sorted(tr.limiares.items()):
        k = teste & (kinds == kind)
        iso = np.zeros(len(t.y), dtype=bool)
        iso[k] = _isolaria(probs[k], t.regra_media[k], lim)
        leg, mal = k & (t.y == 0), k & (t.y == 1)
        fp = _fracao(iso, leg)
        fp_cat = {c: _fracao(iso, leg & (cats == c)) for c in sorted(set(cats[leg])) if c != "geral"}
        det_perdem = _fracao(iso, mal & ~t.regra_alta)
        p = Portao(
            kind=kind, aprovado=False, motivos=[], fp=fp, fp_categorias=fp_cat,
            deteccao_regras_perdem=det_perdem, deteccao_geral=_fracao(iso, mal),
            deteccao_temporal=_fracao(iso, mal & t.temporal_teste),
            deteccao_familias_ineditas=_fracao(iso, mal & ~t.temporal_teste),
            duplicatas_treino_teste=_duplicatas(t.X[k], t.X[treino & (kinds == kind)]),
            n_legitimos=int(leg.sum()), n_maliciosos=int(mal.sum()))

        m = p.motivos
        if p.n_legitimos < MIN_LEGITIMOS_TESTE:
            m.append(f"poucos legitimos no teste: {p.n_legitimos} < {MIN_LEGITIMOS_TESTE}")
        if p.n_maliciosos < MIN_MALICIOSOS_TESTE:
            m.append(f"poucos maliciosos no teste: {p.n_maliciosos} < {MIN_MALICIOSOS_TESTE}")
        if math.isnan(fp) or fp > META_FP:
            m.append(f"falso positivo {fp:.4%} acima da meta {META_FP:.2%}")
        for c, v in fp_cat.items():
            if v > META_FP_CATEGORIA:
                m.append(f"falso positivo em {c}: {v:.2%} acima de {META_FP_CATEGORIA:.1%}")
        if math.isnan(det_perdem):
            m.append("sem maliciosos que as regras perdem no teste")
        elif det_perdem < META_DETECCAO:
            m.append(f"deteccao do que as regras perdem {det_perdem:.1%} abaixo de {META_DETECCAO:.0%}")
        if anterior is not None and legitimos_anteriores is not None:
            ant = _fp_anterior(anterior, kind, legitimos_anteriores)
            if ant is not None:
                sel, fp_ant = ant
                p_novo = probabilidade(tr, legitimos_anteriores.X[sel])
                fp_novo = float(_isolaria(p_novo, legitimos_anteriores.regra_media[sel], lim).mean())
                p.extras.update(fp_anterior=fp_ant, fp_novo_nos_anteriores=fp_novo)
                if fp_novo > fp_ant:
                    m.append(f"FP maior que o do modelo anterior nos legitimos anteriores: "
                             f"{fp_novo:.4%} > {fp_ant:.4%}")
        p.aprovado = not m
        portoes[kind] = p
    return portoes


def _pct(v: float) -> str:
    return "-" if math.isnan(v) else f"{v:.2%}"


def relatorio(portoes: dict[str, Portao], *, model_id: str, contagens: dict) -> str:
    linhas = [f"# Relatorio do modelo {model_id}", "",
              "Contagens: " + ", ".join(f"{k}={v}" for k, v in sorted(contagens.items())), "",
              "| tipo | portao | FP | deteccao (regras perdem) | deteccao geral | corte temporal | familias ineditas "
              "| duplicatas treino/teste | legitimos | maliciosos |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for kind, p in sorted(portoes.items()):
        linhas.append(f"| {kind} | {'aprovado' if p.aprovado else 'reprovado'} | {_pct(p.fp)} | "
                      f"{_pct(p.deteccao_regras_perdem)} | {_pct(p.deteccao_geral)} | {_pct(p.deteccao_temporal)} | "
                      f"{_pct(p.deteccao_familias_ineditas)} | {p.duplicatas_treino_teste} | {p.n_legitimos} | "
                      f"{p.n_maliciosos} |")
    for kind, p in sorted(portoes.items()):
        if p.fp_categorias:
            linhas += ["", f"FP por categoria ({kind}): "
                       + ", ".join(f"{c}={_pct(v)}" for c, v in p.fp_categorias.items())]
        if p.motivos:
            linhas += ["", f"Motivos da reprovacao ({kind}):", *(f"- {mot}" for mot in p.motivos)]
    return "\n".join(linhas) + "\n"
