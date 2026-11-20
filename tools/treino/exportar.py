"""Exportacao do modelo treinado para o JSON estrito do runtime (mandacaru.ml.model) e o golden.json.

Antes de gravar qualquer coisa, `conferir` recarrega o JSON com o carregador do proprio produto e exige que o
avaliador em Python puro reproduza o scikit-learn com tolerancia de 1e-9 nos vetores do golden.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from mandacaru.ml.features import ELF_FEATURE_NAMES, FEATURE_VERSION, SCRIPT_FEATURE_NAMES
from mandacaru.ml.model import parse_model

from .avaliar import Portao, avaliar, relatorio
from .extrair import Tabela, carregar, feature_code_sha
from .treinar import Treinado, probabilidade, treinar

TOL = 1e-9
MAX_JSON = 3 * 1024 * 1024
_NOMES = {"elf": ELF_FEATURE_NAMES, "script": SCRIPT_FEATURE_NAMES}


def _arvore(nodes) -> dict:
    n = len(nodes)
    folha = [bool(nodes["is_leaf"][i]) for i in range(n)]
    # pre-ordem: o scikit-learn ja grava assim; se nao, renumera para filhos terem indice maior que o pai
    ordem: list[int] = []
    pilha = [0]
    while pilha:
        i = pilha.pop()
        ordem.append(i)
        if not folha[i]:
            pilha += [int(nodes["right"][i]), int(nodes["left"][i])]
    novo = {velho: k for k, velho in enumerate(ordem)}
    feature, threshold, left, right, count, value = [], [], [], [], [], []
    for velho in ordem:
        if folha[velho]:
            feature.append(-1)
            threshold.append(0.0)
            left.append(-1)
            right.append(-1)
        else:
            feature.append(int(nodes["feature_idx"][velho]))
            threshold.append(float(nodes["num_threshold"][velho]))
            left.append(novo[int(nodes["left"][velho])])
            right.append(novo[int(nodes["right"][velho])])
        count.append(float(nodes["count"][velho]))
        value.append(float(nodes["value"][velho]))
    # nos internos: media dos filhos ponderada por count, de baixo para cima (explicacao pelo metodo do caminho)
    for i in range(len(ordem) - 1, -1, -1):
        if feature[i] != -1:
            cl, cr = count[left[i]], count[right[i]]
            tot = cl + cr
            value[i] = (cl * value[left[i]] + cr * value[right[i]]) / tot if tot > 0 else \
                (value[left[i]] + value[right[i]]) / 2
    return {"feature": feature, "threshold": threshold, "left": left, "right": right, "value": value}


def _metricas_limpas(metricas: dict) -> dict:
    limpas = {}
    for k, v in metricas.items():
        if not isinstance(k, str) or len(k) > 64:
            raise ValueError(f"chave de metrica invalida: {k!r}")
        if isinstance(v, bool) or not isinstance(v, (int, float, str)):
            raise ValueError(f"metrica {k}: so numero ou texto curto")
        if isinstance(v, float) and not math.isfinite(v):
            continue
        if isinstance(v, str) and len(v) > 64:
            raise ValueError(f"metrica {k}: texto maior que 64 caracteres")
        limpas[k] = v
    return limpas


def exportar(tr: Treinado, portoes: dict[str, Portao], *, family: str, model_id: str, feature_code_sha: str,
             manifesto_sha256: str, metricas: dict) -> dict:
    nomes = _NOMES[family]
    if tr.clf.n_features_in_ != len(nomes):
        raise ValueError(f"modelo com {tr.clf.n_features_in_} caracteristicas; {family} tem {len(nomes)}")
    return {
        "format_version": 1,
        "model_id": model_id,
        "family": family,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "feature_version": FEATURE_VERSION,
        "feature_code_sha": feature_code_sha,
        "feature_names": list(nomes),
        "kinds": {k: {"gate_passed": bool(portoes[k].aprovado) if k in portoes else False, **lim}
                  for k, lim in sorted(tr.limiares.items())},
        "trees": [_arvore(it[0].nodes) for it in tr.clf._predictors],
        "base_score": float(np.asarray(tr.clf._baseline_prediction).item()),
        "calibration": {"x": [float(v) for v in tr.calib_x], "y": [float(v) for v in tr.calib_y]},
        "metrics": _metricas_limpas(metricas),
        "data_manifest_sha256": manifesto_sha256,
    }


def serializar_json(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def golden(tr: Treinado, X, n: int = 200, semente: int = 7) -> dict:
    X = np.asarray(X)
    idx = np.sort(np.random.default_rng(semente).choice(len(X), size=min(n, len(X)), replace=False))
    amostra = X[idx].astype(np.float64)
    return {
        "vetores": amostra.tolist(),
        "raw": [float(v) for v in tr.clf.decision_function(amostra)],
        "prob": [float(v) for v in probabilidade(tr, amostra)],
    }


def conferir(json_modelo: dict, json_golden: dict) -> None:
    modelo = parse_model(serializar_json(json_modelo))
    raizes = sum(t.value[0] for t in modelo.trees)
    for i, (x, raw, prob) in enumerate(zip(json_golden["vetores"], json_golden["raw"], json_golden["prob"],
                                           strict=True)):
        r = modelo.raw_score(x)
        assert abs(r - raw) <= TOL, f"vetor {i}: raw {r} != {raw}"
        p = modelo.probability(x)
        assert abs(p - prob) <= TOL, f"vetor {i}: prob {p} != {prob}"
        soma = modelo.base_score + raizes + sum(modelo.contributions(x))
        assert abs(soma - r) <= 1e-6, f"vetor {i}: contribuicoes nao somam a nota ({soma} != {r})"


def _gravar(path: Path, dados: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as fh:
        fh.write(dados)


def gravar_saida(pasta: Path, *, model_id: str, treinados: dict[str, Treinado], tabelas: dict[str, Tabela],
                 portoes: dict[str, dict[str, Portao]], manifesto: list[str], contagens: dict) -> Path:
    """Escreve na pasta (nova; FileExistsError se ja existir) exatamente: elf.json, script.json, golden.json,
    relatorio-<model_id>.md e manifesto-<model_id>.txt. Tudo e conferido antes de qualquer gravacao."""
    if pasta.exists():
        raise FileExistsError(f"{pasta} ja existe: um modelo anterior nunca e sobrescrito")
    texto_manifesto = "".join(f"{h}\n" for h in sorted(manifesto)).encode("ascii")
    manifesto_sha = hashlib.sha256(texto_manifesto).hexdigest()
    code_sha = feature_code_sha()[:40]
    goldens, modelos = {}, {}
    for fam in ("elf", "script"):
        tr = treinados[fam]
        p = portoes[fam]
        metricas = {f"{k}_fp": v.fp for k, v in p.items()}
        metricas |= {f"{k}_det": v.deteccao_regras_perdem for k, v in p.items()}
        m = exportar(tr, p, family=fam, model_id=f"{fam}-{model_id}", feature_code_sha=code_sha,
                     manifesto_sha256=manifesto_sha, metricas=metricas)
        g = golden(tr, tabelas[fam].X)
        conferir(m, g)
        dados = serializar_json(m)
        if len(dados) > MAX_JSON:
            raise ValueError(f"{fam}.json com {len(dados)} bytes (limite {MAX_JSON})")
        modelos[fam] = dados
        goldens[fam] = {"family": fam, "model_id": m["model_id"], **g}
    pasta.mkdir(parents=True)
    for fam, dados in modelos.items():
        _gravar(pasta / f"{fam}.json", dados)
    _gravar(pasta / "golden.json", serializar_json(goldens))
    md = "\n".join(relatorio(portoes[f], model_id=f"{f}-{model_id}", contagens=contagens) for f in ("elf", "script"))
    _gravar(pasta / f"relatorio-{model_id}.md", md.encode("utf-8"))
    _gravar(pasta / f"manifesto-{model_id}.txt", texto_manifesto)
    return pasta


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m tools.treino.exportar",
                                 description="treina, avalia e exporta a partir das tabelas salvas pela extracao")
    ap.add_argument("--tabelas", required=True, type=Path)
    ap.add_argument("--saida", required=True, type=Path, help="pasta nova do modelo (ex.: ~/saida/<model_id>)")
    ap.add_argument("--model-id", required=True)
    args = ap.parse_args(argv)
    tabelas = carregar(args.tabelas)
    treinados = {f: treinar(tabelas[f]) for f in ("elf", "script")}
    portoes = {f: avaliar(treinados[f], tabelas[f]) for f in ("elf", "script")}
    manifesto = sorted({s for t in tabelas.values() for s in t.sha})
    pasta = gravar_saida(args.saida, model_id=args.model_id, treinados=treinados, tabelas=tabelas, portoes=portoes,
                         manifesto=manifesto, contagens={f: len(t.sha) for f, t in tabelas.items()})
    print(f"saida: {pasta}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
