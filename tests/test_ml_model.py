"""Formato do modelo: JSON estrito, avaliacao iterativa, calibracao e contribuicoes."""
import hashlib
import json
import math

import pytest
from ml_model import model_dict, stump

from mandacaru.ml.features import ELF_FEATURE_NAMES
from mandacaru.ml.model import ModelError, load_model, parse_model


def raw(d):
    return json.dumps(d).encode()


def test_avalia_e_calibra():
    i = ELF_FEATURE_NAMES.index("upx")
    m = parse_model(raw(model_dict(trees=[stump(i, 0.5, -2.0, 3.0)], base_score=0.5)))
    x = [0.0] * len(ELF_FEATURE_NAMES)
    assert m.raw_score(x) == pytest.approx(-1.5)
    x[i] = 1.0
    assert m.raw_score(x) == pytest.approx(3.5)
    assert m.probability(x) == pytest.approx(1 / (1 + math.exp(-3.5)))


def test_contribuicoes_somam_a_nota():
    i = ELF_FEATURE_NAMES.index("entropia_max_secao")
    m = parse_model(raw(model_dict(trees=[stump(i, 7.0, -1.0, 2.0, root_value=0.25)], base_score=-0.1)))
    x = [0.0] * len(ELF_FEATURE_NAMES)
    x[i] = 7.9
    c = m.contributions(x)
    assert c[i] == pytest.approx(1.75)
    assert m.base_score + 0.25 + sum(c) == pytest.approx(m.raw_score(x))


@pytest.mark.parametrize("mutar", [
    lambda d: d["trees"][0]["left"].__setitem__(0, 0),            # filho <= pai (ciclo)
    lambda d: d["trees"][0]["feature"].__setitem__(0, 10_000),    # indice fora
    lambda d: d["trees"][0]["threshold"].__setitem__(0, float("nan")),
    lambda d: d.__setitem__("feature_names", ["x"]),
    lambda d: d.__setitem__("feature_version", 999),
    lambda d: d.__setitem__("pickle", "nao"),                     # chave desconhecida
    lambda d: d["kinds"]["elf"].__setitem__("alto", 1.5),         # limiar fora de [0,1]
])
def test_rejeita_modelo_invalido(mutar):
    d = model_dict(trees=[stump(0, 0.5, 0.0, 1.0)])
    mutar(d)
    with pytest.raises(ModelError):
        parse_model(raw(d))


def test_profundidade_e_tamanho():
    with pytest.raises(ModelError):
        parse_model(b" " * (10 * 1024 * 1024 + 1))
    with pytest.raises(ModelError):
        parse_model(b"{nao e json")
    n = 40                                                         # cadeia de 40 niveis > 16
    tree = {"feature": [0] * n + [-1, -1], "threshold": [0.5] * n + [0.0, 0.0],
            "left": [i + 1 for i in range(n)] + [-1, -1], "right": [n + 1] * n + [-1, -1], "value": [0.0] * (n + 2)}
    with pytest.raises(ModelError):
        parse_model(raw(model_dict(trees=[tree])))


def test_hash_fixado(tmp_path):
    p = tmp_path / "elf.json"
    p.write_bytes(raw(model_dict(trees=[stump(0, 0.5, 0.0, 1.0)])))
    ok = hashlib.sha256(p.read_bytes()).hexdigest()
    assert load_model(p, expected_sha256=ok).family == "elf"
    with pytest.raises(ModelError):
        load_model(p, expected_sha256="0" * 64)
