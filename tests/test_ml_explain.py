"""Motivos em portugues: cada caracteristica tem frase, e os motivos vem das contribuicoes positivas."""
import json

from ml_model import model_dict, stump

from mandacaru.ml.explain import top_reasons
from mandacaru.ml.features import ELF_FEATURE_NAMES, SCRIPT_FEATURE_NAMES
from mandacaru.ml.model import parse_model
from mandacaru.ml.reasons import REASONS


def test_toda_caracteristica_tem_frase():
    assert set(ELF_FEATURE_NAMES) | set(SCRIPT_FEATURE_NAMES) <= set(REASONS)
    for texto, mitre in REASONS.values():
        assert texto.isascii() and len(texto) <= 60
        assert mitre is None or mitre.startswith("T")


def test_top_reasons_ordenado_e_so_positivos():
    iu, ie = ELF_FEATURE_NAMES.index("upx"), ELF_FEATURE_NAMES.index("ind_mineracao")
    d = model_dict(trees=[stump(iu, 0.5, -1.0, 2.0), stump(ie, 0.5, -0.5, 4.0)])
    m = parse_model(json.dumps(d).encode())
    x = [0.0] * len(ELF_FEATURE_NAMES)
    x[iu] = 1
    x[ie] = 2
    r = top_reasons(m, x, k=5)
    assert [z.feature for z in r] == ["ind_mineracao", "upx"]
    assert r[0].mitre == "T1496" and r[1].text == "compactado com UPX"
    x[iu] = 0                                             # upx empurra para baixo: nao e motivo
    assert [z.feature for z in top_reasons(m, x, k=5)] == ["ind_mineracao"]
