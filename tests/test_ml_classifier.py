"""Decisao por faixas, reforco pelas regras, limiar do /tmp, cache e carga dos modelos com hash fixado."""
import hashlib
import json

import pytest
from ml_model import DROPPER, model_dict
from ml_model import script_classifier as _script_classifier

from mandacaru.events import Alert, Severity
from mandacaru.ml import load_default
from mandacaru.ml.decision import decide
from mandacaru.ml.model import KindPolicy

POL = KindPolicy(gate_passed=True, alto=0.9, alto_tmp=0.97, reforco=0.7, medio=0.5)


@pytest.mark.parametrize("score,tmp,regra,modo,faixa,isola", [
    (0.95, False, False, "isolate", "alto", True),
    (0.95, True, False, "isolate", "medio", False),     # /tmp exige 0.97
    (0.98, True, False, "isolate", "alto", True),
    (0.75, False, True, "isolate", "reforco", True),
    (0.75, False, False, "isolate", "medio", False),
    (0.95, False, False, "alert", "alto", False),       # modo alert nunca isola
    (0.30, False, True, "isolate", "baixo", False),
])
def test_decide(score, tmp, regra, modo, faixa, isola):
    assert decide(POL, score, in_tmp=tmp, rule_hit_medium=regra, mode=modo, known_good=False) == (faixa, isola)


def test_portao_reprovado_e_conhecido_nao_isolam():
    reprovado = KindPolicy(False, 0.9, 0.97, 0.7, 0.5)
    assert decide(reprovado, 0.99, in_tmp=False, rule_hit_medium=False, mode="isolate",
                  known_good=False) == ("alto", False)
    assert decide(POL, 0.99, in_tmp=False, rule_hit_medium=False, mode="isolate", known_good=True) == ("alto", False)


def test_score_e_faixa_por_caminho_com_cache():
    c = _script_classifier()
    v1 = c.score(DROPPER, path="/home/ana/Downloads/x.sh")
    v2 = c.score(DROPPER, path="/tmp/x.sh")
    assert v1.band == "alto" and v1.isolate and v1.kind == "sh"
    assert v2.band == "medio" and not v2.isolate and v2.score == v1.score   # mesmo conteudo, outra faixa
    assert v1.sha256 == hashlib.sha256(DROPPER).hexdigest()


def test_reforco_vem_das_regras_e_nao_de_ml():
    c = _script_classifier()
    regra = Alert("yara.Shell_Pipe_To_Interpreter", Severity.MEDIUM, "x", {"path": "/tmp/x"})
    ml = Alert("ml.suspeito", Severity.MEDIUM, "x", {"path": "/tmp/x"})
    assert c.score(DROPPER, path="/tmp/x", rule_alerts=[ml]).band == "medio"
    assert c.score(DROPPER, path="/tmp/x", rule_alerts=[regra]).band == "reforco"   # 0.93: abaixo de alto_tmp


def test_modos_off_e_tipo_desconhecido():
    assert _script_classifier("off").score(DROPPER) is None
    assert _script_classifier().score(b"%PDF-1.7") is None
    assert _script_classifier().score(b"\x7fELF\x02\x01\x01" + b"\0" * 9 + b"\x02\x00>\x00" + b"\0" * 44) is None


def test_load_default(tmp_path):
    assert load_default("isolate", models_dir=tmp_path, pinned={}).problem == "nenhum modelo instalado"
    (tmp_path / "script.json").write_text(json.dumps(model_dict(family="script")))
    r = load_default("isolate", models_dir=tmp_path, pinned={})
    assert r.classifier is None and r.invalid and "hash" in r.problem
    h = hashlib.sha256((tmp_path / "script.json").read_bytes()).hexdigest()
    assert load_default("isolate", models_dir=tmp_path, pinned={"script": h}).classifier is not None
    (tmp_path / "script.json").write_bytes(b'{"format_version": 1, "trunc')
    r = load_default("isolate", models_dir=tmp_path, pinned={"script": h})
    assert r.classifier is None and r.invalid
