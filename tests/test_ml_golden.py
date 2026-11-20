"""O modelo instalado reproduz o golden.json do treino com tolerancia de 1e-9."""
import json
from pathlib import Path

import pytest

from mandacaru.ml import MODEL_SHA256
from mandacaru.ml.model import load_model

ROOT = Path(__file__).resolve().parent.parent


def test_golden_do_modelo_instalado():
    golden_path = ROOT / "tests" / "fixtures" / "ml_golden.json"
    if not golden_path.is_file():
        pytest.skip("nenhum modelo instalado")
    pasta = ROOT / "src" / "mandacaru" / "ml" / "models"
    g = json.loads(golden_path.read_text())
    for fam, dados in g.items():
        m = load_model(pasta / f"{fam}.json", expected_sha256=MODEL_SHA256[fam])
        for x, raw, prob in zip(dados["vetores"], dados["raw"], dados["prob"], strict=True):
            assert m.raw_score(x) == pytest.approx(raw, abs=1e-9)
            assert m.probability(x) == pytest.approx(prob, abs=1e-9)
