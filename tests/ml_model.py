"""Modelos de teste feitos a mao (o modelo real vem do treino, no Plano 2)."""
from mandacaru.ml.features import ELF_FEATURE_NAMES, FEATURE_VERSION, SCRIPT_FEATURE_NAMES
from mandacaru.ml.kind import SCRIPT_KINDS

POLICY = {"gate_passed": True, "alto": 0.9, "alto_tmp": 0.97, "reforco": 0.7, "medio": 0.5}


def stump(feature_index, threshold, left_value, right_value, root_value=0.0) -> dict:
    return {"feature": [feature_index, -1, -1], "threshold": [threshold, 0.0, 0.0], "left": [1, -1, -1],
            "right": [2, -1, -1], "value": [root_value, left_value, right_value]}


def model_dict(*, family="elf", kinds=None, trees=None, base_score=0.0) -> dict:
    names = ELF_FEATURE_NAMES if family == "elf" else SCRIPT_FEATURE_NAMES
    if kinds is None:
        kinds = {"elf": dict(POLICY)} if family == "elf" else {k: dict(POLICY) for k in SCRIPT_KINDS}
    return {
        "format_version": 1,
        "model_id": f"{family}-teste",
        "family": family,
        "created_at": "2026-11-20T00:00:00Z",
        "feature_version": FEATURE_VERSION,
        "feature_code_sha": "0" * 40,
        "feature_names": list(names),
        "kinds": kinds,
        "trees": trees if trees is not None else [stump(0, 0.5, 0.0, 1.0)],
        "base_score": base_score,
        "calibration": {"x": [0.0, 1.0], "y": [0.0, 1.0]},
        "metrics": {},
        "data_manifest_sha256": "0" * 64,
    }
