"""Modelo em JSON estrito, avaliado em Python puro.

Nada de pickle/joblib/ONNX: um arquivo de modelo nao pode executar codigo ao ser aberto. O carregador valida tudo
(chaves, tipos, indices, profundidade, numeros finitos) e qualquer problema vira ModelError: o classificador
desliga e o resto do Mandacaru segue.
"""
from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .features import ELF_FEATURE_NAMES, FEATURE_VERSION, SCRIPT_FEATURE_NAMES
from .kind import SCRIPT_KINDS

MAX_MODEL_BYTES = 10 * 1024 * 1024
MAX_DEPTH = 16
_KEYS = frozenset({"format_version", "model_id", "family", "created_at", "feature_version", "feature_code_sha",
                   "feature_names", "kinds", "trees", "base_score", "calibration", "metrics", "data_manifest_sha256"})
_TREE_KEYS = frozenset({"feature", "threshold", "left", "right", "value"})
_POLICY_KEYS = frozenset({"gate_passed", "alto", "alto_tmp", "reforco", "medio"})
_FAMILY_NAMES = {"elf": ELF_FEATURE_NAMES, "script": SCRIPT_FEATURE_NAMES}
_FAMILY_KINDS = {"elf": frozenset({"elf"}), "script": frozenset(SCRIPT_KINDS)}


class ModelError(ValueError):
    """Arquivo de modelo ausente do formato, adulterado ou inconsistente com este codigo."""


@dataclass(frozen=True)
class KindPolicy:
    gate_passed: bool
    alto: float
    alto_tmp: float
    reforco: float
    medio: float


@dataclass(frozen=True)
class Tree:
    feature: tuple[int, ...]
    threshold: tuple[float, ...]
    left: tuple[int, ...]
    right: tuple[int, ...]
    value: tuple[float, ...]

    def leaf(self, x: Sequence[float]) -> int:
        i = 0
        while self.feature[i] != -1:
            i = self.left[i] if x[self.feature[i]] <= self.threshold[i] else self.right[i]
        return i


@dataclass(frozen=True)
class Model:
    model_id: str
    family: str
    feature_names: tuple[str, ...]
    kinds: dict[str, KindPolicy]
    trees: tuple[Tree, ...]
    base_score: float
    calib_x: tuple[float, ...]
    calib_y: tuple[float, ...]

    def raw_score(self, x: Sequence[float]) -> float:
        return self.base_score + sum(t.value[t.leaf(x)] for t in self.trees)

    def probability(self, x: Sequence[float]) -> float:
        raw = self.raw_score(x)
        p = 1.0 / (1.0 + math.exp(-raw)) if raw >= -700 else 0.0
        xs, ys = self.calib_x, self.calib_y
        if p <= xs[0]:
            return ys[0]
        if p >= xs[-1]:
            return ys[-1]
        for k in range(1, len(xs)):
            if p <= xs[k]:
                frac = (p - xs[k - 1]) / (xs[k] - xs[k - 1])
                return ys[k - 1] + frac * (ys[k] - ys[k - 1])
        return ys[-1]

    def contributions(self, x: Sequence[float]) -> list[float]:
        """Metodo do caminho: base + soma dos valores das raizes + soma das contribuicoes == raw_score."""
        out = [0.0] * len(self.feature_names)
        for t in self.trees:
            i = 0
            while t.feature[i] != -1:
                f = t.feature[i]
                c = t.left[i] if x[f] <= t.threshold[i] else t.right[i]
                out[f] += t.value[c] - t.value[i]
                i = c
        return out


def _finite(v: object, what: str) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        raise ModelError(f"{what}: esperava numero finito")
    return float(v)


def _int(v: object, what: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise ModelError(f"{what}: esperava inteiro")
    return v


def _str(v: object, what: str) -> str:
    if not isinstance(v, str) or len(v) > 128:
        raise ModelError(f"{what}: esperava texto curto")
    return v


def _tree(raw: object, n_features: int, where: str) -> Tree:
    if not isinstance(raw, dict) or set(raw) != _TREE_KEYS:
        raise ModelError(f"{where}: chaves invalidas")
    lists = {k: raw[k] for k in _TREE_KEYS}
    size = len(lists["feature"]) if isinstance(lists["feature"], list) else -1
    if size < 1 or any(not isinstance(v, list) or len(v) != size for v in lists.values()):
        raise ModelError(f"{where}: listas de tamanhos diferentes")
    feature = tuple(_int(v, where) for v in lists["feature"])
    left = tuple(_int(v, where) for v in lists["left"])
    right = tuple(_int(v, where) for v in lists["right"])
    threshold = tuple(_finite(v, where) for v in lists["threshold"])
    value = tuple(_finite(v, where) for v in lists["value"])
    for i, f in enumerate(feature):
        if f == -1:
            continue
        if not 0 <= f < n_features:
            raise ModelError(f"{where}: no {i} usa caracteristica inexistente")
        if not (i < left[i] < size and i < right[i] < size):
            raise ModelError(f"{where}: no {i} aponta para tras ou para fora (ciclo)")
    depth = [0] * size
    for i, f in enumerate(feature):                     # filhos tem indice maior: uma passada basta
        if f != -1:
            for c in (left[i], right[i]):
                depth[c] = max(depth[c], depth[i] + 1)
                if depth[c] > MAX_DEPTH:
                    raise ModelError(f"{where}: profundidade maior que {MAX_DEPTH}")
    return Tree(feature, threshold, left, right, value)


def parse_model(raw: bytes) -> Model:
    if len(raw) > MAX_MODEL_BYTES:
        raise ModelError(f"modelo maior que {MAX_MODEL_BYTES} bytes")
    try:
        d = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ModelError(f"JSON invalido: {exc}") from None
    if not isinstance(d, dict) or set(d) != _KEYS:
        raise ModelError("chaves do modelo invalidas")
    if d["format_version"] != 1:
        raise ModelError("format_version desconhecido")
    family = d["family"]
    if family not in _FAMILY_NAMES:
        raise ModelError("family invalida")
    if d["feature_version"] != FEATURE_VERSION:
        raise ModelError(f"feature_version {d['feature_version']!r} diferente de {FEATURE_VERSION}")
    names = _FAMILY_NAMES[family]
    if d["feature_names"] != list(names):
        raise ModelError("feature_names diferente das caracteristicas deste codigo")
    for k in ("model_id", "created_at", "feature_code_sha", "data_manifest_sha256"):
        _str(d[k], k)
    if not isinstance(d["metrics"], dict):
        raise ModelError("metrics: esperava objeto")

    if not isinstance(d["kinds"], dict) or not d["kinds"]:
        raise ModelError("kinds: esperava objeto nao vazio")
    kinds: dict[str, KindPolicy] = {}
    for kind, pol in d["kinds"].items():
        if kind not in _FAMILY_KINDS[family]:
            raise ModelError(f"kinds: tipo {kind!r} nao pertence a familia {family}")
        if not isinstance(pol, dict) or set(pol) != _POLICY_KEYS or not isinstance(pol["gate_passed"], bool):
            raise ModelError(f"kinds.{kind}: chaves invalidas")
        limits = {k: _finite(pol[k], f"kinds.{kind}.{k}") for k in ("alto", "alto_tmp", "reforco", "medio")}
        if any(not 0.0 <= v <= 1.0 for v in limits.values()):
            raise ModelError(f"kinds.{kind}: limiar fora de [0, 1]")
        kinds[kind] = KindPolicy(pol["gate_passed"], **limits)

    if not isinstance(d["trees"], list):
        raise ModelError("trees: esperava lista")
    trees = tuple(_tree(t, len(names), f"trees[{i}]") for i, t in enumerate(d["trees"]))

    cal = d["calibration"]
    if not isinstance(cal, dict) or set(cal) != {"x", "y"} or not isinstance(cal["x"], list) \
            or not isinstance(cal["y"], list) or len(cal["x"]) != len(cal["y"]) or len(cal["x"]) < 2:
        raise ModelError("calibration invalida")
    xs = tuple(_finite(v, "calibration.x") for v in cal["x"])
    ys = tuple(_finite(v, "calibration.y") for v in cal["y"])
    if any(not 0.0 <= v <= 1.0 for v in xs + ys) or any(b <= a for a, b in zip(xs, xs[1:], strict=False)) \
            or any(b < a for a, b in zip(ys, ys[1:], strict=False)):
        raise ModelError("calibration: x crescente e y nao decrescente, ambos em [0, 1]")

    return Model(model_id=d["model_id"], family=family, feature_names=names, kinds=kinds, trees=trees,
                 base_score=_finite(d["base_score"], "base_score"), calib_x=xs, calib_y=ys)


def load_model(path: Path, *, expected_sha256: str | None) -> Model:
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_MODEL_BYTES + 1)
    except OSError as exc:
        raise ModelError(f"{path}: nao foi possivel ler ({exc.strerror or exc})") from None
    if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ModelError(f"{Path(path).name}: hash diferente do fixado (modelo adulterado ou de outra versao)")
    return parse_model(raw)
