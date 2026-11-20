"""Classificador local de malware por IA (modelo de arvores, Python puro).

Nucleo reutilizavel: bytes -> Verdict, sem rede e sem E/S alem da carga dos modelos. O classificador so
acrescenta suspeita: nunca libera, rebaixa ou suprime um alerta de regra.
"""
from __future__ import annotations

import hashlib
import sys
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from ..events import Alert, Severity
from .decision import MODES, decide
from .explain import Reason, top_reasons
from .features import FAMILY, ExtractionBudgetExceeded, extract
from .kind import detect_kind
from .knowngood import DpkgKnownGood
from .model import Model, ModelError, load_model

# familia -> sha256 do JSON instalado; gerado na release pelo treino (Plano 2)
MODEL_SHA256: dict[str, str] = {}
SHADOW_LOG = "/var/log/mandacaru/ml-shadow.jsonl"
CACHE_SIZE = 4096
_FAMILIES = ("elf", "script")


@dataclass(frozen=True)
class Verdict:
    kind: str
    score: float
    band: str
    isolate: bool
    known_good: bool
    gate_passed: bool
    reasons: tuple[Reason, ...]
    model_id: str
    sha256: str


class Classifier:
    def __init__(self, models: dict[str, Model], mode: str, known_good: DpkgKnownGood | None = None,
                 budget_s: float = 0.25) -> None:
        if mode not in MODES:
            raise ValueError(f"modo invalido: {mode!r}")
        self.models = models
        self.mode = mode
        self.known_good = known_good
        self.budget_s = budget_s
        self._cache: OrderedDict[str, tuple[float, tuple[Reason, ...]]] = OrderedDict()

    def _scored(self, sha: str, kind: str, model: Model, data: bytes) -> tuple[float, tuple[Reason, ...]] | None:
        hit = self._cache.get(sha)
        if hit is not None:
            self._cache.move_to_end(sha)
            return hit
        try:
            x = extract(kind, data, budget_s=self.budget_s)
        except ExtractionBudgetExceeded as exc:
            print(f"[mandacaru] aviso: classificador de IA pulou um arquivo: {exc}", file=sys.stderr)
            return None
        result = (model.probability(x), tuple(top_reasons(model, x, k=5)))
        self._cache[sha] = result
        while len(self._cache) > CACHE_SIZE:
            self._cache.popitem(last=False)
        return result

    def score(self, data: bytes, *, path: str | None = None, rule_alerts: Sequence[Alert] = ()) -> Verdict | None:
        if self.mode == "off":
            return None
        kind = detect_kind(data)
        if kind is None:
            return None
        model = self.models.get(FAMILY[kind])
        policy = model.kinds.get(kind) if model is not None else None
        if model is None or policy is None:
            return None
        sha = hashlib.sha256(data).hexdigest()
        scored = self._scored(sha, kind, model, data)
        if scored is None:
            return None
        prob, reasons = scored
        in_tmp = path is not None and (path == "/tmp" or path.startswith("/tmp/"))
        rule_hit = any(a.severity >= Severity.MEDIUM and not a.rule.startswith("ml.") for a in rule_alerts)
        band, _ = decide(policy, prob, in_tmp=in_tmp, rule_hit_medium=rule_hit, mode=self.mode, known_good=False)
        known = band in ("alto", "reforco") and self.known_good is not None and self.known_good.contains(data)
        band, isolate = decide(policy, prob, in_tmp=in_tmp, rule_hit_medium=rule_hit, mode=self.mode,
                               known_good=known)
        return Verdict(kind=kind, score=prob, band=band, isolate=isolate, known_good=known,
                       gate_passed=policy.gate_passed, reasons=reasons, model_id=model.model_id, sha256=sha)


@dataclass(frozen=True)
class LoadResult:
    classifier: Classifier | None
    problem: str | None
    invalid: bool


def load_default(mode: str, *, models_dir: Path | None = None, pinned: dict[str, str] | None = None,
                 known_good: DpkgKnownGood | None = None) -> LoadResult:
    """Carrega os modelos instalados. Qualquer modelo presente e invalido desliga o classificador (invalid=True)."""
    base = Path(models_dir) if models_dir is not None else Path(str(resources.files("mandacaru") / "ml" / "models"))
    pins = MODEL_SHA256 if pinned is None else pinned
    models: dict[str, Model] = {}
    for fam in _FAMILIES:
        path = base / f"{fam}.json"
        if not path.is_file():
            continue
        if fam not in pins:
            return LoadResult(None, f"{path.name}: hash nao fixado", True)
        try:
            models[fam] = load_model(path, expected_sha256=pins[fam])
        except ModelError as exc:
            return LoadResult(None, str(exc), True)
        if models[fam].family != fam:
            return LoadResult(None, f"{path.name}: familia {models[fam].family!r} no arquivo errado", True)
    if not models:
        return LoadResult(None, "nenhum modelo instalado", False)
    kg = known_good if known_good is not None else DpkgKnownGood()
    return LoadResult(Classifier(models, mode, kg), None, False)
