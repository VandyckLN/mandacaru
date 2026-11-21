"""Motivos de uma decisao: as caracteristicas que mais empurraram a nota para cima."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .model import Model
from .reasons import REASONS, applies


@dataclass(frozen=True)
class Reason:
    feature: str
    value: float
    contribution: float
    text: str
    mitre: str | None


def top_reasons(model: Model, x: Sequence[float], k: int = 5) -> list[Reason]:
    contrib = model.contributions(x)
    names = model.feature_names
    order = sorted((i for i, c in enumerate(contrib) if c > 0 and applies(names[i], float(x[i]))),
                   key=lambda i: -contrib[i])[:k]
    out = []
    for i in order:
        name = model.feature_names[i]
        text, mitre = REASONS.get(name, (name, None))
        out.append(Reason(name, float(x[i]), contrib[i], text, mitre))
    return out
