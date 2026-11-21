"""Faixas e isolamento (spec 7.4). O orcamento de falso positivo foi calibrado so para alto e reforco."""
from __future__ import annotations

from .model import KindPolicy

MODES = ("off", "shadow", "alert", "isolate")
BANDS = ("alto", "reforco", "medio", "baixo")


def decide(policy: KindPolicy, score: float, *, in_tmp: bool, rule_hit_medium: bool, mode: str,
           known_good: bool) -> tuple[str, bool]:
    """(faixa, isolar). Isolar so com faixa alto/reforco, modo isolate, portao aprovado e arquivo desconhecido."""
    if score >= (policy.alto_tmp if in_tmp else policy.alto):
        band = "alto"
    elif rule_hit_medium and score >= policy.reforco:
        band = "reforco"
    elif score >= policy.medio:
        band = "medio"
    else:
        band = "baixo"
    isolate = band in ("alto", "reforco") and mode == "isolate" and policy.gate_passed and not known_good
    return band, isolate
