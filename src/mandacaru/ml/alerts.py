"""Verdict -> Alert ml.* e registro do modo sombra. O summary nunca leva conteudo do arquivo."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

from ..events import Alert, Severity
from . import Verdict
from .features import FEATURE_VERSION

SUMMARY_MAX = 200
_RULES = {"alto": ("ml.malware", Severity.HIGH), "reforco": ("ml.malware_reforco", Severity.HIGH),
          "medio": ("ml.suspeito", Severity.MEDIUM)}


def _motivos(v: Verdict) -> list[dict]:
    return [{"feature": r.feature, "valor": round(r.value, 4), "contribuicao": round(r.contribution, 4)}
            for r in v.reasons[:5]]


def _summary(v: Verdict, name: str) -> str:
    pct = round(v.score * 100)
    reasons = "; ".join(r.text for r in v.reasons[:3]) or "padrao geral de malware"
    if v.band == "medio":
        text = f"IA: {name} suspeito (confianca {pct}%) - {reasons}"
    else:
        text = f"IA: {name} parece malware (confianca {pct}%) - {reasons}. Use Analisar antes de Confio"
    return text if len(text) <= SUMMARY_MAX else text[:SUMMARY_MAX - 3] + "..."


def verdict_alert(v: Verdict, path: Path) -> Alert | None:
    if v.band == "baixo" or v.known_good:
        return None
    rule, severity = _RULES[v.band]
    mitre: list[str] = []
    for r in v.reasons:
        if r.mitre and r.mitre not in mitre:
            mitre.append(r.mitre)
    return Alert(
        rule=rule,
        severity=severity,
        summary=_summary(v, path.name),
        evidence={"path": str(path), "sha256": v.sha256, "score": round(v.score, 4), "ml_band": v.band,
                  "ml_isolate": v.isolate, "kind": v.kind, "model_id": v.model_id,
                  "feature_version": FEATURE_VERSION, "motivos": _motivos(v)},
        mitre=mitre,
    )


def shadow_record(v: Verdict, path: Path) -> dict:
    """O que o modelo faria no modo isolate (would_isolate), sem agir."""
    return {
        "ts": datetime.fromtimestamp(time.time(), timezone.utc).isoformat(),
        "path": str(path),
        "sha256": v.sha256,
        "kind": v.kind,
        "score": round(v.score, 4),
        "band": v.band,
        "would_isolate": v.band in ("alto", "reforco") and v.gate_passed and not v.known_good,
        "model_id": v.model_id,
        "motivos": _motivos(v),
    }
