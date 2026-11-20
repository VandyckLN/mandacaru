"""Produtor da fila: cada arquivo isolado pela quarentena vira um relatorio sanitizado na outbox."""
from __future__ import annotations

import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .outbox import TelemetryOutbox
from .sanitizer import sanitize_event_payload

if TYPE_CHECKING:
    from ..config import Config
    from ..events import Alert
    from ..quarantine import Case

IsolatedHook = Callable[["Case", "list[Alert]"], None]


def _os_release(path: Path = Path("/etc/os-release")) -> tuple[str, str]:
    data: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                data[k.strip()] = v.strip().strip('"')
    except OSError:
        pass
    return data.get("ID", "linux"), data.get("VERSION_ID", "")


def payload_from_case(case: Case, alerts: list[Alert], *, tlp: str,
                      os_release: Path = Path("/etc/os-release")) -> dict:
    """So hash, tamanho, regras e MITRE: nada de caminho, usuario, hostname ou conteudo."""
    yara_rules = sorted({a.rule.removeprefix("yara.") for a in alerts if a.rule.startswith("yara.")})
    mitre = sorted({t for a in alerts for t in a.mitre})
    distro, version = _os_release(os_release)
    return sanitize_event_payload(
        sha256=case.sha256,
        mime="application/octet-stream",
        size_bytes=case.size,
        yara_rules=yara_rules,
        mitre_attack=mitre,
        tlp=tlp,
        distro=distro,
        distro_version=version,
        arch=platform.machine() or "unknown",
        detected_at=datetime.fromtimestamp(case.quarantined_at, timezone.utc).isoformat(),
    )


def make_enqueuer(cfg: Config, outbox: TelemetryOutbox) -> IsolatedHook:
    """Callback do Engine. Falha da fila nunca atrapalha a deteccao: so avisa em stderr."""

    def _hook(case: Case, alerts: list[Alert]) -> None:
        try:
            payload = payload_from_case(case, alerts, tlp=cfg.telemetry_tlp)
            outbox.enqueue(payload, require_approval=cfg.telemetry_require_approval)
        except Exception as exc:  # noqa: BLE001
            print(f"[mandacaru] aviso: telemetria nao enfileirou o caso {case.id}: {exc}", file=sys.stderr)

    return _hook
