"""Pipeline de telemetria opt-in segura (LGPD by Design) para MISP e MalwareBazaar/Threat Hub."""
from __future__ import annotations

from .dispatcher import DispatchResult, TelemetryDispatcher
from .mappers import build_malwarebazaar_metadata, build_misp_event
from .outbox import OutboxItem, TelemetryOutbox
from .sanitizer import is_public_ip, is_sample_allowed, sanitize_event_payload, sanitize_text

__all__ = [
    "DispatchResult",
    "OutboxItem",
    "TelemetryDispatcher",
    "TelemetryOutbox",
    "build_malwarebazaar_metadata",
    "build_misp_event",
    "is_public_ip",
    "is_sample_allowed",
    "sanitize_event_payload",
    "sanitize_text",
]
