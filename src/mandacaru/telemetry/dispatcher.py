"""Envio seguro da fila aprovada para o Mandacaru Threat Hub ou MISP self-hosted."""
from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .. import __version__
from ..config import Config
from .mappers import payload_to_misp_event
from .outbox import OutboxItem, TelemetryOutbox
from .sanitizer import is_sample_allowed

MAX_RESP_BYTES = 1024 * 1024
HttpSender = Callable[[urllib.request.Request, float, bool], tuple[int, bytes]]


class _AuthStrippingRedirect(urllib.request.HTTPRedirectHandler):
    """Remove cabecalhos de autenticacao se um redirect mudar host ou esquema."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and (
            urllib.parse.urlsplit(newurl).netloc.lower() != req.host.lower()
            or urllib.parse.urlsplit(newurl).scheme != urllib.parse.urlsplit(req.full_url).scheme
        ):
            for hdr_dict in (new.headers, new.unredirected_hdrs):
                for key in list(hdr_dict):
                    if key.lower() in ("authorization", "x-apikey", "auth-key"):
                        del hdr_dict[key]
        return new


def _default_http(req: urllib.request.Request, timeout: float, verify_tls: bool) -> tuple[int, bytes]:
    ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    opener = urllib.request.build_opener(_AuthStrippingRedirect, urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read(MAX_RESP_BYTES)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_RESP_BYTES)


@dataclass(frozen=True)
class DispatchResult:
    sent: int
    failed: int
    skipped: int


class TelemetryDispatcher:
    """Despacha apenas itens APPROVED quando a telemetria estiver explicitamente habilitada."""

    def __init__(
        self,
        cfg: Config,
        outbox: TelemetryOutbox,
        *,
        http: HttpSender = _default_http,
        timeout_sec: float = 20.0,
        misp_api_key: str | None = None,
    ) -> None:
        self.cfg = cfg
        self.outbox = outbox
        self.http = http
        self.timeout_sec = timeout_sec
        self._misp_api_key = misp_api_key if misp_api_key is not None else os.environ.get("MANDACARU_MISP_API_KEY", "")

    def flush(self) -> DispatchResult:
        if self.cfg.telemetry_level == "off":
            return DispatchResult(sent=0, failed=0, skipped=len(self.outbox.list_items("APPROVED")))

        destinations = self._configured_destinations()
        if not destinations:
            return DispatchResult(sent=0, failed=0, skipped=len(self.outbox.list_items("APPROVED")))

        sent = 0
        failed = 0
        for item in self.outbox.list_items("APPROVED"):
            try:
                self._send_item(item, destinations)
                self.outbox.mark_sent(item.id)
                sent += 1
            except Exception as exc:  # noqa: BLE001
                self.outbox.mark_failed(item.id, str(exc))
                failed += 1
        return DispatchResult(sent=sent, failed=failed, skipped=0)

    def _configured_destinations(self) -> list[str]:
        dests: list[str] = []
        if self.cfg.telemetry_hub_enabled and self.cfg.telemetry_hub_endpoint:
            dests.append("hub")
        if self.cfg.telemetry_misp_enabled and self.cfg.telemetry_misp_url:
            dests.append("misp")
        return dests

    def _send_item(self, item: OutboxItem, destinations: list[str]) -> None:
        if "hub" in destinations:
            self._send_hub(item)
        if "misp" in destinations:
            self._send_misp(item)

    def _send_hub(self, item: OutboxItem) -> None:
        body_obj = dict(item.payload)
        if self.cfg.telemetry_level == "samples_elf" and item.sample_path:
            sample = Path(item.sample_path)
            max_bytes = self.cfg.telemetry_max_sample_mb * 1024 * 1024
            body_obj["sample_eligible"] = is_sample_allowed(sample, max_size_bytes=max_bytes)
        else:
            body_obj["sample_eligible"] = False

        req = urllib.request.Request(
            self.cfg.telemetry_hub_endpoint,
            data=json.dumps(body_obj, ensure_ascii=False).encode("utf-8"),
            headers={
                "User-Agent": f"mandacaru/{__version__}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        status, _ = self.http(req, self.timeout_sec, True)
        if status not in (200, 201, 202):
            raise RuntimeError(f"Threat Hub recusou envio (status {status})")

    def _send_misp(self, item: OutboxItem) -> None:
        if not self._misp_api_key:
            raise RuntimeError("MANDACARU_MISP_API_KEY ausente no ambiente")
        url = self.cfg.telemetry_misp_url.rstrip("/") + "/events/add"
        misp_payload = payload_to_misp_event(item.payload, distribution=0)
        req = urllib.request.Request(
            url,
            data=json.dumps(misp_payload, ensure_ascii=False).encode("utf-8"),
            headers={
                "User-Agent": f"mandacaru/{__version__}",
                "Authorization": self._misp_api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        status, _ = self.http(req, self.timeout_sec, self.cfg.telemetry_misp_verify_tls)
        if status not in (200, 201):
            raise RuntimeError(f"MISP recusou envio (status {status})")
