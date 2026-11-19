"""Analise por hash: consulta o SHA-256 em servicos de reputacao gratuitos.

So o hash sai da maquina (o conteudo so com upload_virustotal, que o chamador
exige confirmar). Roda no auxiliar, nunca no servico.
"""
from __future__ import annotations

import json
import re
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Callable

from . import __version__
from .config import Config

Resolver = Callable[[str], "list[str]"]
Http = Callable[[urllib.request.Request, float], "tuple[int, bytes]"]

MAX_BODY = 1024 * 1024
MAX_UPLOAD = 32 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")
_USER_AGENT = f"mandacaru/{__version__}"
_NOT_FOUND_ERRNOS = {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", object())}
_LABELS = {"cymru": "Team Cymru", "malwarebazaar": "MalwareBazaar", "virustotal": "VirusTotal"}


def _default_resolver(name: str) -> list[str]:
    infos = socket.getaddrinfo(name, None, socket.AF_INET)
    return [info[4][0] for info in infos]


class _KeyStrippingRedirect(urllib.request.HTTPRedirectHandler):
    """Segue redirect, mas sem levar as chaves de API se o host ou o esquema (https -> http) mudar."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and (urllib.parse.urlsplit(newurl).netloc.lower() != req.host.lower()
                                or urllib.parse.urlsplit(newurl).scheme != urllib.parse.urlsplit(req.full_url).scheme):
            for k in list(new.headers):
                if k.lower() in ("x-apikey", "auth-key"):
                    del new.headers[k]
            for k in list(new.unredirected_hdrs):
                if k.lower() in ("x-apikey", "auth-key"):
                    del new.unredirected_hdrs[k]
        return new


_OPENER = urllib.request.build_opener(_KeyStrippingRedirect)


def _default_http(req: urllib.request.Request, timeout: float) -> tuple[int, bytes]:
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return resp.status, resp.read(MAX_BODY)
    except urllib.error.HTTPError as e:
        return e.code, e.read(MAX_BODY)


@dataclass
class SourceResult:
    status: str  # "achou" | "nao_achou" | "erro" | "desligada"
    detail: str = ""


@dataclass
class AnalysisResult:
    case_id: str
    verdict: str
    sources: dict[str, SourceResult]
    summary: str

    def to_dict(self) -> dict:
        return {
            "v": 1,
            "id": self.case_id,
            "verdict": self.verdict,
            "sources": {k: {"status": s.status, "detail": s.detail} for k, s in self.sources.items()},
            "summary": self.summary,
        }


def _request(url, headers=None, data=None):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": _USER_AGENT, **(headers or {})})
    return req


def _json(body: bytes) -> dict:
    try:
        obj = json.loads(body)
    except ValueError:
        return {}
    return obj if isinstance(obj, dict) else {}


def _cymru(h, resolver, http, timeout, cfg):
    # Formato do nome: https://hash.cymru.com/docs_dns (SHA-256 em dois blocos de 32 hex)
    name = f"{h[:32]}.{h[32:]}.hash.cymru.com"
    box: dict = {}

    def work():
        try:
            box["ips"] = resolver(name)
        except BaseException as e:  # noqa: BLE001 - repassado abaixo
            box["err"] = e

    # getaddrinfo nao tem timeout: roda numa thread daemon e desiste depois do teto das outras fontes
    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return SourceResult("erro", "timeout")
    try:
        if "err" in box:
            raise box["err"]
        ips = box["ips"]
    except socket.gaierror as e:
        # So "nome inexistente" e nao_achou; EAI_AGAIN/EAI_FAIL (offline, resolvedor morto) e erro.
        if e.errno in _NOT_FOUND_ERRNOS:
            return SourceResult("nao_achou")
        return SourceResult("erro", "falha de DNS")
    return SourceResult("achou" if "127.0.0.2" in ips else "nao_achou")


def _circl(h, resolver, http, timeout, cfg):
    req = _request(f"https://hashlookup.circl.lu/lookup/sha256/{h}", {"Accept": "application/json"})
    status, body = http(req, timeout)
    if status == 200:
        j = _json(body)
        return SourceResult("achou", str(j.get("FileName") or j.get("source") or ""))
    if status == 404:
        return SourceResult("nao_achou")
    return SourceResult("erro", f"status inesperado {status}")


def _malwarebazaar(h, resolver, http, timeout, cfg):
    req = _request("https://mb-api.abuse.ch/api/v1/", {"Auth-Key": cfg.malwarebazaar_key},
                   f"query=get_info&hash={h}".encode())
    status, body = http(req, timeout)
    if status != 200:
        return SourceResult("erro", f"status inesperado {status}")
    j = _json(body)
    qs = j.get("query_status")
    if qs == "ok":
        data = j.get("data")
        sig = data[0].get("signature") if isinstance(data, list) and data and isinstance(data[0], dict) else ""
        return SourceResult("achou", str(sig or ""))
    if qs == "hash_not_found":
        return SourceResult("nao_achou")
    return SourceResult("erro", "resposta inesperada")


def _virustotal(h, resolver, http, timeout, cfg):
    req = _request(f"https://www.virustotal.com/api/v3/files/{h}", {"x-apikey": cfg.virustotal_key})
    status, body = http(req, timeout)
    if status == 404:
        return SourceResult("nao_achou")
    if status != 200:
        return SourceResult("erro", f"status inesperado {status}")
    try:
        stats = _json(body)["data"]["attributes"]["last_analysis_stats"]
        mal = int(stats.get("malicious", 0))
        total = sum(int(v) for v in stats.values())
    except (KeyError, TypeError, ValueError, AttributeError):
        return SourceResult("erro", "resposta inesperada")
    return SourceResult("achou" if mal > 0 else "nao_achou", f"{mal}/{total} detectam")


def analyze(case_id: str, sha256: str, cfg: Config, resolver: Resolver = _default_resolver,
            http: Http = _default_http, timeout: float = 10.0) -> AnalysisResult:
    if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
        raise ValueError("sha256 invalido")
    plan = [
        ("cymru", cfg.cymru, _cymru),
        ("circl", True, _circl),
        ("malwarebazaar", bool(cfg.malwarebazaar_key), _malwarebazaar),
        ("virustotal", bool(cfg.virustotal_key), _virustotal),
    ]
    sources: dict[str, SourceResult] = {}
    for name, enabled, fn in plan:
        if not enabled:
            sources[name] = SourceResult("desligada")
            continue
        try:
            sources[name] = fn(sha256, resolver, http, timeout, cfg)
        except Exception as e:  # noqa: BLE001 - fonte nunca derruba as outras
            sources[name] = SourceResult("erro", f"falha: {type(e).__name__}")

    malware = [n for n in ("cymru", "malwarebazaar", "virustotal") if sources[n].status == "achou"]
    if malware:
        verdict = "malicioso"
        parts = []
        for n in malware:
            if n == "cymru":
                parts.append("Team Cymru conhece")
            else:
                parts.append(f"{_LABELS[n]} {sources[n].detail}".rstrip())
        summary = "Malicioso: " + "; ".join(parts)
    elif sources["circl"].status == "achou":
        verdict = "legitimo_conhecido"
        summary = "Legitimo conhecido: CIRCL reconhece este arquivo"
    else:
        verdict = "desconhecido"
        active = [s for s in sources.values() if s.status != "desligada"]
        if active and all(s.status == "erro" for s in active):
            summary = "Desconhecido: analise limitada, sem resposta das fontes"
        else:
            summary = "Desconhecido: nenhuma fonte conhece este arquivo"
    return AnalysisResult(case_id, verdict, sources, summary)


def upload_virustotal(data: bytes, filename: str, key: str, http: Http = _default_http,
                      timeout: float = 60.0) -> str:
    if len(data) > MAX_UPLOAD:
        raise ValueError("arquivo maior que 32 MB")
    boundary = uuid.uuid4().hex
    safe = filename.replace('"', "_").replace("\r", "_").replace("\n", "_")
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{safe}\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(
        "https://www.virustotal.com/api/v3/files", data=body, method="POST",
        headers={"User-Agent": _USER_AGENT, "x-apikey": key,
                 "Content-Type": f"multipart/form-data; boundary={boundary}"})
    status, resp = http(req, timeout)
    if status != 200:
        raise RuntimeError(f"VirusTotal recusou o envio (status {status})")
    try:
        return str(_json(resp)["data"]["id"])
    except (KeyError, TypeError):
        raise RuntimeError("VirusTotal respondeu sem id da analise") from None
