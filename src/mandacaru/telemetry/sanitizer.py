"""Barreiras de privacidade (LGPD by Design): bloqueio de documentos pessoais e higienizacao de PII."""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

ELF_MAGIC = b"\x7fELF"
SHEBANG_MAGIC = b"#!"

BLOCKED_EXTENSIONS = frozenset(
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods",
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".mp4", ".mkv", ".mp3",
        ".env", ".pem", ".key", ".crt", ".p12", ".pfx", ".kdbx", ".sqlite", ".db",
        ".csv", ".txt", ".md", ".rtf", ".gpg", ".asc",
    }
)

_HOME_PATH_RE = re.compile(r"/home/[^/\s'\"]+")
_SECRET_RE = re.compile(
    r"(?i)(authorization:\s*bearer\s+\S+|bearer\s+[a-z0-9._\-]+|"
    r"akia[0-9a-z]{16}|(--?pass(?:word)?[=\s]+)\S+|"
    r"(https?://)[^/\s:@]+:[^/\s@]+@)"
)


def is_sample_allowed(path: Path, max_size_bytes: int = 15 * 1024 * 1024) -> bool:
    """Permite envio de amostra somente para binarios ELF ou scripts executaveis fora de extensoes pessoais."""
    if not path.is_file() or path.is_symlink():
        return False
    if path.suffix.lower() in BLOCKED_EXTENSIONS:
        return False
    size = path.stat().st_size
    if size == 0 or size > max_size_bytes:
        return False

    with path.open("rb") as fh:
        header = fh.read(4)
    return header.startswith(ELF_MAGIC) or header.startswith(SHEBANG_MAGIC)


def sanitize_text(text: str) -> str:
    """Remove usernames em /home e redige tokens, chaves AWS e senhas em linhas de comando."""
    cleaned = _HOME_PATH_RE.sub("/home/$USER", text)
    cleaned = _SECRET_RE.sub("[REDACTED]", cleaned)
    return cleaned


def is_public_ip(ip_str: str) -> bool:
    """Retorna True apenas para enderecos IP globalmente roteaveis (exclui RFC 1918, loopback e link-local)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_global
    except ValueError:
        return False


def sanitize_event_payload(
    *,
    sha256: str,
    mime: str,
    size_bytes: int,
    yara_rules: list[str],
    mitre_attack: list[str],
    cmdline: str = "",
    tlsh: str | None = None,
    dst_ips: list[str] | None = None,
    tlp: str = "TLP:CLEAR",
    distro: str = "linux",
    distro_version: str = "",
    arch: str = "x86_64",
    detected_at: str = "",
    ml: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Constroi um payload sanitizado sem hostname, machine-id, usernames ou IPs internos."""
    network_iocs = [
        {"type": "ip-dst", "value": ip}
        for ip in (dst_ips or [])
        if is_public_ip(ip)
    ]
    indicator: dict[str, Any] = {
        "sha256": sha256.lower(),
        "mime": mime,
        "size_bytes": int(size_bytes),
    }
    if tlsh:
        indicator["tlsh"] = tlsh

    detection: dict[str, Any] = {
        "engine": "mandacaru",
        "yara_rules": list(yara_rules),
        "mitre_attack": list(mitre_attack),
        "sanitized_cmdline": sanitize_text(cmdline) if cmdline else "",
    }
    if ml is not None:
        detection["ml"] = {"model_id": str(ml["model_id"]), "score": float(ml["score"])}
    return {
        "schema_version": "1.0",
        "tlp": tlp.upper(),
        "detected_at": detected_at,
        "os": {"distro": distro, "version": distro_version, "arch": arch},
        "indicator": indicator,
        "detection": detection,
        "network_iocs": network_iocs,
    }
