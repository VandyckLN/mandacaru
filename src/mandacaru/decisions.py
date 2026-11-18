"""Log append-only (JSON Lines) das decisoes da quarentena."""
from __future__ import annotations

import fcntl
import json
import os
import pwd
import time
from collections.abc import Mapping

from mandacaru.events import safe_text

DEFAULT_LOG = "/var/log/mandacaru/decisions.jsonl"
ACTIONS = {
    "isolar", "nao_isolado", "ignorado_confiavel", "analisar", "manter", "confiar", "apagar",
    "desconfiar", "expirado", "restauracao_recusada",
}


class DecisionLog:
    def __init__(self, path: str | os.PathLike = DEFAULT_LOG):
        self.path = os.fspath(path)

    def record(self, action: str, *, case_id: str | None = None, sha256: str | None = None,
               path: str | None = None, by: str = "sistema", uid: int | None = None,
               detail: dict | None = None) -> None:
        """Acrescenta uma linha. Levanta ValueError (acao invalida) ou OSError (falha de gravacao)."""
        if action not in ACTIONS:
            raise ValueError(f"acao desconhecida: {action!r}")
        entry = {"v": 1, "ts": time.time(), "id": case_id, "sha256": sha256, "path": path,
                 "action": action, "by": by, "uid": uid, "detail": detail}
        line = safe_text(json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8")
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            os.write(fd, line)
        finally:
            os.close(fd)  # fecha o fd e solta o flock


def actor_from_env(env: Mapping[str, str] = os.environ) -> tuple[str, int | None]:
    raw = env.get("PKEXEC_UID") or env.get("SUDO_UID")
    if not raw:
        return "sistema", None
    try:
        uid = int(raw)
    except ValueError:
        return "sistema", None
    try:
        return pwd.getpwuid(uid).pw_name, uid
    except KeyError:
        return str(uid), uid
