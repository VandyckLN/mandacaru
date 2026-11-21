"""Quarentena: guarda o arquivo embaralhado e restaura só se o hash conferir."""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime
from pathlib import Path

from mandacaru_win.scan import Finding

KEY = b"mandacaru-quarentena"
_ID_RE = re.compile(r"^[0-9a-f]{32}$")


class QuarantineError(Exception):
    """Erro com mensagem em português, pronta para mostrar ao usuário."""


def _xor(data: bytes) -> bytes:
    # Simétrico: embaralhar e desembaralhar são a mesma operação.
    n = len(data)
    if n == 0:
        return b""
    stream = (KEY * (n // len(KEY) + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")).to_bytes(n, "big")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Quarantine:
    def __init__(self, base: Path):
        self._base = Path(base)

    def _paths(self, qid: str) -> tuple[Path, Path]:
        if not isinstance(qid, str) or not _ID_RE.match(qid):
            raise QuarantineError("Item de quarentena inválido.")
        return self._base / f"{qid}.bin", self._base / f"{qid}.json"

    def add(self, finding: Finding) -> str:
        original = Path(finding.path)
        try:
            data = original.read_bytes()
        except OSError as e:
            raise QuarantineError(f"Não foi possível ler o arquivo: {e}") from e
        if _sha(data) != finding.sha256:
            raise QuarantineError("O arquivo mudou desde a varredura; varra de novo.")

        qid = uuid.uuid4().hex
        binp, jsonp = self._paths(qid)
        meta = {
            "id": qid,
            "caminho_original": str(original),
            "sha256": finding.sha256,
            "data": datetime.now().isoformat(timespec="microseconds"),
            "regras": [a.rule for a in finding.alerts],
            "severidade": finding.severity.name,
        }
        try:
            self._base.mkdir(parents=True, exist_ok=True)
            binp.write_bytes(_xor(data))
            if _sha(_xor(binp.read_bytes())) != finding.sha256:
                raise OSError("a cópia em quarentena não confere")
            jsonp.write_text(json.dumps(meta, ensure_ascii=False, indent=2),
                             encoding="utf-8")
        except OSError as e:
            self._cleanup(binp, jsonp)
            raise QuarantineError(f"Não foi possível gravar na quarentena: {e}") from e
        try:
            os.remove(original)
        except OSError as e:
            self._cleanup(binp, jsonp)
            raise QuarantineError(
                "O arquivo está em uso; feche o programa que o usa e tente de novo."
            ) from e
        return qid

    @staticmethod
    def _cleanup(*paths: Path) -> None:
        for p in paths:
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass

    def _meta(self, qid: str) -> dict:
        _, jsonp = self._paths(qid)
        try:
            meta = json.loads(jsonp.read_text(encoding="utf-8"))
            if not isinstance(meta, dict):
                raise ValueError
            return meta
        except (OSError, ValueError) as e:
            raise QuarantineError("Item não encontrado na quarentena.") from e

    def items(self) -> list[dict]:
        out: list[dict] = []
        if not self._base.is_dir():
            return out
        for p in self._base.glob("*.json"):
            try:
                m = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(m, dict) and all(
                        k in m for k in ("id", "caminho_original", "sha256", "data")):
                    m.setdefault("regras", [])
                    m.setdefault("severidade", "")
                    out.append(m)
            except (OSError, ValueError):
                continue
        out.sort(key=lambda m: str(m["data"]), reverse=True)
        return out

    def restore(self, qid: str) -> Path:
        binp, jsonp = self._paths(qid)
        meta = self._meta(qid)
        try:
            data = _xor(binp.read_bytes())
        except OSError as e:
            raise QuarantineError(f"Não foi possível ler o item da quarentena: {e}") from e
        if _sha(data) != meta.get("sha256"):
            raise QuarantineError(
                "O arquivo em quarentena foi alterado e não será restaurado.")

        orig = Path(meta["caminho_original"])
        dest, n = orig, 1
        while dest.exists():
            suf = " (restaurado)" if n == 1 else f" (restaurado {n})"
            dest = orig.with_name(orig.stem + suf + orig.suffix)
            n += 1
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            while True:
                try:
                    with open(dest, "xb") as fh:
                        fh.write(data)
                    break
                except FileExistsError:  # corrida: outro processo criou o nome
                    suf = f" (restaurado {n})"
                    dest = orig.with_name(orig.stem + suf + orig.suffix)
                    n += 1
        except OSError as e:
            raise QuarantineError(f"Não foi possível restaurar o arquivo: {e}") from e
        self._cleanup(binp, jsonp)
        return dest

    def delete(self, qid: str) -> None:
        binp, jsonp = self._paths(qid)
        try:
            binp.unlink(missing_ok=True)
            jsonp.unlink(missing_ok=True)
        except OSError as e:
            raise QuarantineError(f"Não foi possível apagar o item: {e}") from e
