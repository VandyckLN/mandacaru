"""Dados do usuário: lista de confiança e histórico de varreduras."""
from __future__ import annotations

import dataclasses
import json
import os
from datetime import datetime
from pathlib import Path

from mandacaru_win.scan import ScanSummary


def data_dir() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share")
    d = base / "Mandacaru"
    d.mkdir(parents=True, exist_ok=True)
    return d


class TrustList:
    """Arquivos confiáveis pelo usuário, identificados pelo SHA-256."""

    def __init__(self, path: Path):
        self._path = Path(path)
        self._entries: list[dict] = self._load()

    def _load(self) -> list[dict]:
        if not self._path.exists():
            return []
        try:
            raw = self._path.read_bytes()
        except FileNotFoundError:
            return []
        try:
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, list):
                raise ValueError("formato inesperado")
            return [e for e in data if isinstance(e, dict) and "sha256" in e]
        except ValueError:  # inclui UnicodeDecodeError e JSONDecodeError
            # Preserva o arquivo ruim (sem sobrescrever backups anteriores).
            dest = self._path.with_name(self._path.name + ".corrompido")
            n = 1
            while dest.exists():
                dest = self._path.with_name(f"{self._path.name}.corrompido.{n}")
                n += 1
            try:
                os.replace(self._path, dest)
            except OSError:
                pass
            return []

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_name(self._path.name + ".tmp")
        tmp.write_text(json.dumps(self._entries, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        os.replace(tmp, self._path)

    def hashes(self) -> set[str]:
        return {e["sha256"] for e in self._entries}

    def entries(self) -> list[dict]:
        return list(self._entries)

    def add(self, sha256: str, path: Path) -> None:
        if sha256 in self.hashes():
            return
        self._entries.append({
            "sha256": sha256,
            "caminho_quando_confiado": str(path),
            "data": datetime.now().isoformat(timespec="seconds"),
        })
        self._save()

    def remove(self, sha256: str) -> None:
        self._entries = [e for e in self._entries if e["sha256"] != sha256]
        self._save()


class History:
    """Histórico de varreduras em JSON Lines (uma por linha)."""

    def __init__(self, path: Path):
        self._path = Path(path)

    def append(self, summary: ScanSummary) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(dataclasses.asdict(summary), ensure_ascii=False) + "\n")

    def recent(self, n: int = 50) -> list[dict]:
        if not self._path.exists():
            return []
        rows: list[dict] = []
        with open(self._path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if isinstance(row, dict):
                    rows.append(row)
        return rows[::-1][:n]
