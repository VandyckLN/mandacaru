"""Fila local SQLite auditavel com deduplicacao por SHA-256 e aprovacao opt-in."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_OUTBOX_DB = Path("/var/lib/mandacaru/telemetry/outbox.db")
VALID_STATES = frozenset({"PENDING", "APPROVED", "REJECTED", "SENT", "FAILED"})


@dataclass(frozen=True)
class OutboxItem:
    id: int
    sha256: str
    status: str
    payload: dict[str, Any]
    sample_path: str | None
    created_at: str
    updated_at: str
    last_error: str


class TelemetryOutbox:
    """Armazena relatorios sanitizados para revisao local antes do envio a MISP/Threat Hub."""

    def __init__(self, db_path: Path = DEFAULT_OUTBOX_DB) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS outbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sha256 TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    sample_path TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_error TEXT NOT NULL DEFAULT ''
                )
                """
            )

    def _row_to_item(self, row: tuple) -> OutboxItem:
        return OutboxItem(
            id=int(row[0]),
            sha256=str(row[1]),
            status=str(row[2]),
            payload=json.loads(row[3]),
            sample_path=row[4],
            created_at=str(row[5]),
            updated_at=str(row[6]),
            last_error=str(row[7]),
        )

    def enqueue(
        self,
        payload: dict[str, Any],
        *,
        require_approval: bool = True,
        sample_path: str | None = None,
    ) -> tuple[int, bool]:
        """Enfileira um relatorio deduplicado por sha256. Retorna (id, created)."""
        sha256 = str(payload.get("indicator", {}).get("sha256", "")).lower()
        if len(sha256) != 64:
            raise ValueError("payload sem indicator.sha256 valido (64 hex)")
        status = "PENDING" if require_approval else "APPROVED"
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            existing = conn.execute("SELECT id FROM outbox WHERE sha256 = ?", (sha256,)).fetchone()
            if existing:
                return int(existing[0]), False
            cur = conn.execute(
                """
                INSERT INTO outbox (sha256, status, payload, sample_path, created_at, updated_at, last_error)
                VALUES (?, ?, ?, ?, ?, ?, '')
                """,
                (sha256, status, json.dumps(payload, ensure_ascii=False), sample_path, now, now),
            )
            return int(cur.lastrowid), True

    def list_items(self, status: str | None = None) -> list[OutboxItem]:
        with sqlite3.connect(self.db_path) as conn:
            if status:
                rows = conn.execute(
                    "SELECT id, sha256, status, payload, sample_path, created_at, updated_at, last_error "
                    "FROM outbox WHERE status = ? ORDER BY id ASC",
                    (status,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, sha256, status, payload, sample_path, created_at, updated_at, last_error "
                    "FROM outbox ORDER BY id ASC"
                ).fetchall()
        return [self._row_to_item(r) for r in rows]

    def get(self, item_id: int) -> OutboxItem | None:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id, sha256, status, payload, sample_path, created_at, updated_at, last_error "
                "FROM outbox WHERE id = ?",
                (item_id,),
            ).fetchone()
        return self._row_to_item(row) if row else None

    def set_status(self, item_id: int, status: str, error: str = "") -> bool:
        if status not in VALID_STATES:
            raise ValueError(f"estado invalido: {status}")
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "UPDATE outbox SET status = ?, updated_at = ?, last_error = ? WHERE id = ?",
                (status, now, error, item_id),
            )
            return cur.rowcount > 0

    def approve(self, item_id: int) -> bool:
        return self.set_status(item_id, "APPROVED")

    def reject(self, item_id: int) -> bool:
        return self.set_status(item_id, "REJECTED")

    def mark_sent(self, item_id: int) -> bool:
        return self.set_status(item_id, "SENT", error="")

    def mark_failed(self, item_id: int, error: str) -> bool:
        return self.set_status(item_id, "FAILED", error=error)
