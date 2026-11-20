"""Cache SQLite local do catalogo CISA KEV (Known Exploited Vulnerabilities)."""
from __future__ import annotations

import json
import sqlite3
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from .. import __version__

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_KEV_DB = Path("/var/lib/mandacaru/vuln_cache/kev.db")
MAX_KEV_BYTES = 10 * 1024 * 1024
HttpFetcher = Callable[[urllib.request.Request, float], tuple[int, bytes]]


def _default_http(req: urllib.request.Request, timeout: float) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(MAX_KEV_BYTES)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_KEV_BYTES)


class KevCache:
    """Mantem um conjunto local de CVEs conhecidamente exploradas em ataques reais."""

    def __init__(
        self,
        cache_db: Path = DEFAULT_KEV_DB,
        ttl_hours: int = 24,
        timeout_sec: float = 15.0,
        http: HttpFetcher = _default_http,
    ) -> None:
        self.cache_db = Path(cache_db)
        self.ttl = timedelta(hours=ttl_hours)
        self.timeout_sec = timeout_sec
        self.http = http
        self.cache_db.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.cache_db) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS kev_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS kev_cves (
                    cve_id TEXT PRIMARY KEY
                )
                """
            )

    def _is_fresh(self) -> bool:
        with sqlite3.connect(self.cache_db) as conn:
            row = conn.execute("SELECT value FROM kev_meta WHERE key = 'fetched_at'").fetchone()
        if not row:
            return False
        try:
            fetched_at = datetime.fromisoformat(row[0])
        except ValueError:
            return False
        return (datetime.now(timezone.utc) - fetched_at) <= self.ttl

    def load_cached(self) -> set[str]:
        with sqlite3.connect(self.cache_db) as conn:
            rows = conn.execute("SELECT cve_id FROM kev_cves").fetchall()
        return {r[0] for r in rows}

    def refresh(self) -> set[str]:
        req = urllib.request.Request(
            CISA_KEV_URL,
            headers={"User-Agent": f"mandacaru/{__version__}", "Accept": "application/json"},
            method="GET",
        )
        status, body = self.http(req, self.timeout_sec)
        if status != 200:
            raise RuntimeError(f"CISA KEV respondeu status {status}")
        payload = json.loads(body.decode("utf-8"))
        cves = {
            str(item["cveID"]).strip().upper()
            for item in payload.get("vulnerabilities", [])
            if isinstance(item, dict) and item.get("cveID")
        }
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.cache_db) as conn:
            conn.execute("DELETE FROM kev_cves")
            conn.executemany("INSERT INTO kev_cves (cve_id) VALUES (?)", [(c,) for c in sorted(cves)])
            conn.execute(
                """
                INSERT INTO kev_meta (key, value) VALUES ('fetched_at', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (now,),
            )
        return cves

    def get_cves(self, *, offline_only: bool = False) -> set[str]:
        if offline_only or self._is_fresh():
            return self.load_cached()
        try:
            return self.refresh()
        except Exception:  # noqa: BLE001 - falha de rede nunca derruba o scanner local
            return self.load_cached()
