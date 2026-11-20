"""Cliente em lote da API OSV.dev com cache SQLite local."""
from __future__ import annotations

import json
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable

from .. import __version__
from .inventory import InstalledPackage

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
DEFAULT_OSV_DB = Path("/var/lib/mandacaru/vuln_cache/osv.db")
MAX_BODY = 10 * 1024 * 1024
HttpFetcher = Callable[[urllib.request.Request, float], tuple[int, bytes]]


def _default_http(req: urllib.request.Request, timeout: float) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(MAX_BODY)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_BODY)


class OsvClient:
    """Consulta vulnerabilidades no OSV.dev em lotes e armazena detalhes em cache SQLite."""

    def __init__(
        self,
        cache_db: Path = DEFAULT_OSV_DB,
        ttl_hours: int = 24,
        timeout_sec: float = 15.0,
        http: HttpFetcher = _default_http,
        workers: int = 8,
    ) -> None:
        self.cache_db = Path(cache_db)
        self.ttl = timedelta(hours=ttl_hours)
        self.timeout_sec = timeout_sec
        self.http = http
        self.workers = max(1, workers)
        self.errors: list[str] = []  # detalhes que nao vieram nem da rede nem do cache antigo
        self.cache_db.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.cache_db) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vuln_cache (
                    vuln_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    fetched_at TEXT NOT NULL
                )
                """
            )

    def _get_cached(self, vuln_id: str, *, allow_stale: bool = False) -> dict | None:
        with sqlite3.connect(self.cache_db) as conn:
            row = conn.execute(
                "SELECT payload, fetched_at FROM vuln_cache WHERE vuln_id = ?",
                (vuln_id,),
            ).fetchone()
        if not row:
            return None
        if not allow_stale:
            try:
                fetched_at = datetime.fromisoformat(row[1])
            except ValueError:
                return None
            if datetime.now(timezone.utc) - fetched_at > self.ttl:
                return None
        return json.loads(row[0])

    def _set_cached(self, vuln_id: str, payload: dict) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.cache_db) as conn:
            conn.execute(
                """
                INSERT INTO vuln_cache (vuln_id, payload, fetched_at)
                VALUES (?, ?, ?)
                ON CONFLICT(vuln_id) DO UPDATE SET
                    payload = excluded.payload,
                    fetched_at = excluded.fetched_at
                """,
                (vuln_id, json.dumps(payload), now),
            )

    def _http_json(self, url: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"User-Agent": f"mandacaru/{__version__}", "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
        status, raw = self.http(req, self.timeout_sec)
        if status != 200:
            raise RuntimeError(f"OSV.dev respondeu status {status} para {url}")
        return json.loads(raw.decode("utf-8"))

    def query_packages(
        self,
        packages: list[InstalledPackage],
        batch_size: int = 500,
    ) -> dict[InstalledPackage, list[dict]]:
        findings: dict[InstalledPackage, list[dict]] = {}
        ids_to_fetch: set[str] = set()
        pkg_to_ids: dict[InstalledPackage, list[str]] = {}

        for i in range(0, len(packages), batch_size):
            chunk = packages[i : i + batch_size]
            payload = {
                "queries": [
                    {
                        "version": pkg.version,
                        "package": {"name": pkg.source_name, "ecosystem": pkg.ecosystem},
                    }
                    for pkg in chunk
                ]
            }
            resp = self._http_json(OSV_BATCH_URL, body=payload)
            results = resp.get("results", [])

            for pkg, entry in zip(chunk, results, strict=False):
                vulns = entry.get("vulns") or []
                if not vulns:
                    continue
                v_ids = [v["id"] for v in vulns if isinstance(v, dict) and "id" in v]
                if v_ids:
                    pkg_to_ids[pkg] = v_ids
                    ids_to_fetch.update(v_ids)

        details = self._fetch_details(ids_to_fetch)
        for pkg, v_ids in pkg_to_ids.items():
            findings[pkg] = [details[vid] for vid in v_ids if vid in details]
        return findings

    def _fetch_details(self, vuln_ids: Iterable[str]) -> dict[str, dict]:
        """Cache fresco primeiro; o resto vem da rede em paralelo. Uma falha cai no cache vencido e,
        sem ele, fica de fora e vai para `errors`: um detalhe faltando nao descarta o scan inteiro."""
        self.errors = []
        resolved: dict[str, dict] = {}
        missing: list[str] = []
        for vid in sorted(set(vuln_ids)):
            cached = self._get_cached(vid)
            if cached is not None:
                resolved[vid] = cached
            else:
                missing.append(vid)
        if not missing:
            return resolved

        with ThreadPoolExecutor(max_workers=min(self.workers, len(missing))) as ex:
            futures = {
                ex.submit(self._http_json, OSV_VULN_URL.format(vuln_id=urllib.parse.quote(vid, safe=""))): vid
                for vid in missing
            }
            for fut in as_completed(futures):
                vid = futures[fut]
                try:
                    detail = fut.result()
                except Exception as exc:  # noqa: BLE001 - rede/HTTP/JSON: tenta o cache vencido
                    stale = self._get_cached(vid, allow_stale=True)
                    if stale is not None:
                        resolved[vid] = stale
                    else:
                        self.errors.append(f"{vid}: {exc}")
                    continue
                self._set_cached(vid, detail)
                resolved[vid] = detail
        return resolved
