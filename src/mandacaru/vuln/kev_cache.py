"""Cache SQLite local do catalogo CISA KEV (Known Exploited Vulnerabilities)."""
from __future__ import annotations

import json
import re
import sqlite3
import unicodedata
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from .. import __version__

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_KEV_DB = Path("/var/lib/mandacaru/vuln_cache/kev.db")
MAX_KEV_BYTES = 10 * 1024 * 1024
HttpFetcher = Callable[[urllib.request.Request, float], tuple[int, bytes]]
SCHEMA_VERSION = "2"  # 2: guarda tambem vendorProject/product/dateAdded

# Sufixos juridicos e marcas de arquitetura/edicao que nao identificam o produto.
_SUFFIXES = frozenset({
    "inc", "incorporated", "corp", "corporation", "llc", "ltd", "limited", "gmbh", "co", "plc",
    "sa", "ag", "srl", "bv", "ab", "oy", "the",
})
_ARCH_RE = re.compile(r"\b(?:(?:32|64)[\s_-]?bits?|x86[_-]64|x64|x86|amd64|arm64|win64|win32)\b")
_VERSION_RE = re.compile(r"\bv?\d+(?:\.\d+)+[\w.+-]*")
_PAREN_RE = re.compile(r"\([^)]*\)|\[[^\]]*\]")
_ALT_SPLIT_RE = re.compile(r"\s+and\s+|/|,|&")


def normalize_name(text: str) -> str:
    """Nome de fabricante/produto comparavel: minusculas, sem acentos, pontuacao, versao,
    arquitetura, texto entre parenteses nem sufixos como "Inc." ("7-Zip 23.01 (x64)" -> "7 zip")."""
    t = unicodedata.normalize("NFKD", str(text)).encode("ascii", "ignore").decode("ascii").lower()
    t = _PAREN_RE.sub(" ", t)
    t = _VERSION_RE.sub(" ", t)
    t = _ARCH_RE.sub(" ", t)
    tokens = [w for w in re.split(r"[^a-z0-9]+", t) if w and w not in _SUFFIXES]
    return " ".join(tokens)


def name_key(text: str) -> str:
    """Forma compacta (sem espacos) usada nas igualdades: "7-Zip" e "7zip" viram "7zip"."""
    return normalize_name(text).replace(" ", "")


def product_keys(product: str) -> list[str]:
    """Chaves de um `product` do KEV, inclusive as alternativas ("Firefox and Thunderbird")."""
    keys = [name_key(product)]
    keys += [name_key(part) for part in _ALT_SPLIT_RE.split(str(product).lower())]
    return list(dict.fromkeys(k for k in keys if k))


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    vendor_project: str
    product: str
    date_added: str


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
            # Tabelas novas (esquema 2); um banco antigo so ganha linhas aqui no proximo refresh.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS kev_entries (
                    cve_id TEXT PRIMARY KEY,
                    vendor_project TEXT NOT NULL,
                    product TEXT NOT NULL,
                    date_added TEXT NOT NULL,
                    vendor_key TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS kev_products (
                    cve_id TEXT NOT NULL,
                    product_key TEXT NOT NULL,
                    PRIMARY KEY (cve_id, product_key)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS kev_products_key ON kev_products (product_key)")

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

    def _has_entries(self) -> bool:
        with sqlite3.connect(self.cache_db) as conn:
            row = conn.execute("SELECT value FROM kev_meta WHERE key = 'schema'").fetchone()
        return bool(row) and row[0].isdigit() and int(row[0]) >= int(SCHEMA_VERSION)

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
        entries: dict[str, KevEntry] = {}
        for item in payload.get("vulnerabilities", []):
            if not isinstance(item, dict) or not item.get("cveID"):
                continue
            cve = str(item["cveID"]).strip().upper()
            entries[cve] = KevEntry(cve, str(item.get("vendorProject") or ""), str(item.get("product") or ""),
                                    str(item.get("dateAdded") or ""))
        cves = set(entries)
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.cache_db) as conn:
            conn.execute("DELETE FROM kev_cves")
            conn.executemany("INSERT INTO kev_cves (cve_id) VALUES (?)", [(c,) for c in sorted(cves)])
            conn.execute("DELETE FROM kev_entries")
            conn.execute("DELETE FROM kev_products")
            conn.executemany(
                "INSERT INTO kev_entries (cve_id, vendor_project, product, date_added, vendor_key) VALUES (?, ?, ?, ?, ?)",
                [(e.cve_id, e.vendor_project, e.product, e.date_added, name_key(e.vendor_project))
                 for e in entries.values()],
            )
            conn.executemany(
                "INSERT OR IGNORE INTO kev_products (cve_id, product_key) VALUES (?, ?)",
                [(e.cve_id, k) for e in entries.values() for k in product_keys(e.product)],
            )
            conn.executemany(
                """
                INSERT INTO kev_meta (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                [("fetched_at", now), ("schema", SCHEMA_VERSION)],
            )
        return cves

    def get_cves(self, *, offline_only: bool = False) -> set[str]:
        if offline_only or self._is_fresh():
            return self.load_cached()
        try:
            return self.refresh()
        except Exception:  # noqa: BLE001 - falha de rede nunca derruba o scanner local
            return self.load_cached()

    # ---------- consultas por produto (aba Atualizacoes do Windows) ----------
    def _ensure_entries(self, offline_only: bool) -> None:
        if offline_only or (self._is_fresh() and self._has_entries()):
            return
        try:
            self.refresh()
        except Exception:  # noqa: BLE001 - sem rede usa o que estiver no cache
            pass

    @staticmethod
    def _rows_to_entries(rows) -> list[KevEntry]:
        return [KevEntry(*r) for r in rows]

    def entries(self, *, offline_only: bool = False) -> list[KevEntry]:
        """Todas as entradas com fabricante/produto (atualiza o cache se vencido ou do esquema antigo)."""
        self._ensure_entries(offline_only)
        with sqlite3.connect(self.cache_db) as conn:
            rows = conn.execute(
                "SELECT cve_id, vendor_project, product, date_added FROM kev_entries ORDER BY cve_id"
            ).fetchall()
        return self._rows_to_entries(rows)

    def find_by_product(self, product: str, vendor: str | None = None, *,
                        offline_only: bool = False) -> list[KevEntry]:
        """Entradas cujo `product` normalizado (ou uma alternativa dele) e igual ao informado;
        com `vendor`, exige tambem o `vendorProject` normalizado igual."""
        key = name_key(product)
        if not key:
            return []
        self._ensure_entries(offline_only)
        sql = (
            "SELECT e.cve_id, e.vendor_project, e.product, e.date_added FROM kev_products p "
            "JOIN kev_entries e ON e.cve_id = p.cve_id WHERE p.product_key = ?"
        )
        args: list[str] = [key]
        if vendor is not None:
            sql += " AND e.vendor_key = ?"
            args.append(name_key(vendor))
        with sqlite3.connect(self.cache_db) as conn:
            rows = conn.execute(sql + " ORDER BY e.cve_id", args).fetchall()
        return self._rows_to_entries(rows)
