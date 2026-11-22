"""Programas desatualizados e vulneráveis (aba Atualizações). Sem Qt: tudo injetável.

Inventário: primeiro o módulo `Microsoft.WinGet.Client` do PowerShell (`Get-WinGetPackage`
convertido em JSON: não depende de idioma nem da largura do console). Sem o módulo, cai
no texto de `winget upgrade`, lido sem usar os rótulos do cabeçalho nem a posição das
colunas: cada linha da tabela é quebrada em palavras e lida da direita para a esquerda
(origem, disponível, instalada, id — nenhum deles tem espaço; o nome fica com o resto).
Linhas cortadas pelo winget ("…") são descartadas e contadas.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher
from functools import lru_cache
from pathlib import Path
from typing import Callable

from mandacaru import __version__
from mandacaru.vuln.kev_cache import KevCache, KevEntry, name_key, normalize_name, product_keys

Runner = Callable[[list[str], float], tuple[int, str]]
HttpFetcher = Callable[[urllib.request.Request, float], tuple[int, bytes]]
Progress = Callable[[str, int, int], None]
StopFlag = Callable[[], bool]

WINDOWS_UPDATE_URI = "ms-settings:windowsupdate"
APP_INSTALLER_URI = "ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1"  # "Instalador de Aplicativo"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_BODY = 32 * 1024 * 1024

# Riscos, do pior para o melhor.
EXPLORADA = "Explorada"
EXPLORADA_PRODUTO = "Explorada (produto)"
ALTA = "Alta"
MEDIA = "Média"
SUSPEITA = "Suspeita"
BAIXA = "Baixa"
SEM_CVE = "Sem CVE conhecida"
DESATUALIZADO = "Desatualizado"
RISK_RANK = {EXPLORADA: 7, EXPLORADA_PRODUTO: 6, ALTA: 5, MEDIA: 4, SUSPEITA: 3, BAIXA: 2, SEM_CVE: 1,
             DESATUALIZADO: 0}
PRESELECT = frozenset({EXPLORADA, EXPLORADA_PRODUTO, ALTA})

TEXTO_PRODUTO_EXPLORADO = ("Este programa tem falhas usadas em ataques; versões antigas podem estar afetadas — "
                           "atualizar é a correção recomendada.")

# Ids do winget: "Fabricante.Programa" ou id da Microsoft Store. Nunca começam com "-".
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_SOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_VER_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+~-]*$")
_AVAIL_RE = re.compile(r"^(?=.*\d)[0-9A-Za-z][0-9A-Za-z._+~-]*$")  # a disponível sempre tem número
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_SEP_RE = re.compile(r"^-{10,}$")
_ELLIPSIS = ("…", "...")

# Casamento de nome extra para o KEV: produto cujo nome normalizado começa com o prefixo.
_KEV_ALIASES = {"google.chrome": ("google", "chromium")}
_WEAK_JACCARD = 0.5
_WEAK_RATIO = 0.85


class WingetUnavailable(RuntimeError):
    """winget não está instalado (ou não roda) neste computador."""


@dataclass(frozen=True)
class Program:
    name: str
    id: str
    installed: str
    available: str
    source: str = ""


@dataclass(frozen=True)
class NvdCve:
    id: str
    score: float | None
    kev: bool


@dataclass(frozen=True)
class NvdResult:
    vendor: str
    product: str
    cves: tuple[NvdCve, ...]

    @property
    def worst(self) -> float | None:
        scores = [c.score for c in self.cves if c.score is not None]
        return max(scores) if scores else None


@dataclass
class Assessment:
    program: Program
    risk: str
    detail: str
    preselected: bool
    cves: tuple[str, ...] = ()
    kev_cves: tuple[str, ...] = ()
    worst_cvss: float | None = None


@dataclass
class WindowsUpdates:
    available: bool
    total: int = 0
    security: int = 0
    titles: list[str] = field(default_factory=list)
    reason: str = ""


@dataclass
class CheckResult:
    items: list[Assessment]
    complete: bool
    method: str
    notes: list[str] = field(default_factory=list)
    windows: WindowsUpdates | None = None
    interrupted: bool = False


@dataclass(frozen=True)
class ApplyResult:
    id: str
    name: str
    status: str  # ok | reiniciar | ja_atualizado | fechar | ocupado | cancelado | falhou | invalido
    message: str
    code: int | None = None

    @property
    def success(self) -> bool:
        return self.status in ("ok", "reiniciar", "ja_atualizado")


# ---------- execução de processos ----------
def _default_run(args: list[str], timeout: float) -> tuple[int, str]:
    """Executa sem shell e sem janela; devolve (código, stdout em texto)."""
    p = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, check=False,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return p.returncode, p.stdout.decode("utf-8", errors="replace")


def find_winget() -> str | None:
    # O alias do winget fica em WindowsApps; o PATH é só o plano B.
    la = os.environ.get("LOCALAPPDATA")
    if la:
        p = Path(la) / "Microsoft" / "WindowsApps" / "winget.exe"
        if p.exists():
            return str(p)
    return shutil.which("winget")


def powershell_path() -> str:
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    return os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def _ps_args(ps: str, script: str) -> list[str]:
    # Script sem aspas duplas (o -Command do powershell.exe trata mal o escape de ").
    return [ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]


def valid_winget_id(value: str) -> bool:
    return isinstance(value, str) and bool(_ID_RE.fullmatch(value))  # fullmatch: "$" aceitaria "\\n"


# ---------- inventário ----------
PS_LIST_SCRIPT = "; ".join([
    "$ErrorActionPreference = 'Stop'",
    "[Console]::OutputEncoding = [Text.Encoding]::UTF8",
    "if (-not (Get-Module -ListAvailable -Name Microsoft.WinGet.Client)) { exit 3 }",
    "Import-Module Microsoft.WinGet.Client",
    "$l = @(Get-WinGetPackage | Where-Object { $_.IsUpdateAvailable } | ForEach-Object { "
    "[pscustomobject]@{ Name = [string]$_.Name; Id = [string]$_.Id; Installed = [string]$_.InstalledVersion; "
    "Available = [string](@($_.AvailableVersions)[0]); Source = [string]$_.Source } })",
    "ConvertTo-Json -InputObject $l -Compress",
])
PS_NO_MODULE = 3


def parse_ps_packages(text: str) -> list[Program]:
    data = json.loads(text.strip() or "[]")
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise ValueError("formato inesperado")
    out = []
    for row in data:
        if not isinstance(row, dict):
            continue
        vals = {k: str(row.get(k) or "").strip() for k in ("Name", "Id", "Installed", "Available", "Source")}
        if not (valid_winget_id(vals["Id"]) and vals["Available"]):
            continue
        out.append(Program(vals["Name"] or vals["Id"], vals["Id"], vals["Installed"], vals["Available"],
                           vals["Source"]))
    return out


def _parse_row(line: str) -> Program | None:
    t = line.split()
    if len(t) < 5:
        return None
    source, available = t[-1], t[-2]
    if len(t) >= 6 and t[-4] in ("<", ">"):  # "< 1.2" (faixa) ocupa duas palavras
        installed, pid, name = f"{t[-4]} {t[-3]}", t[-5], t[:-5]
    else:
        installed, pid, name = t[-3], t[-4], t[:-4]
    inst_core = installed[2:] if installed[:1] in "<>" else installed
    if not name or any(e in x for x in (pid, installed, available, source) for e in _ELLIPSIS):
        return None
    if not (_ID_RE.fullmatch(pid) and _VER_RE.fullmatch(inst_core) and _AVAIL_RE.fullmatch(available)
            and _SOURCE_RE.fullmatch(source)):
        return None
    return Program(" ".join(name), pid, installed, available, source)


def parse_winget_upgrade(text: str) -> tuple[list[Program], int]:
    """(programas, linhas descartadas). Só lê linhas depois de uma linha de traços."""
    programs: list[Program] = []
    skipped = 0
    in_table = False
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = _ANSI_RE.sub("", raw.rsplit("\r", 1)[-1]).rstrip()  # tira o "spinner" de progresso
        if _SEP_RE.match(line.strip()):
            in_table = True
            continue
        if not in_table:
            continue
        if not line.strip():
            in_table = False
            continue
        row = _parse_row(line)
        if row is not None:
            programs.append(row)
        elif any(e in line for e in _ELLIPSIS):
            skipped += 1  # linha cortada: continua na tabela
        else:
            in_table = False  # rodapé ("2 atualizações disponíveis.")
    return programs, skipped


# ---------- KEV ----------
@lru_cache(maxsize=4096)
def _alt_tokens(product: str) -> tuple[frozenset[str], ...]:
    parts = re.split(r"\s+and\s+|/|,|&", product.lower())
    return tuple(frozenset(normalize_name(p).split()) for p in [product, *parts] if normalize_name(p))


class KevMatcher:
    """Casa programas com o catálogo KEV pelo par fabricante/produto normalizado.

    forte: produto igual (ou alternativa "X and Y") e fabricante confirmado pelo id do winget
           ou pelo começo do nome; ou nome == fabricante + produto.
    suspeita: fabricante confirmado e produto só parecido (Jaccard das palavras >= 0,5 ou
              semelhança do texto >= 0,85); ou produto igual sem fabricante confirmado.
    """

    def __init__(self, kev: KevCache, *, offline_only: bool = False):
        self._kev = kev
        self.entries: list[KevEntry] = kev.entries(offline_only=offline_only)
        self.cves = {e.cve_id for e in self.entries}

    @staticmethod
    def _keys(p: Program) -> tuple[str, str, str, str, list[str]]:
        tokens = normalize_name(p.name).split()
        n = "".join(tokens)
        parts = p.id.split(".")
        pub = name_key(parts[0]) if len(parts) >= 2 else ""
        pkg = name_key(" ".join(parts[1:])) if len(parts) >= 2 else ""
        n_sem_pub = n[len(pub):] if pub and n.startswith(pub) and len(n) > len(pub) else ""
        return n, pub, pkg, n_sem_pub, tokens

    def match(self, p: Program) -> tuple[str | None, list[KevEntry]]:
        if not self.entries:
            return None, []
        n, pub, pkg, n_sem_pub, tokens = self._keys(p)
        if not n:
            return None, []

        def vendor_ok(v: str) -> bool:
            return bool(v) and (v == pub or n.startswith(v))

        strong: dict[str, KevEntry] = {}
        weak: dict[str, KevEntry] = {}
        for key in {k for k in (n, n_sem_pub, pkg) if k}:
            for e in self._kev.find_by_product(key, offline_only=True):
                (strong if vendor_ok(name_key(e.vendor_project)) else weak)[e.cve_id] = e
        alias = _KEV_ALIASES.get(p.id.lower())
        prog_sets = [frozenset(tokens)]
        if pkg:
            prog_sets.append(frozenset(normalize_name(" ".join(p.id.split(".")[1:])).split()))
        for e in self.entries:
            if e.cve_id in strong:
                continue
            v = name_key(e.vendor_project)
            if not vendor_ok(v):
                continue
            keys = product_keys(e.product)
            if n.startswith(v) and n[len(v):] in keys:
                strong[e.cve_id] = e
                continue
            if alias and v == alias[0] and any(k.startswith(alias[1]) for k in keys):
                strong[e.cve_id] = e
                continue
            vtok = set(normalize_name(e.vendor_project).split())
            for alt in _alt_tokens(e.product):
                if len("".join(alt)) < 3:
                    continue
                for prog_set in prog_sets:
                    ps = prog_set - vtok or prog_set  # compara só a parte do produto
                    jac = len(alt & ps) / len(alt | ps)
                    ratio = SequenceMatcher(None, "".join(sorted(alt)), "".join(sorted(ps))).ratio()
                    if jac >= _WEAK_JACCARD or ratio >= _WEAK_RATIO:
                        weak[e.cve_id] = e
        if strong:
            return "forte", sorted(strong.values(), key=lambda e: e.cve_id)
        if weak:
            return "suspeita", sorted(weak.values(), key=lambda e: e.cve_id)
        return None, []


# ---------- NVD ----------
class Cancelled(Exception):
    pass


class RateLimiter:
    """No máximo `max_calls` chamadas a cada `period` segundos (NVD sem chave: 5 / 30 s)."""

    def __init__(self, max_calls: int = 5, period: float = 30.0,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep):
        self.max_calls, self.period = max_calls, period
        self._clock, self._sleep = clock, sleep
        self._calls: list[float] = []

    def wait(self, should_stop: StopFlag | None = None) -> None:
        while True:
            now = self._clock()
            self._calls = [t for t in self._calls if now - t < self.period]
            if len(self._calls) < self.max_calls:
                self._calls.append(now)
                return
            if should_stop is not None and should_stop():
                raise Cancelled()
            self._sleep(min(self._calls[0] + self.period - now, 0.5))


def _default_http(req: urllib.request.Request, timeout: float) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(MAX_BODY)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_BODY)


_CPE_SPLIT_RE = re.compile(r"(?<!\\):")
_KEYWORD_PAREN_RE = re.compile(r"\([^)]*\)|\[[^\]]*\]")
_KEYWORD_VER_RE = re.compile(r"\bv?\d+(?:\.\d+)+\S*")


def _cpe_escape(value: str) -> str | None:
    """Versão no formato CPE 2.3 (escapa o que não é letra, número, ".", "_" ou "-")."""
    if not value or not value.isascii() or not value[0].isalnum() or any(c.isspace() for c in value):
        return None
    return "".join(c if c.isalnum() or c in "._-" else "\\" + c for c in value)


def _cvss(cve: dict) -> float | None:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = [m for m in metrics.get(key) or [] if isinstance(m, dict)]
        rows.sort(key=lambda m: m.get("type") != "Primary")
        for m in rows:
            score = (m.get("cvssData") or {}).get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
    return None


class NvdClient:
    """CPE (fabricante:produto) por programa e CVEs por versão, com cache SQLite."""

    def __init__(self, cache_db: Path, *, http: HttpFetcher = _default_http, limiter: RateLimiter | None = None,
                 ttl_hours: int = 24, map_ttl_days: int = 30, timeout_sec: float = 30.0):
        self.cache_db = Path(cache_db)
        self.http = http
        self.limiter = limiter or RateLimiter()
        self.ttl = timedelta(hours=ttl_hours)
        self.map_ttl = timedelta(days=map_ttl_days)
        self.timeout_sec = timeout_sec
        self.cache_db.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.cache_db) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS cpe_map (prog TEXT PRIMARY KEY, vendor TEXT, product TEXT, "
                         "fetched_at TEXT NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS cve_cache (key TEXT PRIMARY KEY, payload TEXT NOT NULL, "
                         "fetched_at TEXT NOT NULL)")

    @staticmethod
    def _age(ts: str) -> timedelta | None:
        try:
            return datetime.now(timezone.utc) - datetime.fromisoformat(ts)
        except ValueError:
            return None

    def _get(self, url: str, params: dict, should_stop: StopFlag | None) -> dict:
        self.limiter.wait(should_stop)
        req = urllib.request.Request(
            f"{url}?{urllib.parse.urlencode(params, safe=':*')}",
            headers={"User-Agent": f"mandacaru/{__version__}", "Accept": "application/json"}, method="GET")
        status, body = self.http(req, self.timeout_sec)
        if status != 200:
            raise RuntimeError(f"NVD respondeu status {status}")
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("resposta inesperada da NVD")
        return data

    # --- mapeamento programa -> CPE ---
    @staticmethod
    def _keyword(name: str) -> str:
        t = _KEYWORD_VER_RE.sub(" ", _KEYWORD_PAREN_RE.sub(" ", name))
        return " ".join(t.split())[:100]

    @staticmethod
    def _score(p: Program, vendor: str, product: str) -> int:
        n, pub, pkg, n_sem_pub, _ = KevMatcher._keys(p)
        v, k = name_key(vendor), name_key(product)
        vendor_ok = bool(v) and (v == pub or n.startswith(v))
        exact = k in {x for x in (n, pkg, n_sem_pub) if x} or (bool(v) and n == v + k)
        if exact and vendor_ok:
            return 3
        if exact:
            return 2
        similar = max((SequenceMatcher(None, k, x).ratio() for x in (n, pkg, n_sem_pub) if x), default=0.0)
        if vendor_ok and k and similar >= _WEAK_RATIO:
            return 1
        return 0

    def cpe_for(self, p: Program, *, offline_only: bool = False,
                should_stop: StopFlag | None = None) -> tuple[str, str] | None:
        with sqlite3.connect(self.cache_db) as conn:
            row = conn.execute("SELECT vendor, product, fetched_at FROM cpe_map WHERE prog = ?", (p.id,)).fetchone()
        if row:
            age = self._age(row[2])
            ttl = self.map_ttl if row[0] else self.ttl  # "não achei" vale menos tempo
            if offline_only or (age is not None and age <= ttl):
                return (row[0], row[1]) if row[0] else None
        if offline_only:
            return None
        data = self._get(NVD_CPE_URL, {"keywordSearch": self._keyword(p.name), "resultsPerPage": 200}, should_stop)
        counts: dict[tuple[str, str], int] = {}
        for item in data.get("products") or []:
            name = ((item or {}).get("cpe") or {}).get("cpeName") or ""
            parts = _CPE_SPLIT_RE.split(name)
            if len(parts) >= 5 and parts[2] == "a":
                counts[(parts[3], parts[4])] = counts.get((parts[3], parts[4]), 0) + 1
        best = max(counts, key=lambda vp: (self._score(p, *vp), counts[vp]), default=None)
        if best is not None and self._score(p, *best) == 0:
            best = None  # nada parecido o bastante: melhor não chutar
        with sqlite3.connect(self.cache_db) as conn:
            conn.execute("INSERT INTO cpe_map (prog, vendor, product, fetched_at) VALUES (?, ?, ?, ?) "
                         "ON CONFLICT(prog) DO UPDATE SET vendor = excluded.vendor, product = excluded.product, "
                         "fetched_at = excluded.fetched_at",
                         (p.id, best[0] if best else None, best[1] if best else None,
                          datetime.now(timezone.utc).isoformat()))
        return best

    # --- CVEs de uma versão ---
    def cves_for(self, vendor: str, product: str, version: str, *, offline_only: bool = False,
                 should_stop: StopFlag | None = None) -> NvdResult | None:
        ver = _cpe_escape(version)
        if ver is None:
            return None
        key = f"{vendor}:{product}:{ver}"
        with sqlite3.connect(self.cache_db) as conn:
            row = conn.execute("SELECT payload, fetched_at FROM cve_cache WHERE key = ?", (key,)).fetchone()
        if row:
            age = self._age(row[1])
            if offline_only or (age is not None and age <= self.ttl):
                return NvdResult(vendor, product, tuple(NvdCve(c[0], c[1], bool(c[2])) for c in json.loads(row[0])))
        if offline_only:
            return None
        cves: dict[str, NvdCve] = {}
        start, per_page = 0, 2000
        for _ in range(5):  # no máximo 10 mil CVEs por versão
            data = self._get(NVD_CVE_URL, {"virtualMatchString": f"cpe:2.3:a:{key}:*:*:*:*:*:*:*",
                                           "resultsPerPage": per_page, "startIndex": start}, should_stop)
            items = data.get("vulnerabilities") or []
            for v in items:
                cve = (v or {}).get("cve") or {}
                if cve.get("id"):
                    cid = str(cve["id"]).upper()
                    cves[cid] = NvdCve(cid, _cvss(cve), bool(cve.get("cisaExploitAdd")))
            start += len(items)
            if not items or start >= int(data.get("totalResults") or 0):
                break
        result = NvdResult(vendor, product, tuple(sorted(cves.values(), key=lambda c: c.id)))
        with sqlite3.connect(self.cache_db) as conn:
            conn.execute("INSERT INTO cve_cache (key, payload, fetched_at) VALUES (?, ?, ?) "
                         "ON CONFLICT(key) DO UPDATE SET payload = excluded.payload, fetched_at = excluded.fetched_at",
                         (key, json.dumps([[c.id, c.score, c.kev] for c in result.cves]),
                          datetime.now(timezone.utc).isoformat()))
        return result

    def lookup(self, p: Program, *, offline_only: bool = False,
               should_stop: StopFlag | None = None) -> NvdResult | None:
        cpe = self.cpe_for(p, offline_only=offline_only, should_stop=should_stop)
        if cpe is None:
            return None
        installed = p.installed[2:] if p.installed[:1] in "<>" else p.installed
        return self.cves_for(cpe[0], cpe[1], installed, offline_only=offline_only, should_stop=should_stop)


# ---------- avaliação ----------
def assess(p: Program, kev_level: str | None, kev_entries: list[KevEntry], kev_cves: set[str],
           nvd: NvdResult | None, nvd_note: str = "") -> Assessment:
    risk, detail = DESATUALIZADO, "Há versão nova. Rode a verificação completa para consultar falhas conhecidas."
    cves: tuple[str, ...] = ()
    worst = None
    exploited: list[str] = []
    if nvd is not None:
        cves = tuple(c.id for c in nvd.cves)
        worst = nvd.worst
        exploited = [c.id for c in nvd.cves if c.kev or c.id in kev_cves]
        unscored = any(c.score is None for c in nvd.cves)
        if exploited:
            risk = EXPLORADA
            detail = (f"A versão instalada tem falha usada em ataques ({', '.join(exploited[:5])}). "
                      "Atualize assim que puder.")
        elif not nvd.cves:
            risk, detail = SEM_CVE, "Nenhuma CVE encontrada na NVD para a versão instalada."
        else:
            if worst is not None and worst >= 7.0:
                risk = ALTA
            elif (worst is not None and worst >= 4.0) or unscored:
                risk = MEDIA  # CVE ainda sem nota: trata como média
            else:
                risk = BAIXA
            nota = f"pior nota CVSS {worst:.1f}" if worst is not None else "ainda sem nota CVSS"
            detail = f"{len(nvd.cves)} CVE(s) conhecida(s) na versão instalada; {nota}."
    elif nvd_note:
        detail = f"Há versão nova. {nvd_note}"
    kev_ids = tuple(e.cve_id for e in kev_entries)
    if kev_level == "forte" and RISK_RANK[risk] < RISK_RANK[EXPLORADA_PRODUTO]:
        risk = EXPLORADA_PRODUTO
        extra = f" {detail}" if nvd is not None else ""
        detail = f"{TEXTO_PRODUTO_EXPLORADO} (CISA KEV: {', '.join(kev_ids[:5])}){extra}"
    elif kev_level == "suspeita" and nvd is None and RISK_RANK[risk] < RISK_RANK[SUSPEITA]:
        e = kev_entries[0]
        risk = SUSPEITA
        detail = (f"O nome parece com \"{e.vendor_project} {e.product}\", que tem falhas usadas em ataques "
                  f"(CISA KEV), mas não é certeza que seja o mesmo programa.")
    marked = exploited if exploited else (list(kev_ids) if risk == EXPLORADA_PRODUTO else [])
    return Assessment(p, risk, detail, risk in PRESELECT, cves, tuple(marked), worst)


def _sort(items: list[Assessment]) -> list[Assessment]:
    return sorted(items, key=lambda a: (-RISK_RANK[a.risk], a.program.name.lower()))


# ---------- Windows Update (só leitura) ----------
PS_WU_SCRIPT = "; ".join([
    "$ErrorActionPreference = 'Stop'",
    "[Console]::OutputEncoding = [Text.Encoding]::UTF8",
    "$s = New-Object -ComObject Microsoft.Update.Session",
    "$r = $s.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0')",
    "$l = @(foreach ($u in $r.Updates) { $c = @($u.Categories | Where-Object { "
    "$_.CategoryID -eq '0fa1201d-4330-4fa8-8ae9-b877473b6441' }); "
    "[pscustomobject]@{ Title = [string]$u.Title; Security = [bool]($u.MsrcSeverity -or $c.Count -gt 0) } })",
    "ConvertTo-Json -InputObject $l -Compress",
])


def parse_windows_updates(text: str) -> WindowsUpdates:
    data = json.loads(text.strip() or "[]")
    if isinstance(data, dict):
        data = [data]
    rows = [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []
    sec = [r for r in rows if r.get("Security") is True]
    titles = [str(r.get("Title") or "") for r in sec + [r for r in rows if r not in sec]]
    return WindowsUpdates(True, len(rows), len(sec), titles)


# ---------- serviço ----------
_EXIT = {
    0x8A150101: ("fechar", "Feche o programa e tente de novo."),
    0x8A150103: ("fechar", "Um arquivo do programa está em uso: feche o programa e tente de novo."),
    0x8A150102: ("ocupado", "Outra instalação está em andamento; tente de novo daqui a pouco."),
    0x8A150109: ("reiniciar", "Atualizado; reinicie o computador para concluir."),
    0x8A15010B: ("reiniciar", "Atualizado; o computador vai reiniciar para concluir."),
    0x8A15010A: ("falhou", "Reinicie o computador e tente de novo."),
    0x8A15010C: ("cancelado", "Cancelado (o aviso de permissão do Windows foi recusado?)."),
    0x8A15002B: ("ja_atualizado", "Nenhuma atualização aplicável: já estava em dia."),
    0x8A15010D: ("ja_atualizado", "Já estava instalado."),
    0x8A15010F: ("falhou", "Bloqueado por política do computador."),
    0x8A150107: ("falhou", "Sem conexão com a internet."),
}


class UpdateService:
    """Verificação rápida / completa e aplicação de atualizações via winget."""

    def __init__(self, cache_dir: Path, *, run: Runner = _default_run, http: HttpFetcher = _default_http,
                 which: Callable[[], str | None] = find_winget, is_windows: bool | None = None,
                 kev: KevCache | None = None, nvd: NvdClient | None = None, ps: str | None = None):
        self.cache_dir = Path(cache_dir)
        self.run = run
        self.which = which
        self.is_windows = sys.platform == "win32" if is_windows is None else is_windows
        self.kev = kev or KevCache(cache_db=self.cache_dir / "kev.db", http=http)
        self.nvd = nvd or NvdClient(self.cache_dir / "nvd.db", http=http)
        self.ps = ps or powershell_path()

    def _winget(self) -> str:
        w = self.which()
        if not w:
            raise WingetUnavailable("O winget (Instalador de Aplicativo) não foi encontrado neste computador.")
        return w

    def list_upgrades(self) -> tuple[list[Program], str, list[str]]:
        winget = self._winget()
        notes: list[str] = []
        if self.is_windows:
            try:
                rc, out = self.run(_ps_args(self.ps, PS_LIST_SCRIPT), 180)
                if rc == 0:
                    return parse_ps_packages(out), "Microsoft.WinGet.Client", notes
            except (OSError, subprocess.SubprocessError, ValueError):
                pass  # sem PowerShell/módulo ou JSON ruim: usa o texto do winget
        try:
            rc, out = self.run([winget, "upgrade", "--include-unknown", "--accept-source-agreements",
                                "--disable-interactivity"], 300)
        except FileNotFoundError as e:
            raise WingetUnavailable(str(e)) from e
        except subprocess.TimeoutExpired as e:
            raise RuntimeError("O winget demorou demais para responder.") from e
        programs, skipped = parse_winget_upgrade(out)
        if rc != 0 and not programs and "---" not in out:
            raise RuntimeError(f"O winget falhou (código 0x{rc & 0xFFFFFFFF:08X}).")
        if skipped:
            notes.append(f"{skipped} programa(s) não puderam ser lidos na saída do winget.")
        return programs, "winget upgrade", notes

    def _check(self, complete: bool, on_progress: Progress | None, should_stop: StopFlag | None) -> CheckResult:
        prog = on_progress or (lambda *_: None)
        stop = should_stop or (lambda: False)
        prog("Listando programas com versão nova…", 0, 0)
        programs, method, notes = self.list_upgrades()
        prog("Consultando o catálogo de falhas exploradas (CISA KEV)…", 0, len(programs))
        matcher = KevMatcher(self.kev)
        if not matcher.entries:
            notes.append("Catálogo CISA KEV indisponível (sem internet e sem cópia local).")
        result = CheckResult([], complete, method, notes)
        errors = 0
        for i, p in enumerate(programs, 1):
            level, entries = matcher.match(p)
            nvd, nvd_note = None, ""
            if complete and not any(c.isdigit() for c in p.installed):
                nvd_note = "Versão instalada desconhecida: sem consulta à NVD."
            elif complete and not result.interrupted and errors < 3:
                prog(f"Consultando a NVD: {p.name}", i - 1, len(programs))
                try:
                    nvd = self.nvd.lookup(p, should_stop=stop)
                    errors = 0
                    if nvd is None:
                        nvd_note = "Programa não identificado na NVD."
                except Cancelled:
                    result.interrupted = True
                except Exception:  # noqa: BLE001 - rede/HTTP/JSON: segue com o cache
                    errors += 1
                    nvd_note = "NVD indisponível agora."
                if stop():
                    result.interrupted = True
            if nvd is None:
                nvd = self.nvd.lookup(p, offline_only=True)  # cache (de uma completa anterior)
            result.items.append(assess(p, level, entries, matcher.cves, nvd, nvd_note))
        if complete and errors >= 3:
            notes.append("A NVD não respondeu; parte dos programas ficou sem consulta de CVEs.")
        if result.interrupted:
            notes.append("Verificação interrompida: a lista pode estar incompleta.")
        if complete and not result.interrupted:
            prog("Lendo atualizações pendentes do Windows…", len(programs), len(programs))
            result.windows = self.windows_updates()
        result.items = _sort(result.items)
        return result

    def quick(self, on_progress: Progress | None = None, should_stop: StopFlag | None = None) -> CheckResult:
        return self._check(False, on_progress, should_stop)

    def complete(self, on_progress: Progress | None = None, should_stop: StopFlag | None = None) -> CheckResult:
        return self._check(True, on_progress, should_stop)

    def windows_updates(self) -> WindowsUpdates:
        if not self.is_windows:
            return WindowsUpdates(False, reason="indisponível fora do Windows")
        try:
            rc, out = self.run(_ps_args(self.ps, PS_WU_SCRIPT), 600)
            if rc != 0:
                return WindowsUpdates(False, reason=f"indisponível (código {rc & 0xFFFFFFFF:#x})")
            return parse_windows_updates(out)
        except (OSError, subprocess.SubprocessError, ValueError) as e:
            return WindowsUpdates(False, reason=f"indisponível ({e})")

    def apply_one(self, p: Program) -> ApplyResult:
        if not valid_winget_id(p.id):
            return ApplyResult(p.id, p.name, "invalido", "Identificador inválido; nada foi executado.")
        try:
            winget = self._winget()
        except WingetUnavailable as e:
            return ApplyResult(p.id, p.name, "falhou", str(e))
        args = [winget, "upgrade", "--id", p.id, "--exact", "--silent",
                "--accept-package-agreements", "--accept-source-agreements"]
        if _SOURCE_RE.fullmatch(p.source or ""):
            args += ["--source", p.source]
        try:
            rc, _out = self.run(args, 1800)
        except subprocess.TimeoutExpired:
            return ApplyResult(p.id, p.name, "falhou", "Demorou demais (mais de 30 minutos).")
        except OSError as e:
            return ApplyResult(p.id, p.name, "falhou", f"Não foi possível executar o winget: {e}")
        code = rc & 0xFFFFFFFF
        if code == 0:
            return ApplyResult(p.id, p.name, "ok", "Atualizado.", 0)
        status, msg = _EXIT.get(code, ("falhou", f"Falhou (código 0x{code:08X})."))
        return ApplyResult(p.id, p.name, status, msg, code)

    def apply(self, programs: list[Program], on_result: Callable[[ApplyResult], None] | None = None,
              should_stop: StopFlag | None = None,
              on_start: Callable[[Program], None] | None = None) -> list[ApplyResult]:
        """Um por vez, na ordem dada; para antes do próximo se `should_stop`."""
        results = []
        for p in programs:
            if should_stop is not None and should_stop():
                break
            if on_start is not None:
                on_start(p)
            r = self.apply_one(p)
            results.append(r)
            if on_result is not None:
                on_result(r)
        return results
