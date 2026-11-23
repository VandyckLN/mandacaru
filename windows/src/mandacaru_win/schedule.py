"""Agendamento de varredura em segundo plano com expressões cron (5 campos).

Padrão: a cada 4 horas (`0 */4 * * *`). Sem dependências externas (apenas stdlib).
Formato cron: `minuto hora dia-do-mês mês dia-da-semana`
  - minuto:        0-59
  - hora:          0-23
  - dia-do-mês:    1-31
  - mês:           1-12
  - dia-da-semana: 0-7 (0 e 7 = domingo, 1 = segunda ... 6 = sábado)
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from mandacaru_win.store import _atomic_write_json, _backup_corrupt

DEFAULT_CRON = "0 */4 * * *"

CRON_PRESETS: tuple[tuple[str, str], ...] = (
    ("A cada 4 horas (padrão)", "0 */4 * * *"),
    ("A cada 1 hora", "0 * * * *"),
    ("A cada 2 horas", "0 */2 * * *"),
    ("A cada 6 horas", "0 */6 * * *"),
    ("A cada 12 horas", "0 */12 * * *"),
    ("Todo dia às 12:00", "0 12 * * *"),
    ("Todo dia às 18:00", "0 18 * * *"),
    ("Toda segunda às 09:00", "0 9 * * 1"),
)

_FIELD_SPEC = (
    ("minuto", 0, 59),
    ("hora", 0, 23),
    ("dia do mês", 1, 31),
    ("mês", 1, 12),
    ("dia da semana", 0, 7),
)


class CronError(ValueError):
    """Expressão cron inválida (mensagem em português para a interface)."""


def _parse_field(token: str, name: str, lo: int, hi: int, is_dow: bool = False) -> tuple[frozenset[int], bool]:
    """Retorna (valores_aceitos, eh_curinga)."""
    token = token.strip()
    if not token:
        raise CronError(f"Campo '{name}' vazio.")
    wildcard = token == "*"
    values: set[int] = set()
    for part in token.split(","):
        part = part.strip()
        if not part:
            raise CronError(f"Item vazio no campo '{name}'.")
        step = 1
        if "/" in part:
            base, step_str = part.split("/", 1)
            if not step_str.isdigit() or int(step_str) <= 0:
                raise CronError(f"Passo inválido '{part}' no campo '{name}'.")
            step = int(step_str)
        else:
            base = part
        if base == "*":
            start, end = lo, hi
        elif "-" in base:
            a, b = base.split("-", 1)
            if not (a.isdigit() and b.isdigit()):
                raise CronError(f"Intervalo inválido '{part}' no campo '{name}'.")
            start, end = int(a), int(b)
            if start > end:
                raise CronError(f"Intervalo invertido '{part}' no campo '{name}'.")
        elif base.isdigit():
            start = int(base)
            end = hi if "/" in part else start
        else:
            raise CronError(f"Valor inválido '{part}' no campo '{name}'.")
        if start < lo or end > hi:
            raise CronError(f"Valor fora do limite ({lo}–{hi}) no campo '{name}': '{part}'.")
        for v in range(start, end + 1, step):
            values.add(0 if (is_dow and v == 7) else v)
    if not values:
        raise CronError(f"Nenhum valor válido no campo '{name}'.")
    return frozenset(values), wildcard


@dataclass(frozen=True)
class CronSchedule:
    expr: str
    minutes: frozenset[int]
    hours: frozenset[int]
    days: frozenset[int]
    months: frozenset[int]
    dows: frozenset[int]
    dom_any: bool
    dow_any: bool

    def _dow_matches(self, dt: datetime) -> bool:
        # Python weekday(): segunda=0..domingo=6 -> cron: domingo=0, segunda=1..sábado=6
        cron_dow = (dt.weekday() + 1) % 7
        return cron_dow in self.dows

    def _day_matches(self, dt: datetime) -> bool:
        dom_ok = dt.day in self.days
        dow_ok = self._dow_matches(dt)
        if self.dom_any and self.dow_any:
            return True
        if self.dom_any:
            return dow_ok
        if self.dow_any:
            return dom_ok
        # Semântica clássica do Vixie cron: quando ambos são restritos, vale OU.
        return dom_ok or dow_ok

    def matches(self, dt: datetime) -> bool:
        return (
            dt.minute in self.minutes
            and dt.hour in self.hours
            and dt.month in self.months
            and self._day_matches(dt)
        )

    def next_run(self, after: datetime) -> datetime:
        """Próximo instante (estritamente após `after`, precisão de minuto) que satisfaz o cron."""
        cur = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
        limit = cur + timedelta(days=366 * 5)
        while cur < limit:
            if cur.month not in self.months:
                year = cur.year + (1 if cur.month == 12 else 0)
                month = 1 if cur.month == 12 else cur.month + 1
                cur = cur.replace(year=year, month=month, day=1, hour=0, minute=0)
                continue
            if not self._day_matches(cur):
                cur = (cur + timedelta(days=1)).replace(hour=0, minute=0)
                continue
            if cur.hour not in self.hours:
                cur = (cur + timedelta(hours=1)).replace(minute=0)
                continue
            if cur.minute not in self.minutes:
                cur = cur + timedelta(minutes=1)
                continue
            return cur
        raise CronError("A expressão cron não possui próxima execução nos próximos 5 anos.")


def parse_cron(expr: str) -> CronSchedule:
    """Valida e converte uma expressão cron de 5 campos."""
    if not isinstance(expr, str):
        raise CronError("A expressão cron deve ser texto.")
    parts = expr.strip().split()
    if len(parts) != 5:
        raise CronError("Use exatamente 5 campos: minuto hora dia mês dia-da-semana (ex.: 0 */4 * * *).")
    parsed = []
    for i, ((name, lo, hi), tok) in enumerate(zip(_FIELD_SPEC, parts, strict=True)):
        parsed.append(_parse_field(tok, name, lo, hi, is_dow=(i == 4)))
    return CronSchedule(
        expr=" ".join(parts),
        minutes=parsed[0][0],
        hours=parsed[1][0],
        days=parsed[2][0],
        months=parsed[3][0],
        dows=parsed[4][0],
        dom_any=parsed[2][1],
        dow_any=parsed[4][1],
    )


def describe_cron(expr: str) -> str:
    """Descrição amigável em português para expressões comuns."""
    norm = " ".join(expr.strip().split())
    for label, preset in CRON_PRESETS:
        if norm == preset:
            return label
    parts = norm.split()
    if len(parts) == 5:
        m, h, dom, mon, dow = parts
        if dom == "*" and mon == "*" and dow == "*":
            if m.startswith("*/") and h == "*":
                return f"A cada {m[2:]} minuto(s)"
            if m == "0" and h.startswith("*/"):
                return f"A cada {h[2:]} hora(s)"
            if m.isdigit() and h.isdigit():
                return f"Todo dia às {int(h):02d}:{int(m):02d}"
    return f"Agendamento personalizado ({norm})"


VALID_SCOPES = ("principais", "completa", "personalizada")
DEFAULT_BATCH_SIZE = 200
DEFAULT_BATCH_PAUSE_S = 0.05


@dataclass
class ScheduleConfig:
    enabled: bool = True
    cron: str = DEFAULT_CRON
    paths: list[str] = field(default_factory=list)
    scope: str = "completa"  # principais | completa (em lotes) | personalizada
    minimize_to_tray: bool = True
    last_run: float | None = None


class ScheduleStore:
    """Persistência atômica das configurações de monitoramento em `schedule.json`."""

    def __init__(self, path: Path):
        self._path = Path(path)
        self._cfg = self._load()

    def _load(self) -> ScheduleConfig:
        if not self._path.exists():
            return ScheduleConfig()
        try:
            raw = self._path.read_bytes()
        except FileNotFoundError:
            return ScheduleConfig()
        try:
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("formato inesperado")
        except ValueError:
            _backup_corrupt(self._path)
            return ScheduleConfig()

        cron = data.get("cron", DEFAULT_CRON)
        try:
            cron = parse_cron(cron).expr
        except CronError:
            cron = DEFAULT_CRON
        enabled = data.get("enabled")
        minimize = data.get("minimize_to_tray")
        paths = data.get("paths")
        clean_paths = ([os.path.abspath(p) for p in paths if isinstance(p, str) and p.strip()]
                       if isinstance(paths, list) else [])
        scope = data.get("scope")
        if scope not in VALID_SCOPES:
            scope = "personalizada" if clean_paths else "completa"
        last_run = data.get("last_run")
        return ScheduleConfig(
            enabled=enabled if isinstance(enabled, bool) else True,
            cron=cron,
            paths=clean_paths,
            scope=scope,
            minimize_to_tray=minimize if isinstance(minimize, bool) else True,
            last_run=float(last_run) if isinstance(last_run, (int, float)) and not isinstance(last_run, bool) else None,
        )

    def get(self) -> ScheduleConfig:
        return ScheduleConfig(
            enabled=self._cfg.enabled,
            cron=self._cfg.cron,
            paths=list(self._cfg.paths),
            scope=self._cfg.scope,
            minimize_to_tray=self._cfg.minimize_to_tray,
            last_run=self._cfg.last_run,
        )

    def save(self, cfg: ScheduleConfig) -> None:
        normalized = parse_cron(cfg.cron).expr
        scope = cfg.scope if cfg.scope in VALID_SCOPES else "completa"
        clean = ScheduleConfig(
            enabled=bool(cfg.enabled),
            cron=normalized,
            paths=list(dict.fromkeys(os.path.abspath(p) for p in cfg.paths if str(p).strip())),
            scope=scope,
            minimize_to_tray=bool(cfg.minimize_to_tray),
            last_run=cfg.last_run,
        )
        _atomic_write_json(self._path, {
            "enabled": clean.enabled,
            "cron": clean.cron,
            "paths": clean.paths,
            "scope": clean.scope,
            "minimize_to_tray": clean.minimize_to_tray,
            "last_run": clean.last_run,
        })
        self._cfg = clean

    def mark_run(self, ts: float | None = None) -> None:
        cfg = self.get()
        cfg.last_run = time.time() if ts is None else float(ts)
        self.save(cfg)
