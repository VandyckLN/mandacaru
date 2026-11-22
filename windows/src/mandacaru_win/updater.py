"""Autoatualização do Mandacaru no Windows (sem Qt: testável em qualquer sistema).

Fluxo: consulta a última release no GitHub (no máximo 1×/24 h), oferece a versão
nova se houver instalador publicado com hash, baixa para ``<dados>/updates``,
confere o SHA-256 com o ``digest`` da API e só então monta o comando do setup.
Falha de rede nunca vira exceção para a interface: vira "nada a fazer".
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from mandacaru_win import __version__

RELEASES_URL = "https://api.github.com/repos/VandyckLN/mandacaru/releases/latest"
# O instalador só é baixado deste prefixo (o GitHub redireciona para o CDN dele).
DOWNLOAD_PREFIX = "https://github.com/VandyckLN/mandacaru/releases/download/"
CHECK_INTERVAL = 24 * 3600
SNOOZE = 7 * 24 * 3600
CHECK_TIMEOUT = 8.0
DOWNLOAD_TIMEOUT = 30.0
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_SETUP_BYTES = 512 * 1024 * 1024
STATE_FILE = "update.json"
UPDATES_DIR = "updates"
# Parâmetro próprio: o installer.iss reabre o app só quando ele está presente.
REOPEN_FLAG = "/ATUALIZACAO"

# Mesmo contrato de urllib.request.urlopen(req, timeout=...): devolve uma
# resposta com .read(n) usável em "with"; erros de rede são OSError.
Http = Callable[..., object]

_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+)*)$")
_DIGEST_RE = re.compile(r"^sha256:([0-9a-fA-F]{64})$")


class UpdateError(Exception):
    """Falha ao baixar ou conferir o instalador (mensagem pronta para a interface)."""


@dataclass(frozen=True)
class Update:
    version: str
    current: str
    url: str
    sha256: str
    size: int | None
    name: str


@dataclass(frozen=True)
class CheckResult:
    update: Update | None  # preenchido só quando a faixa deve aparecer
    reason: str  # disponivel | em_dia | adiado | recente | falha


# ---------- versões ----------
def parse_version(text: object) -> tuple[int, ...] | None:
    """'v0.6.1' -> (0, 6, 1). Sufixos (rc, beta, -dev...) -> None: são ignorados."""
    if not isinstance(text, str):
        return None
    m = _VERSION_RE.match(text.strip())
    if not m:
        return None
    parts = [int(p) for p in m.group(1).split(".")]
    while len(parts) > 1 and parts[-1] == 0:  # 0.7 == 0.7.0
        parts.pop()
    return tuple(parts)


def is_newer(candidate: str, current: str) -> bool:
    a, b = parse_version(candidate), parse_version(current)
    return a is not None and b is not None and a > b


def asset_name(version: str) -> str:
    return f"Mandacaru-{version}-setup.exe"


def pick_update(release: object, current: str = __version__) -> Update | None:
    """Update se a release é estável, maior que a atual e tem instalador com hash."""
    if not isinstance(release, dict) or release.get("draft") or release.get("prerelease"):
        return None
    tag = release.get("tag_name")
    if parse_version(tag) is None or not is_newer(tag, current):
        return None
    version = tag.strip().lstrip("v")
    name = asset_name(version)
    for asset in release.get("assets") or []:
        if not isinstance(asset, dict) or asset.get("name") != name:
            continue
        url = asset.get("browser_download_url")
        m = _DIGEST_RE.match(str(asset.get("digest") or ""))
        if not isinstance(url, str) or not url.startswith(DOWNLOAD_PREFIX) or not m:
            return None  # sem hash publicado não oferecemos (não daria para conferir)
        size = asset.get("size")
        size = size if isinstance(size, int) and not isinstance(size, bool) and size > 0 else None
        if size is not None and size > MAX_SETUP_BYTES:
            return None
        return Update(version, current, url, m.group(1).lower(), size, name)
    return None


# ---------- rede ----------
def _request(url: str, accept: str) -> urllib.request.Request:
    return urllib.request.Request(url, headers={
        "User-Agent": f"mandacaru/{__version__}", "Accept": accept})


def fetch_latest(http: Http = urllib.request.urlopen, timeout: float = CHECK_TIMEOUT) -> dict | None:
    """JSON da última release, ou None em qualquer falha (rede, HTTP, JSON)."""
    try:
        req = _request(RELEASES_URL, "application/vnd.github+json")
        with http(req, timeout=timeout) as resp:
            body = resp.read(MAX_JSON_BYTES + 1)
        if len(body) > MAX_JSON_BYTES:
            return None
        data = json.loads(body.decode("utf-8"))
    except Exception:  # noqa: BLE001 - rede, HTTP, JSON: nada disso pode chegar à interface
        return None
    return data if isinstance(data, dict) else None


# ---------- estado (update.json) ----------
def load_state(data: Path) -> dict:
    try:
        raw = json.loads((Path(data) / STATE_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return raw if isinstance(raw, dict) else {}


def save_state(data: Path, state: dict) -> None:
    """Grava atomicamente; falha de disco é ignorada (só perde o carimbo)."""
    path = Path(data) / STATE_FILE
    tmp = path.with_name(path.name + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _num(v: object) -> float:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else 0.0


def _cached_update(state: dict, current: str) -> Update | None:
    raw = state.get("disponivel")
    if not isinstance(raw, dict):
        return None
    try:
        u = Update(**{**raw, "current": current})
    except TypeError:
        return None
    ok = (is_newer(u.version, current) and isinstance(u.url, str) and u.url.startswith(DOWNLOAD_PREFIX)
          and isinstance(u.sha256, str) and re.fullmatch(r"[0-9a-f]{64}", u.sha256) is not None
          and u.name == asset_name(u.version))
    return u if ok else None


def is_snoozed(state: dict, update: Update, now: float) -> bool:
    """'Depois' vale 7 dias, ou até aparecer versão maior que a adiada."""
    v = state.get("adiada_versao")
    return (_num(state.get("adiado_ate")) > now and isinstance(v, str)
            and not is_newer(update.version, v))


def check(data: Path, current: str = __version__, http: Http = urllib.request.urlopen,
          now: Callable[[], float] = time.time, force: bool = False,
          timeout: float = CHECK_TIMEOUT) -> CheckResult:
    """Decide se a faixa aparece. ``force`` (botão "Verificar") ignora o carimbo e o adiamento."""
    t = now()
    state = load_state(data)
    last = state.get("ultima_verificacao")
    recent = isinstance(last, (int, float)) and not isinstance(last, bool) and 0 <= t - last < CHECK_INTERVAL
    if not force and recent:
        update = _cached_update(state, current)  # a faixa volta na próxima abertura
        reason = "recente"
    else:
        release = fetch_latest(http, timeout)
        if release is None:
            return CheckResult(None, "falha")  # sem carimbo: tenta de novo na próxima abertura
        update = pick_update(release, current)
        state["ultima_verificacao"] = t
        state["disponivel"] = asdict(update) if update else None
        save_state(data, state)
        reason = "disponivel" if update else "em_dia"
    if update is None:
        return CheckResult(None, "em_dia" if reason == "disponivel" else reason)
    if not force and is_snoozed(state, update, t):
        return CheckResult(None, "adiado")
    return CheckResult(update, "disponivel")


def snooze(data: Path, version: str, now: Callable[[], float] = time.time) -> None:
    state = load_state(data)
    state["adiada_versao"] = version
    state["adiado_ate"] = now() + SNOOZE
    save_state(data, state)


# ---------- download e instalação ----------
def updates_dir(data: Path) -> Path:
    return Path(data) / UPDATES_DIR


def download(update: Update, data: Path, http: Http = urllib.request.urlopen,
             timeout: float = DOWNLOAD_TIMEOUT,
             on_progress: Callable[[int, int | None], None] | None = None,
             should_stop: Callable[[], bool] = lambda: False,
             chunk: int = 256 * 1024) -> Path:
    """Baixa e confere o SHA-256. Devolve o caminho do setup; senão UpdateError (sem deixar arquivo)."""
    if not re.fullmatch(r"[0-9a-f]{64}", update.sha256 or ""):
        raise UpdateError("A versão publicada não traz o hash do instalador; a atualização foi cancelada.")
    if update.name != asset_name(update.version) or parse_version(update.version) is None \
            or not update.url.startswith(DOWNLOAD_PREFIX):
        raise UpdateError("Dados da atualização inválidos; a atualização foi cancelada.")
    folder = updates_dir(data)
    try:
        folder.mkdir(parents=True, exist_ok=True)
        for old in folder.iterdir():  # instaladores antigos não servem mais
            if old.is_file() and old.suffix in (".exe", ".part"):
                old.unlink()
    except OSError as e:
        raise UpdateError(f"Não foi possível preparar a pasta de atualizações: {e}") from e
    dest = folder / update.name
    part = folder / (update.name + ".part")
    h = hashlib.sha256()
    got = 0
    try:
        req = _request(update.url, "application/octet-stream")
        with http(req, timeout=timeout) as resp, open(part, "wb") as fh:
            while True:
                if should_stop():
                    raise UpdateError("Download cancelado.")
                block = resp.read(chunk)
                if not block:
                    break
                got += len(block)
                if got > MAX_SETUP_BYTES or (update.size is not None and got > update.size):
                    raise UpdateError("O arquivo baixado é maior que o publicado; a atualização foi cancelada.")
                h.update(block)
                fh.write(block)
                if on_progress is not None:
                    on_progress(got, update.size)
        if h.hexdigest() != update.sha256:
            raise UpdateError("O arquivo baixado não confere com o publicado (SHA-256 diferente). "
                              "Nada foi instalado.")
        os.replace(part, dest)
    except UpdateError:
        _discard(part)
        raise
    except (OSError, ValueError) as e:
        _discard(part)
        raise UpdateError(f"Não foi possível baixar a atualização: {e}") from e
    return dest


def _discard(p: Path) -> None:
    try:
        p.unlink(missing_ok=True)
    except OSError:
        pass


def install_command(setup: Path, log: Path | None = None) -> list[str]:
    """Instalação silenciosa por cima da atual; o instalador reabre o app (REOPEN_FLAG)."""
    cmd = [str(setup), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
           "/CLOSEAPPLICATIONS", REOPEN_FLAG]
    if log is not None:
        cmd.append(f"/LOG={log}")
    return cmd


def _default_runner(cmd: list[str]) -> None:
    kw: dict = {"close_fds": True}
    if sys.platform == "win32":  # o setup precisa sobreviver ao app que vai fechar
        kw["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    subprocess.Popen(cmd, **kw)  # noqa: S603 - caminho e argumentos montados aqui


def run_installer(setup: Path, runner: Callable[[list[str]], None] = _default_runner) -> None:
    """Executa o setup (``runner`` injetável). Erro ao iniciar vira UpdateError."""
    cmd = install_command(setup, Path(setup).with_name("instalacao.log"))
    try:
        runner(cmd)
    except OSError as e:
        raise UpdateError(f"Não foi possível iniciar o instalador: {e}") from e

