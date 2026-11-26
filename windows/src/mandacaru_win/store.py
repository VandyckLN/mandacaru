"""Dados do usuário: lista de confiança, achados de projeto ignorados e histórico de varreduras."""
from __future__ import annotations

import dataclasses
import json
import os
import time
from datetime import datetime
from pathlib import Path

from mandacaru_win.scan import ScanSummary


def data_dir() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share")
    d = base / "Mandacaru"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _atomic_write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(data, ensure_ascii=False, indent=2))
            fh.flush()
            os.fsync(fh.fileno())
        for attempt in range(5):  # antivírus/indexador podem segurar o destino
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.05)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _backup_corrupt(path: Path) -> None:
    """Preserva o arquivo corrompido sem sobrescrever backups anteriores."""
    dest = path.with_name(path.name + ".corrompido")
    n = 1
    while dest.exists():
        dest = path.with_name(f"{path.name}.corrompido.{n}")
        n += 1
    os.replace(path, dest)


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
            return [e for e in data if isinstance(e, dict) and isinstance(e.get("sha256"), str)]
        except ValueError:  # inclui UnicodeDecodeError e JSONDecodeError
            _backup_corrupt(self._path)
            return []

    def _save(self, entries: list[dict]) -> None:
        _atomic_write_json(self._path, entries)

    def hashes(self) -> set[str]:
        return {e["sha256"] for e in self._entries}

    def entries(self) -> list[dict]:
        return list(self._entries)

    def add(self, sha256: str, path: Path) -> None:
        if sha256 in self.hashes():
            return
        entries = [*self._entries, {
            "sha256": sha256,
            "caminho_quando_confiado": str(path),
            "data": datetime.now().isoformat(timespec="seconds"),
        }]
        self._save(entries)
        self._entries = entries

    def remove(self, sha256: str) -> None:
        entries = [e for e in self._entries if e["sha256"] != sha256]
        self._save(entries)
        self._entries = entries


class ExcludeList:
    """Pastas excluídas da varredura pelo usuário."""

    def __init__(self, path: Path):
        self._path = Path(path)
        self._entries: list[dict] = self._load()

    @staticmethod
    def _key(path: str | os.PathLike) -> str:
        return os.path.normcase(os.path.abspath(path))

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
            return [e for e in data if isinstance(e, dict) and isinstance(e.get("caminho"), str)
                    and e["caminho"].strip()]
        except ValueError:
            _backup_corrupt(self._path)
            return []

    def _save(self, entries: list[dict]) -> None:
        _atomic_write_json(self._path, entries)

    def paths(self) -> list[str]:
        return [e["caminho"] for e in self._entries]

    def entries(self) -> list[dict]:
        return list(self._entries)

    def add(self, path: str | os.PathLike) -> None:
        full = os.path.abspath(path)
        key = self._key(full)
        if any(self._key(e["caminho"]) == key for e in self._entries):
            return
        entries = [*self._entries, {
            "caminho": full,
            "data": datetime.now().isoformat(timespec="seconds"),
        }]
        self._save(entries)
        self._entries = entries

    def remove(self, path: str | os.PathLike) -> None:
        key = self._key(path)
        entries = [e for e in self._entries if self._key(e["caminho"]) != key]
        self._save(entries)
        self._entries = entries


class IgnoradosProjeto:
    """Achados de "Verificar projeto" ignorados pelo usuário.

    Arquivos: par (regra, SHA-256 do arquivo) — mudou o arquivo, o achado volta a aparecer.
    Dependências: par (regra, chave) com chave = (ecossistema, nome, versão, *ids) — mudar outra linha
    do lockfile não traz de volta, mas um aviso novo para o mesmo pacote traz.
    """

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
            return [e for e in data if isinstance(e, dict) and isinstance(e.get("regra"), str)
                    and (isinstance(e.get("sha256"), str) or _lista_str(e.get("chave")))]
        except ValueError:  # inclui UnicodeDecodeError e JSONDecodeError
            _backup_corrupt(self._path)
            return []

    def contem(self, regra: str, sha256: str) -> bool:
        return any(e["regra"] == regra and e.get("sha256") == sha256 for e in self._entries)

    def contem_chave(self, regra: str, chave: tuple[str, ...]) -> bool:
        return any(e["regra"] == regra and e.get("chave") == list(chave) for e in self._entries)

    def adicionar_chave(self, regra: str, chave: tuple[str, ...], caminho: Path) -> None:
        if self.contem_chave(regra, chave):
            return
        self._gravar({"regra": regra, "chave": list(chave), "caminho": str(caminho),
                      "data": datetime.now().isoformat(timespec="seconds")})

    def _gravar(self, entrada: dict) -> None:
        entries = [*self._entries, entrada]
        _atomic_write_json(self._path, entries)
        self._entries = entries

    def entries(self) -> list[dict]:
        return list(self._entries)

    def adicionar(self, regra: str, sha256: str, caminho: Path) -> None:
        if self.contem(regra, sha256):
            return
        self._gravar({"regra": regra, "sha256": sha256, "caminho": str(caminho),
                      "data": datetime.now().isoformat(timespec="seconds")})


def _lista_str(v: object) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def _num(v: object) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


UPDATE_KIND = "atualizacao"


def _valid_update(row: dict) -> bool:
    progs = row.get("programas")
    return (_num(row.get("started")) and _num(row.get("duration", 0)) and isinstance(progs, list)
            and all(isinstance(p, dict) and all(isinstance(v, str) for v in p.values()) for p in progs))


def _valid_summary(row: object) -> bool:
    """Linha do histórico com os tipos esperados; qualquer outra é ignorada."""
    if not isinstance(row, dict):
        return False
    if row.get("tipo") == UPDATE_KIND:
        return _valid_update(row)
    paths = row.get("paths", [])
    return (isinstance(paths, list) and all(isinstance(p, str) for p in paths)
            and all(_num(row.get(k, 0)) for k in ("files", "findings", "duration"))
            and (_num(row.get("started", 0)) or isinstance(row.get("started"), str)))


class History:
    """Histórico de varreduras em JSON Lines (uma por linha)."""

    def __init__(self, path: Path):
        self._path = Path(path)

    def append(self, summary: ScanSummary) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(dataclasses.asdict(summary), ensure_ascii=False) + "\n")

    def append_update(self, started: float, duration: float, programas: list[dict[str, str]]) -> None:
        """Registra uma rodada de "Atualizar selecionados" (id, nome, de, para, resultado, mensagem)."""
        row = {"tipo": UPDATE_KIND, "started": started, "duration": duration,
               "programas": [{k: str(v) for k, v in p.items()} for p in programas]}
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

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
                if _valid_summary(row):
                    rows.append(row)
        return rows[::-1][:n]
