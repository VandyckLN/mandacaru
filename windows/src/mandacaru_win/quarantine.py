"""Quarentena: guarda o arquivo embaralhado e restaura só se o hash conferir."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import uuid
from datetime import datetime
from pathlib import Path

from mandacaru_win.scan import Finding
from mandacaru_win.shred import ShredError, shred_file

KEY = b"mandacaru-quarentena"
CHUNK = 1024 * 1024
_ID_RE = re.compile(r"[0-9a-f]{32}")
_GONE = "O arquivo não existe mais; varra de novo."


class QuarantineError(Exception):
    """Erro com mensagem em português, pronta para mostrar ao usuário."""


def _xor(data: bytes, offset: int = 0) -> bytes:
    # Simétrico: embaralhar e desembaralhar são a mesma operação. `offset` é a
    # posição do bloco no arquivo (a chave se repete ao longo do arquivo todo).
    n = len(data)
    if n == 0:
        return b""
    k = len(KEY)
    start = offset % k
    stream = (KEY * ((start + n) // k + 1))[start:start + n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")).to_bytes(n, "big")


def _read_zone(path: Path) -> str | None:
    """Mark-of-the-Web (fluxo NTFS Zone.Identifier); só no Windows, falha em silêncio."""
    if sys.platform != "win32":
        return None
    try:
        with open(str(path) + ":Zone.Identifier", "rb") as fh:
            return fh.read(65536).decode("utf-8", "replace")
    except OSError:
        return None


def _write_zone(path: Path, text: str) -> None:
    if sys.platform != "win32":
        return
    try:
        with open(str(path) + ":Zone.Identifier", "wb") as fh:
            fh.write(text.encode("utf-8"))
    except OSError:
        pass


def _sha_plain(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def _sha_scrambled(path: Path) -> str:
    """SHA-256 do conteúdo original de um .bin (desembaralhando em blocos)."""
    h = hashlib.sha256()
    off = 0
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            h.update(_xor(chunk, off))
            off += len(chunk)
    return h.hexdigest()


def _fsync_write(path: Path, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())


def _valid_meta(m: object) -> bool:
    return (isinstance(m, dict)
            and all(isinstance(m.get(k), str) for k in ("caminho_original", "sha256", "data")))


class Quarantine:
    def __init__(self, base: Path):
        self._base = Path(base)

    def _paths(self, qid: str) -> tuple[Path, Path]:
        if not isinstance(qid, str) or not _ID_RE.fullmatch(qid):
            raise QuarantineError("Item de quarentena inválido.")
        return self._base / f"{qid}.bin", self._base / f"{qid}.json"

    def add(self, finding: Finding) -> str:
        original = Path(finding.path)
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
        zone = _read_zone(original)
        if zone is not None:
            meta["zone_identifier"] = zone
        stage = "gravar na quarentena"
        try:
            self._base.mkdir(parents=True, exist_ok=True)
            stage = "ler o arquivo"
            h = hashlib.sha256()
            off = 0
            with open(original, "rb") as src:
                stage = "gravar na quarentena"
                with open(binp, "wb") as dst:
                    while True:
                        stage = "ler o arquivo"
                        chunk = src.read(CHUNK)
                        stage = "gravar na quarentena"
                        if not chunk:
                            break
                        h.update(chunk)
                        dst.write(_xor(chunk, off))
                        off += len(chunk)
                    dst.flush()
                    os.fsync(dst.fileno())
            if h.hexdigest() != finding.sha256:
                raise QuarantineError("O arquivo mudou desde a varredura; varra de novo.")
            stage = "gravar na quarentena"
            if _sha_scrambled(binp) != finding.sha256:
                raise OSError("a cópia em quarentena não confere")
            _fsync_write(jsonp, json.dumps(meta, ensure_ascii=False, indent=2))
        except QuarantineError:
            self._cleanup(binp, jsonp)
            raise
        except FileNotFoundError as e:
            self._cleanup(binp, jsonp)
            raise QuarantineError(_GONE) from e
        except (OSError, MemoryError) as e:
            self._cleanup(binp, jsonp)
            if stage == "ler o arquivo":
                raise QuarantineError(f"Não foi possível ler o arquivo: {e}") from e
            raise QuarantineError(f"Não foi possível gravar na quarentena: {e}") from e
        try:
            self._remove_original(original)
        except FileNotFoundError as e:
            self._cleanup(binp, jsonp)
            raise QuarantineError(_GONE) from e
        except OSError as e:
            self._cleanup(binp, jsonp)
            raise QuarantineError(
                "O arquivo está em uso; feche o programa que o usa e tente de novo."
            ) from e
        return qid

    @staticmethod
    def _remove_original(original: Path) -> None:
        try:
            os.remove(original)
            return
        except PermissionError:
            # Somente-leitura no Windows: tira o atributo, tenta de novo e, se
            # ainda falhar, devolve o modo original (o arquivo nunca se perde).
            mode = stat.S_IMODE(os.stat(original).st_mode)
            os.chmod(original, mode | stat.S_IWRITE)
            try:
                os.remove(original)
            except OSError:
                try:
                    os.chmod(original, mode)
                except OSError:
                    pass
                raise

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
        except (OSError, ValueError) as e:
            raise QuarantineError("Item não encontrado na quarentena.") from e
        if not _valid_meta(meta):
            raise QuarantineError("Os dados do item de quarentena estão corrompidos.")
        return meta

    def items(self) -> list[dict]:
        out: list[dict] = []
        if not self._base.is_dir():
            return out
        for p in self._base.glob("*.json"):
            if not _ID_RE.fullmatch(p.stem):
                continue
            try:
                m = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not _valid_meta(m):
                continue
            m["id"] = p.stem
            regras = m.get("regras")
            if not (isinstance(regras, list) and all(isinstance(r, str) for r in regras)):
                regras = []
            m["regras"] = regras
            if not isinstance(m.get("severidade"), str):
                m["severidade"] = ""
            out.append(m)
        out.sort(key=lambda m: m["data"], reverse=True)
        return out

    def restore(self, qid: str) -> Path:
        binp, jsonp = self._paths(qid)
        meta = self._meta(qid)
        try:
            ok = _sha_scrambled(binp) == meta["sha256"]
        except OSError as e:
            raise QuarantineError(f"Não foi possível ler o item da quarentena: {e}") from e
        if not ok:
            raise QuarantineError(
                "O arquivo em quarentena foi alterado e não será restaurado.")

        orig = Path(meta["caminho_original"])
        dest, n = orig, 1
        while dest.exists():
            suf = " (restaurado)" if n == 1 else f" (restaurado {n})"
            dest = orig.with_name(orig.stem + suf + orig.suffix)
            n += 1
        created = False
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            while True:
                try:
                    out = open(dest, "xb")
                    created = True
                    break
                except FileExistsError:  # corrida: outro processo criou o nome
                    suf = f" (restaurado {n})"
                    dest = orig.with_name(orig.stem + suf + orig.suffix)
                    n += 1
            with out, open(binp, "rb") as src:
                off = 0
                while chunk := src.read(CHUNK):
                    out.write(_xor(chunk, off))
                    off += len(chunk)
                out.flush()
                os.fsync(out.fileno())
            if _sha_plain(dest) != meta["sha256"]:
                raise OSError("a cópia restaurada não confere")
        except (OSError, MemoryError) as e:
            if created:
                self._cleanup(dest)  # destino parcial; a quarentena fica intacta
            raise QuarantineError(f"Não foi possível restaurar o arquivo: {e}") from e
        zone = meta.get("zone_identifier")
        if isinstance(zone, str):
            _write_zone(dest, zone)
        self._cleanup(binp, jsonp)
        return dest

    def delete(self, qid: str) -> None:
        binp, jsonp = self._paths(qid)
        try:
            for p in (binp, jsonp):
                if p.exists():
                    shred_file(p)
        except (ShredError, OSError) as e:
            raise QuarantineError(f"Não foi possível apagar o item: {e}") from e
