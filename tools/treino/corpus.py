"""Corpus de amostras em zips AES (senha "infected"), lidos so em memoria.

Nada e extraido no disco: cada amostra vive dentro do zip original (malicioso) ou de um zip criado em memoria
(legitimo). O manifesto e um JSONL so de append; o teto de disco conta o tamanho DESCOMPRIMIDO de cada amostra,
um limite superior que nao depende de quanto o zip comprime.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import sys
import uuid
from dataclasses import asdict, dataclass, fields
from pathlib import Path

import pyzipper

SENHA = b"infected"
MAX_BYTES = 8 * 1024 * 1024            # igual ao runtime: so amostras com len < MAX_BYTES
MAX_ZIP_BYTES = MAX_BYTES + 1024 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MANIFESTO = "manifesto.jsonl"


def _aviso(msg: str) -> None:
    print(f"aviso: {msg}", file=sys.stderr)


@dataclass(frozen=True)
class Entry:
    sha256: str
    label: int
    source: str
    family: str
    first_seen: str
    reporter: str
    categoria: str
    package: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.sha256, str) or not _SHA256_RE.fullmatch(self.sha256):
            raise ValueError(f"sha256 invalido: {self.sha256!r}")
        if self.label not in (0, 1):
            raise ValueError(f"label invalido: {self.label!r}")


_ENTRY_FIELDS = {f.name for f in fields(Entry)}


def _member(zf: pyzipper.AESZipFile) -> pyzipper.ZipInfo:
    infos = zf.infolist()
    if len(infos) != 1:
        raise ValueError(f"zip com {len(infos)} membros (esperava 1)")
    info = infos[0]
    if info.is_dir() or stat.S_ISLNK(info.external_attr >> 16):
        raise ValueError("membro e diretorio ou symlink")
    if info.file_size >= MAX_BYTES:
        raise ValueError(f"membro declarado com {info.file_size} bytes (limite {MAX_BYTES})")
    return info


def _read_zip(raw: bytes) -> bytes:
    """Le o unico membro de um zip AES em memoria, com todas as validacoes."""
    if len(raw) > MAX_ZIP_BYTES:
        raise ValueError(f"zip com {len(raw)} bytes (limite {MAX_ZIP_BYTES})")
    with pyzipper.AESZipFile(io.BytesIO(raw)) as zf:
        zf.setpassword(SENHA)
        info = _member(zf)
        with zf.open(info) as fh:
            data = fh.read(MAX_BYTES)
    if len(data) >= MAX_BYTES:
        raise ValueError("leitura chegou ao limite de tamanho")
    return data


class Corpus:
    def __init__(self, root: Path, *, max_disk_bytes: int | None = 20 * 1024**3) -> None:
        self.root = Path(root)
        self.max_disk_bytes = max_disk_bytes
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        for sub in ("malicioso", "legitimo"):
            (self.root / sub).mkdir(mode=0o700, exist_ok=True)
        self._entries: list[Entry] = []
        self._hashes: set[str] = set()
        self._disk_bytes = 0
        self._load()

    def _load(self) -> None:
        path = self.root / _MANIFESTO
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return
        for n, line in enumerate(lines, 1):
            try:
                d = json.loads(line)
                entry = Entry(**{k: v for k, v in d.items() if k in _ENTRY_FIELDS})
                size = int(d.get("bytes", 0))
            except (ValueError, TypeError) as exc:
                _aviso(f"{path.name}:{n}: linha ignorada ({exc})")
                continue
            if entry.sha256 in self._hashes:
                continue
            self._entries.append(entry)
            self._hashes.add(entry.sha256)
            self._disk_bytes += size

    def has(self, sha256: str) -> bool:
        return sha256 in self._hashes

    def disk_usage_bytes(self) -> int:
        return self._disk_bytes

    def entries(self) -> list[Entry]:
        return list(self._entries)

    def _path(self, entry: Entry) -> Path:
        return self.root / ("malicioso" if entry.label == 1 else "legitimo") / f"{entry.sha256}.zip"

    def _fits(self, size: int) -> bool:
        return self.max_disk_bytes is None or self._disk_bytes + size <= self.max_disk_bytes

    def _store(self, entry: Entry, zip_bytes: bytes, size: int) -> None:
        final = self._path(entry)
        tmp = final.with_name(f".{final.name}.{uuid.uuid4().hex[:8]}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            try:
                view = memoryview(zip_bytes)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, final)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        line = (json.dumps({**asdict(entry), "bytes": size}, ensure_ascii=True) + "\n").encode("ascii")
        mfd = os.open(self.root / _MANIFESTO, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            os.write(mfd, line)
        finally:
            os.close(mfd)
        self._entries.append(entry)
        self._hashes.add(entry.sha256)
        self._disk_bytes += size

    def add_zip(self, entry: Entry, zip_bytes: bytes) -> bool:
        """Zip AES pronto (como vem do MalwareBazaar). False se invalido, duplicado, hash diferente ou sem espaco."""
        if self.has(entry.sha256):
            return False
        try:
            data = _read_zip(zip_bytes)
        except Exception as exc:  # noqa: BLE001 - zip hostil: qualquer erro so pula a amostra
            _aviso(f"{entry.sha256[:16]}: zip recusado ({exc})")
            return False
        if hashlib.sha256(data).hexdigest() != entry.sha256:
            _aviso(f"{entry.sha256[:16]}: sha256 do conteudo nao bate")
            return False
        if not self._fits(len(data)):
            _aviso(f"{entry.sha256[:16]}: teto de disco do corpus atingido")
            return False
        self._store(entry, zip_bytes, len(data))
        return True

    def add_bytes(self, entry: Entry, data: bytes) -> bool:
        """Legitimo: cria o zip AES em memoria (deflate nivel 1) e grava so o zip."""
        if self.has(entry.sha256) or len(data) >= MAX_BYTES:
            return False
        if hashlib.sha256(data).hexdigest() != entry.sha256 or not self._fits(len(data)):
            return False
        buf = io.BytesIO()
        with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, compresslevel=1,
                                 encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(SENHA)
            zf.writestr(entry.sha256, data)
        self._store(entry, buf.getvalue(), len(data))
        return True

    def read(self, entry: Entry) -> bytes | None:
        path = self._path(entry)
        try:
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                raise ValueError("nao e arquivo regular")
            if st.st_size > MAX_ZIP_BYTES:
                raise ValueError(f"zip com {st.st_size} bytes (limite {MAX_ZIP_BYTES})")
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as fh:
                raw = fh.read(MAX_ZIP_BYTES + 1)
            return _read_zip(raw)
        except Exception as exc:  # noqa: BLE001 - corrompido, senha errada, symlink, tamanho: so pula
            _aviso(f"{entry.sha256[:16]}: amostra ilegivel ({exc})")
            return None
