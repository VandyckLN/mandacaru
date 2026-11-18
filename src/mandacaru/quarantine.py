"""Quarentena de arquivos: isola sem nunca deixar o arquivo existir so pela metade."""
from __future__ import annotations

import dataclasses
import errno
import grp
import hashlib
import json
import os
import re
import stat
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass

from mandacaru.decisions import DecisionLog
from mandacaru.events import Alert

DEFAULT_DIR = "/var/lib/mandacaru/quarantine"
XOR_KEY = 0xA5
GROUP = "mandacaru"
BLOCK = 1024 * 1024
_ID_RE = re.compile(r"[0-9a-f]{32}")


class CaseNotFound(LookupError):
    pass


class Tampered(RuntimeError):
    pass


def validate_id(case_id: str) -> str:
    if not isinstance(case_id, str) or not _ID_RE.fullmatch(case_id):
        raise CaseNotFound(f"id invalido: {case_id!r}")
    return case_id


@dataclass
class Case:
    id: str
    sha256: str
    size: int
    original_path: str
    uid: int
    gid: int
    mode: int
    mtime: float
    rule: str
    severity: str
    summary: str
    quarantined_at: float
    expires_at: float
    state: str = "isolado"
    original_removido: bool = True
    analysis: dict | None = None

    def to_json(self) -> str:
        d = {"v": 1, **dataclasses.asdict(self)}
        return json.dumps(d, ensure_ascii=True)

    @classmethod
    def from_json(cls, text: str) -> Case:
        d = json.loads(text)
        names = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in names})


@dataclass
class IsolateResult:
    status: str  # "isolado" | "nao_isolado" | "confiavel"
    case: Case | None = None
    reason: str | None = None


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


class UnsafePath(OSError):
    """Algum componente do caminho e um symlink."""


class LimitExceeded(Exception):
    """A entrada passou do limite de bytes dado a xor_stream."""


def open_parent_dir(path: str) -> tuple[int, str]:
    """Abre o diretorio pai de `path` componente a componente, a partir de "/", sem seguir symlinks.

    Devolve (fd do diretorio pai, nome final); o chamador fecha o fd. Levanta UnsafePath se algum componente
    do diretorio for symlink. O nome final NAO e aberto aqui (o chamador usa dir_fd=fd com O_NOFOLLOW).
    """
    path = os.path.abspath(os.fsdecode(path))
    parts = [c for c in path.split("/") if c]
    if not parts:
        raise OSError(errno.EINVAL, "caminho sem nome de arquivo")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for comp in parts[:-1]:
            try:
                nxt = os.open(comp, flags, dir_fd=fd)
            except OSError as e:
                if e.errno in (errno.ELOOP, errno.ENOTDIR):
                    try:
                        is_link = stat.S_ISLNK(os.stat(comp, dir_fd=fd, follow_symlinks=False).st_mode)
                    except OSError:
                        is_link = False
                    if is_link:
                        raise UnsafePath(errno.ELOOP, "caminho com symlink", comp) from None
                raise
            os.close(fd)
            fd = nxt
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def xor_stream(src: int, dst: int, key: int = XOR_KEY, limit: int | None = None) -> str:
    """Copia src -> dst (descritores) aplicando XOR byte a byte; devolve o sha256 hex do conteudo de entrada.

    Com `limit`, levanta LimitExceeded assim que mais de `limit` bytes forem lidos."""
    h = hashlib.sha256()
    table = bytes(b ^ key for b in range(256))
    total = 0
    while True:
        block = os.read(src, BLOCK)
        if not block:
            break
        total += len(block)
        if limit is not None and total > limit:
            raise LimitExceeded()
        h.update(block)
        _write_all(dst, block.translate(table))
    return h.hexdigest()


def _unlink_quiet(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _reason(e: OSError) -> str:
    return e.strerror or str(e)


class Quarantine:
    def __init__(self, root: str | os.PathLike = DEFAULT_DIR, log: DecisionLog | None = None,
                 trust: object | None = None,  # Task 4 troca por TrustList | None
                 retention_days: int = 30, max_file_bytes: int = 256 * 1024 * 1024,
                 max_total_bytes: int = 2 * 1024 * 1024 * 1024, now: Callable[[], float] = time.time):
        self.root = os.fspath(root)
        self.log = log
        self.trust = trust
        self.retention_days = retention_days
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.now = now

    # --- consulta ---
    def _p(self, case_id: str, ext: str) -> str:
        return os.path.join(self.root, case_id + ext)

    def load(self, case_id: str) -> Case:
        validate_id(case_id)
        try:
            with open(self._p(case_id, ".json"), encoding="utf-8") as fh:
                text = fh.read()
        except FileNotFoundError:
            raise CaseNotFound(case_id) from None
        try:
            case = Case.from_json(text)
        except (ValueError, TypeError) as e:
            raise Tampered(f"metadados invalidos em {case_id}") from e
        if case.id != case_id:
            raise Tampered(f"id nao confere em {case_id}")
        return case

    def list(self) -> list[Case]:
        cases = []
        try:
            names = os.listdir(self.root)
        except OSError:
            return []
        for name in names:
            if name.endswith(".json") and _ID_RE.fullmatch(name[:-5]):
                try:
                    cases.append(self.load(name[:-5]))
                except (CaseNotFound, Tampered, OSError):
                    continue
        return sorted(cases, key=lambda c: c.quarantined_at)

    def used_bytes(self) -> int:
        total = 0
        try:
            names = os.listdir(self.root)
        except OSError:
            return 0
        for name in names:
            if name.endswith((".bin", ".bin.tmp")):
                try:
                    total += os.stat(os.path.join(self.root, name)).st_size
                except OSError:
                    pass
        return total

    # --- isolamento ---
    def _record(self, action: str, **kw) -> None:
        if self.log is None:
            return
        try:
            self.log.record(action, **kw)
        except (OSError, ValueError):
            pass  # o log nunca derruba o isolamento

    def _fail(self, path: str, alert: Alert, reason: str, sha256: str | None = None) -> IsolateResult:
        self._record("nao_isolado", sha256=sha256, path=path, detail={"motivo": reason})
        return IsolateResult("nao_isolado", reason=reason)

    def _write_json(self, case: Case) -> None:
        """Grava <id>.json via temporario + rename (0640; grupo mandacaru se der)."""
        final = self._p(case.id, ".json")
        tmp = final + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        try:
            try:
                os.fchmod(fd, 0o640)
                if os.geteuid() == 0:
                    try:
                        os.fchown(fd, -1, grp.getgrnam(GROUP).gr_gid)
                    except KeyError:
                        pass
                _write_all(fd, case.to_json().encode("ascii"))
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(tmp, final)
        except BaseException:
            _unlink_quiet(tmp)
            raise

    def isolate(self, path: str, alert: Alert) -> IsolateResult:
        try:
            return self._isolate(path, alert)
        except Exception as e:  # nunca levanta para o chamador
            return self._fail(path, alert, _reason(e) if isinstance(e, OSError) else repr(e))

    def _fsync_dir(self) -> None:
        dfd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    def _isolate(self, path: str, alert: Alert) -> IsolateResult:
        try:
            pfd, name = open_parent_dir(path)
        except UnsafePath:
            return self._fail(path, alert, "caminho_com_symlink")
        except FileNotFoundError:
            return self._fail(path, alert, "sumiu")
        try:
            return self._isolate_in(pfd, name, path, alert)
        finally:
            os.close(pfd)

    def _isolate_in(self, pfd: int, name: str, path: str, alert: Alert) -> IsolateResult:
        try:
            src = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pfd)
        except FileNotFoundError:
            return self._fail(path, alert, "sumiu")
        except OSError as e:
            if e.errno in (errno.ELOOP, errno.ENXIO):
                return self._fail(path, alert, "nao_regular")
            return self._fail(path, alert, _reason(e))
        case_id = uuid.uuid4().hex
        bin_tmp, bin_final = self._p(case_id, ".bin.tmp"), self._p(case_id, ".bin")
        json_final = self._p(case_id, ".json")
        try:
            st = os.fstat(src)
            if not stat.S_ISREG(st.st_mode):
                return self._fail(path, alert, "nao_regular")
            room = self.max_total_bytes - self.used_bytes()
            if st.st_size > self.max_file_bytes:
                return self._fail(path, alert, "tamanho")
            if st.st_size > room:
                return self._fail(path, alert, "quarentena_cheia")
            limit = min(self.max_file_bytes, room)
            limit_reason = "tamanho" if self.max_file_bytes <= room else "quarentena_cheia"
            try:
                # 2. copia embaralhada + fsync
                dst = os.open(bin_tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    os.fchmod(dst, 0o600)
                    digest = xor_stream(src, dst, limit=limit)
                    copied = os.lseek(dst, 0, os.SEEK_CUR)
                    os.fsync(dst)
                finally:
                    os.close(dst)
                now = self.now()
                case = Case(
                    id=case_id, sha256=digest, size=copied, original_path=path, uid=st.st_uid,
                    gid=st.st_gid, mode=st.st_mode, mtime=st.st_mtime, rule=alert.rule,
                    severity=alert.severity.name, summary=alert.summary, quarantined_at=now,
                    expires_at=now + self.retention_days * 86400)
                # 3. metadados, 4. bin definitivo + fsync do diretorio
                self._write_json(case)
                os.rename(bin_tmp, bin_final)
                self._fsync_dir()
            except BaseException as e:
                for p in (bin_tmp, bin_final, json_final, json_final + ".tmp"):
                    _unlink_quiet(p)
                if isinstance(e, LimitExceeded):
                    return self._fail(path, alert, limit_reason)
                if isinstance(e, OSError):
                    return self._fail(path, alert, _reason(e))
                raise
        finally:
            os.close(src)
        # 5. so agora remove o original, por nome relativo ao diretorio ja aberto (e so se for o mesmo arquivo)
        stale = False
        try:
            cur = os.stat(name, dir_fd=pfd, follow_symlinks=False)
            if (cur.st_dev, cur.st_ino) != (st.st_dev, st.st_ino):
                raise OSError(errno.ESTALE, "arquivo original foi substituido")
            os.unlink(name, dir_fd=pfd)
        except OSError:
            case.original_removido = False
            try:
                self._write_json(case)
                self._fsync_dir()
            except OSError:
                stale = True
        detail = {"rule": case.rule, "severity": case.severity, "original_removido": case.original_removido}
        if stale:
            detail["metadados_desatualizados"] = True
        self._record("isolar", case_id=case.id, sha256=case.sha256, path=path, detail=detail)
        return IsolateResult("isolado", case=case)
