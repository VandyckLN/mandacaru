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
DEFAULT_TRUST = "/var/lib/mandacaru/trusted.json"
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


class LogNotRecorded(Exception):
    """A acao foi aplicada, mas a linha do log de decisoes nao foi gravada (so com strict_log)."""

    def __init__(self, cause: Exception):
        super().__init__(getattr(cause, "strerror", None) or str(cause))
        self.cause = cause


class UnsafePath(OSError):
    """Algum componente do caminho e um symlink."""


class LimitExceeded(Exception):
    """A entrada passou do limite de bytes dado a xor_stream."""


class _StillWriting(Exception):
    """O original mudou enquanto era copiado."""


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


def xor_stream(src: int, dst: int, key: int = XOR_KEY, limit: int | None = None,
               hash_output: bool = False) -> str:
    """Copia src -> dst (descritores) aplicando XOR byte a byte; devolve o sha256 hex do conteudo de entrada
    (ou do de saida com `hash_output=True`, usado ao desembaralhar).

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
        out = block.translate(table)
        h.update(out if hash_output else block)
        _write_all(dst, out)
    return h.hexdigest()


def _hash_fd(fd: int, limit: int) -> str:
    """sha256 hex do que resta ler em `fd`; LimitExceeded se passar de `limit` bytes."""
    h = hashlib.sha256()
    total = 0
    while True:
        block = os.read(fd, BLOCK)
        if not block:
            return h.hexdigest()
        total += len(block)
        if total > limit:
            raise LimitExceeded()
        h.update(block)


class TrustList:
    """Hashes que o usuario mandou confiar. Arquivo ausente ou corrompido = lista vazia."""

    def __init__(self, path: str | os.PathLike = DEFAULT_TRUST, recheck_seconds: float = 5.0,
                 now: Callable[[], float] = time.monotonic):
        self.path = os.fspath(path)
        self.recheck_seconds = recheck_seconds
        self.now = now
        self._sig: tuple | None = None
        self._hashes: set[str] = set()
        self._checked: float | None = None

    def _read(self) -> list[dict]:
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return []
        if not isinstance(data, list):
            return []
        return [e for e in data if isinstance(e, dict) and isinstance(e.get("sha256"), str)]

    def _refresh(self, force: bool = False) -> None:
        t = self.now()
        if not force and self._checked is not None and t - self._checked < self.recheck_seconds:
            return
        self._checked = t
        try:
            st = os.stat(self.path)
            sig: tuple | None = (st.st_mtime_ns, st.st_size, st.st_ino)
        except OSError:
            sig = None
        if sig != self._sig or sig is None:
            self._sig = sig
            self._hashes = {e["sha256"] for e in self._read()} if sig else set()

    def contains(self, sha256: str) -> bool:
        self._refresh()
        if sha256 in self._hashes:
            return True
        # falta no cache: confere o arquivo agora (so roda em deteccao HIGH), senao um "confiar" de menos de
        # `recheck_seconds` atras passaria despercebido e o servico isolaria o arquivo restaurado
        self._refresh(force=True)
        return sha256 in self._hashes

    def _save(self, entries: list[dict]) -> None:
        tmp = f"{self.path}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        try:
            try:
                os.fchmod(fd, 0o644)
                _write_all(fd, json.dumps(entries, ensure_ascii=True, indent=1).encode("ascii"))
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(tmp, self.path)
        except BaseException:
            _unlink_quiet(tmp)
            raise
        self._checked = None  # forca reler na proxima consulta

    def add(self, sha256: str, original_path: str, by: str) -> bool:
        """Poe o hash na lista; devolve True so se ele ainda nao estava no arquivo."""
        entries = self._read()
        if any(e["sha256"] == sha256 for e in entries):
            return False
        entries.append({"sha256": sha256, "added_at": time.time(), "original_path": original_path, "by": by})
        self._save(entries)
        return True

    def remove(self, sha256: str) -> bool:
        entries = self._read()
        kept = [e for e in entries if e["sha256"] != sha256]
        if len(kept) == len(entries):
            return False
        self._save(kept)
        return True


def _unlink_quiet(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _reason(e: OSError) -> str:
    return e.strerror or str(e)


class Quarantine:
    def __init__(self, root: str | os.PathLike = DEFAULT_DIR, log: DecisionLog | None = None,
                 trust: TrustList | None = None,
                 retention_days: int = 30, max_file_bytes: int = 256 * 1024 * 1024,
                 max_total_bytes: int = 2 * 1024 * 1024 * 1024, now: Callable[[], float] = time.time,
                 strict_log: bool = False):
        self.root = os.fspath(root)
        self.log = log
        self.trust = trust
        self.retention_days = retention_days
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.now = now
        # o monitor nunca para por causa do log; a CLI de decisoes (strict_log=True) nao decide sem registrar
        self.strict_log = strict_log

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
    def _record(self, action: str, strict: bool | None = None, **kw) -> None:
        if self.log is None:
            return
        try:
            self.log.record(action, **kw)
        except (OSError, ValueError) as e:
            if self.strict_log if strict is None else strict:
                raise LogNotRecorded(e) from e
            # sem strict_log o log nunca derruba o isolamento

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
                if self.trust is not None:
                    sha = _hash_fd(src, limit)
                    os.lseek(src, 0, os.SEEK_SET)
                    if self.trust.contains(sha):
                        self._record("ignorado_confiavel", sha256=sha, path=path)
                        return IsolateResult("confiavel")
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
                # quem ainda esta escrevendo (cp, curl, unzip, editor) continuaria num inode orfao e a copia
                # ficaria pela metade: so remove o original se ele nao mudou desde o primeiro fstat
                fin = os.fstat(src)
                if copied != st.st_size or ((fin.st_size, fin.st_mtime_ns, fin.st_ctime_ns)
                                            != (st.st_size, st.st_mtime_ns, st.st_ctime_ns)):
                    raise _StillWriting()
            except BaseException as e:
                for p in (bin_tmp, bin_final, json_final, json_final + ".tmp"):
                    _unlink_quiet(p)
                if isinstance(e, _StillWriting):
                    try:
                        self._fsync_dir()
                    except OSError:
                        pass
                    return self._fail(path, alert, "em_escrita")  # o proximo file_write tenta de novo
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

    # --- restauracao ("Confio") ---
    def restore(self, case_id: str, by: str, uid: int | None) -> str:
        """Devolve o arquivo ao lugar (ou a <nome>.restaurado-<data>) e poe o hash na lista de confianca."""
        case = self.load(case_id)
        try:
            pfd, name = open_parent_dir(case.original_path)
        except UnsafePath:
            self._refuse(case, by, uid, "caminho_com_symlink")
            raise
        except FileNotFoundError:
            self._refuse(case, by, uid, "diretorio_ausente")
            raise FileNotFoundError(
                errno.ENOENT, f"o diretorio original nao existe mais: {os.path.dirname(case.original_path)}") from None
        try:
            final = self._restore_in(pfd, name, case, by, uid)
        finally:
            os.close(pfd)
        for ext in (".bin", ".json"):
            _unlink_quiet(self._p(case.id, ext))
        try:
            self._fsync_dir()
        except OSError:
            pass
        dest = os.path.join(os.path.dirname(case.original_path), final)
        self._record("confiar", case_id=case.id, sha256=case.sha256, path=case.original_path, by=by, uid=uid,
                     detail={"restaurado_em": dest})
        return dest

    def _refuse(self, case: Case, by: str, uid: int | None, motivo: str) -> None:
        # a recusa nao e a decisao: falha do log aqui nao pode esconder o motivo real
        self._record("restauracao_recusada", strict=False, case_id=case.id, sha256=case.sha256, path=case.original_path,
                     by=by, uid=uid, detail={"motivo": motivo})

    def _restore_in(self, pfd: int, name: str, case: Case, by: str, uid: int | None) -> str:
        tmpname = f".mandacaru-restore-{uuid.uuid4().hex}"
        try:
            src = os.open(self._p(case.id, ".bin"), os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            self._refuse(case, by, uid, "bin_ausente")
            raise Tampered(f"arquivo isolado ausente em {case.id}") from None
        added = refused = False
        try:
            # o hash entra na lista ANTES de o conteudo aparecer na pasta vigiada: o monitor ve o temporario
            # (create/write) e o isolaria, levando junto a restauracao
            if self.trust is not None:
                added = self.trust.add(case.sha256, case.original_path, by)
            fd = os.open(tmpname, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=pfd)
            try:
                try:
                    digest = xor_stream(src, fd, hash_output=True)
                    if digest != case.sha256:
                        self._refuse(case, by, uid, "hash_diferente")
                        refused = True
                        raise Tampered(f"conteudo adulterado em {case.id}")
                    if os.geteuid() == 0:
                        os.fchown(fd, case.uid, case.gid)
                    os.fchmod(fd, stat.S_IMODE(case.mode))
                    os.utime(fd, (case.mtime, case.mtime))
                    os.fsync(fd)
                finally:
                    os.close(fd)
                final = name
                try:
                    os.link(tmpname, final, src_dir_fd=pfd, dst_dir_fd=pfd, follow_symlinks=False)
                except FileExistsError:
                    final = f"{name}.restaurado-{time.strftime('%Y-%m-%d', time.gmtime(self.now()))}"
                    try:
                        os.link(tmpname, final, src_dir_fd=pfd, dst_dir_fd=pfd, follow_symlinks=False)
                    except FileExistsError:
                        self._refuse(case, by, uid, "destino_existe")
                        refused = True
                        raise
                try:
                    # o novo nome tem de estar no disco antes de apagar o .bin (senao um crash perde o arquivo)
                    os.fsync(pfd)
                except OSError:
                    try:
                        os.unlink(final, dir_fd=pfd)
                    except OSError:
                        pass
                    raise
                return final
            finally:
                try:
                    os.unlink(tmpname, dir_fd=pfd)
                except OSError:
                    pass
        except BaseException as e:
            if added:
                try:
                    self.trust.remove(case.sha256)
                except OSError:
                    pass
            if isinstance(e, OSError) and not refused:
                self._refuse(case, by, uid, _reason(e))
            raise
        finally:
            os.close(src)

    # --- manter, apagar, expirar ---
    def keep(self, case_id: str, by: str, uid: int | None) -> Case:
        """Registra a decisao de manter; o prazo de expiracao nao muda."""
        case = self.load(case_id)
        self._record("manter", case_id=case.id, sha256=case.sha256, path=case.original_path, by=by, uid=uid)
        return case

    def delete(self, case_id: str, by: str, uid: int | None, action: str = "apagar") -> None:
        case = self.load(case_id)
        for ext in (".bin", ".json"):
            try:
                os.unlink(self._p(case.id, ext))
            except FileNotFoundError:
                pass
        self._fsync_dir()
        self._record(action, case_id=case.id, sha256=case.sha256, path=case.original_path, by=by, uid=uid)

    def read_original(self, case_id: str, max_bytes: int | None = None) -> bytes:
        """Conteudo original desembaralhado, so em memoria; confere o sha256 (diferente = Tampered)."""
        case = self.load(case_id)
        try:
            fd = os.open(self._p(case.id, ".bin"), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            raise Tampered(f"arquivo isolado ausente em {case.id}") from None
        try:
            size = os.fstat(fd).st_size
            if max_bytes is not None and size > max_bytes:
                raise ValueError(f"arquivo isolado maior que o limite de {max_bytes} bytes")
            chunks = []
            while True:
                block = os.read(fd, BLOCK)
                if not block:
                    break
                chunks.append(block)
        finally:
            os.close(fd)
        data = b"".join(chunks).translate(bytes(b ^ XOR_KEY for b in range(256)))
        if max_bytes is not None and len(data) > max_bytes:
            raise ValueError(f"arquivo isolado maior que o limite de {max_bytes} bytes")
        if hashlib.sha256(data).hexdigest() != case.sha256:
            raise Tampered(f"conteudo adulterado em {case.id}")
        return data

    def set_analysis(self, case_id: str, analysis: dict) -> Case:
        case = self.load(case_id)
        case.analysis = analysis
        self._write_json(case)
        self._fsync_dir()
        return case

    def purge_expired(self) -> int:
        """Apaga os casos vencidos e os orfaos; nunca levanta por causa de uma entrada ruim."""
        now = self.now()
        removed = 0
        for case in self.list():  # list() ja pula os .json ilegiveis
            if case.expires_at > now:
                continue
            try:
                self.delete(case.id, "sistema", None, action="expirado")
            except LogNotRecorded:
                raise
            except Exception:
                continue
            removed += 1
        try:
            names = os.listdir(self.root)
        except OSError:
            return removed
        present = set(names)
        for name in names:
            orphan_bin = name.endswith(".bin") and _ID_RE.fullmatch(name[:-4]) and name[:-4] + ".json" not in present
            stale_tmp = False
            if name.endswith(".tmp"):
                try:
                    stale_tmp = now - os.stat(os.path.join(self.root, name)).st_mtime > 3600
                except OSError:
                    pass
            if orphan_bin or stale_tmp:
                _unlink_quiet(os.path.join(self.root, name))
        return removed
