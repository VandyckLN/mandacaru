"""Neutralizar: achar e remover a persistência do usuário ligada ao incidente, com Desfazer.

Só entra o que menciona um caminho/pasta do incidente ou tem o SHA-256 dele; programas legítimos
do usuário nunca são listados. Antes de remover, `backup()` guarda o estado completo (o chamador
grava no incidente) e `remover()` confere que nada mudou desde então. `restaurar()` nunca
sobrescreve o que já estiver no lugar.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import csv
import hashlib
import io
import ntpath
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from mandacaru.projeto.achado import exibivel
from mandacaru_win.incident import IncidentError, sha256_arquivo

CHAVE_RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
CHAVE_RUNONCE = CHAVE_RUN + "Once"
REG_SZ, REG_EXPAND_SZ = 1, 2
_CHAVES = {"hkcu_run": CHAVE_RUN, "hkcu_runonce": CHAVE_RUNONCE}
LIMITE_INICIALIZAR = 1024 * 1024
_CHAVE_XOR = b"mandacaru-incidente"
_FRONTEIRA = re.compile(r"[0-9a-z_.\-]")

_MUDOU = "A entrada mudou desde a detecção; nada foi removido."
_EXISTE = "Já existe outra entrada com esse nome; nada foi alterado."
_ADULTERADO = "O backup desta ação está inválido ou foi alterado; nada foi restaurado."
_GRANDE = "Arquivo grande demais para guardar no incidente; use a Quarentena."

Executor = Callable[[list[str], float], tuple[int, str]]
AGENDADOR = "Agendador de Tarefas"
# Colunas de `schtasks /Query /FO CSV /V /NH`: a posição não muda com o idioma do Windows.
_COL_NOME, _COL_EXECUTAR, _COL_COMO = 1, 8, 14
_TIMEOUT = 60.0


def _run_oem(args: list[str], timeout: float) -> tuple[int, str]:
    """Executa sem shell e sem janela; a saída do schtasks vem na página de código OEM do console."""
    p = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, check=False,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        enc = codecs.lookup("oem").name
    except LookupError:
        enc = "utf-8"
    saida = p.stdout if p.returncode == 0 else p.stdout + p.stderr
    return p.returncode, saida.decode(enc, errors="replace")


def _schtasks() -> str:
    raiz = os.environ.get("SystemRoot") or r"C:\Windows"
    return ntpath.join(raiz, "System32", "schtasks.exe")


def _nome_tarefa_valido(nome: object) -> bool:
    return (isinstance(nome, str) and nome.startswith("\\") and 1 < len(nome) <= 260
            and not any(c == '"' or ord(c) < 32 for c in nome))


@dataclass(frozen=True)
class Entrada:
    tipo: str  # hkcu_run | hkcu_runonce | startup_user | schtask_user | schtask_sistema
    local: str  # chave do registro, pasta Inicializar ou "Agendador de Tarefas"
    nome: str
    comando: str
    sha256: str | None = None
    exige_servico: bool = False  # só a Proteção avançada (marco d) pode remover


class Registro(Protocol):
    def valores(self, chave: str) -> list[tuple[str, object, int]]: ...
    def apagar(self, chave: str, nome: str) -> None: ...
    def gravar(self, chave: str, nome: str, valor: str, tipo_reg: int) -> None: ...


def _norm(s: str) -> str:
    return ntpath.expandvars(s).replace("/", "\\").casefold()


def menciona(texto: str, alvo: str) -> bool:
    """`texto` cita o caminho `alvo` inteiro (C:\\proj casa C:\\proj\\x.js, mas não C:\\projeto)."""
    a = _norm(alvo).rstrip("\\")
    if not a:
        return False
    t = _norm(texto)
    i = t.find(a)
    while i >= 0:
        fim = i + len(a)
        if fim == len(t) or not _FRONTEIRA.match(t[fim]):
            return True
        i = t.find(a, i + 1)
    return False


def _embaralhar(dados: bytes) -> bytes:
    # Para o backup no JSON não virar uma cópia "viva" do arquivo malicioso (o Defender apagaria o registro).
    k = _CHAVE_XOR
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(dados))


def _textos(dados: bytes) -> str:
    """O que um atalho/script cita: ANSI e UTF-16 (nas duas posições possíveis do .lnk)."""
    return "\n".join((dados.decode("latin-1"), dados.decode("utf-16-le", "ignore"),
                      dados[1:].decode("utf-16-le", "ignore")))


def _nome_seguro(nome: object) -> bool:
    return (isinstance(nome, str) and nome not in ("", ".", "..")
            and not any(c in nome for c in '\\/:\0') and nome == nome.strip())


def _remover_arquivo(f: Path) -> None:
    try:
        os.remove(f)
    except PermissionError:
        os.chmod(f, stat.S_IMODE(os.lstat(f).st_mode) | stat.S_IWRITE)  # somente leitura no Windows
        os.remove(f)


class Persistencia:
    def __init__(self, *, registro: Registro | None = None, pasta_inicializar: Path | None = None,
                 run: Executor | None = None, usuario: str | None = None):
        if registro is None and sys.platform == "win32":
            registro = RegistroWindows()
        if pasta_inicializar is None and os.environ.get("APPDATA"):
            pasta_inicializar = (Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu"
                                 / "Programs" / "Startup")
        if run is None and sys.platform == "win32":
            run = _run_oem
        self._registro = registro
        self._pasta = Path(pasta_inicializar) if pasta_inicializar is not None else None
        self._run = run
        self._usuario = usuario if usuario is not None else os.environ.get("USERNAME", "")

    # ---------- detectar ----------
    def detectar(self, alvos: Iterable[str], hashes: Iterable[str] = frozenset()) -> list[Entrada]:
        alvos = [a for a in alvos if a]
        hashes = set(hashes)
        return [*self._detectar_registro(alvos), *self._detectar_inicializar(alvos, hashes),
                *self._detectar_tarefas(alvos)]

    def _detectar_tarefas(self, alvos: list[str]) -> list[Entrada]:
        if self._run is None or not alvos:
            return []
        try:
            rc, saida = self._run([_schtasks(), "/Query", "/FO", "CSV", "/V", "/NH"], _TIMEOUT)
        except (OSError, subprocess.SubprocessError):
            return []
        if rc != 0:
            return []
        vistas: set[str] = set()
        achadas = []
        for linha in csv.reader(io.StringIO(saida)):
            if len(linha) <= _COL_COMO:
                continue
            nome, comando, como = linha[_COL_NOME], linha[_COL_EXECUTAR], linha[_COL_COMO]
            if nome in vistas or not any(menciona(comando, a) for a in alvos):
                continue
            vistas.add(nome)  # uma linha por gatilho: a mesma tarefa aparece repetida
            do_usuario = bool(self._usuario) and (
                como.rsplit("\\", 1)[-1].casefold() == self._usuario.casefold())
            achadas.append(Entrada("schtask_user" if do_usuario else "schtask_sistema", AGENDADOR, nome,
                                   comando, exige_servico=not do_usuario))
        return achadas

    def _detectar_registro(self, alvos: list[str]) -> list[Entrada]:
        if self._registro is None:
            return []
        saida = []
        for tipo, chave in _CHAVES.items():
            try:
                valores = self._registro.valores(chave)
            except OSError:
                continue
            for nome, valor, _t in valores:
                if isinstance(valor, str) and any(menciona(valor, a) for a in alvos):
                    saida.append(Entrada(tipo, chave, nome, valor))
        return saida

    def _detectar_inicializar(self, alvos: list[str], hashes: set[str]) -> list[Entrada]:
        if self._pasta is None or not self._pasta.is_dir():
            return []
        saida = []
        for f in sorted(self._pasta.iterdir()):
            try:
                if not stat.S_ISREG(os.lstat(f).st_mode):
                    continue
                with open(f, "rb") as fh:
                    inicio = fh.read(LIMITE_INICIALIZAR)
            except OSError:
                continue
            sha = sha256_arquivo(f)
            texto = _textos(inicio)
            if (sha is not None and sha in hashes) or any(menciona(texto, a) for a in alvos):
                saida.append(Entrada("startup_user", str(self._pasta), f.name, str(f), sha))
        return saida

    # ---------- backup / remover ----------
    def backup(self, e: Entrada) -> dict:
        """Estado completo da entrada agora; recusa se já não é o que foi detectado."""
        if e.exige_servico:
            raise IncidentError("Esta entrada só pode ser removida com a Proteção avançada.")
        if e.tipo in _CHAVES:
            atual = self._valor_registro(_CHAVES[e.tipo], e.nome)
            if atual is None or atual[0] != e.comando:
                raise IncidentError(_MUDOU)
            return {"tipo": e.tipo, "chave": _CHAVES[e.tipo], "nome": e.nome,
                    "valor": atual[0], "tipo_reg": atual[1]}
        if e.tipo == "startup_user":
            dados = self._ler_inicializar(e.local, e.nome)
            if hashlib.sha256(dados).hexdigest() != e.sha256:
                raise IncidentError(_MUDOU)
            return {"tipo": e.tipo, "pasta": e.local, "nome": e.nome, "sha256": e.sha256,
                    "conteudo": base64.b64encode(_embaralhar(dados)).decode("ascii")}
        if e.tipo == "schtask_user":
            if not _nome_tarefa_valido(e.nome):
                raise IncidentError(_MUDOU)
            xml = self._xml_tarefa(e.nome)
            if xml is None:
                raise IncidentError(_MUDOU)
            return {"tipo": e.tipo, "nome": e.nome, "xml": xml}
        raise IncidentError(f"Tipo de persistência desconhecido: {e.tipo}")

    def remover(self, backup: dict) -> None:
        tipo = backup.get("tipo")
        if tipo in _CHAVES:
            chave, nome = self._validar_registro(backup)
            atual = self._valor_registro(chave, nome)
            if atual != (backup["valor"], backup["tipo_reg"]):
                raise IncidentError(_MUDOU)
            try:
                self._registro.apagar(chave, nome)
            except OSError as e:
                raise IncidentError(f"Não foi possível remover a entrada: {e}") from e
            return
        if tipo == "startup_user":
            f, _dados = self._validar_inicializar(backup)
            if sha256_arquivo(f) != backup["sha256"]:
                raise IncidentError(_MUDOU)
            try:
                _remover_arquivo(f)
            except OSError as e:
                raise IncidentError(f"Não foi possível remover o arquivo: {e}") from e
            return
        if tipo == "schtask_user":
            nome = self._validar_tarefa(backup)
            if self._xml_tarefa(nome) != backup["xml"]:
                raise IncidentError(_MUDOU)
            self._schtasks_ok(["/Delete", "/TN", nome, "/F"], "remover a tarefa")
            return
        raise IncidentError(_ADULTERADO)

    # ---------- restaurar ----------
    def restaurar(self, backup: dict) -> None:
        tipo = backup.get("tipo") if isinstance(backup, dict) else None
        if tipo in _CHAVES:
            chave, nome = self._validar_registro(backup)
            atual = self._valor_registro(chave, nome)
            if atual is not None:
                if atual[0] == backup["valor"]:
                    return
                raise IncidentError(_EXISTE)
            try:
                self._registro.gravar(chave, nome, backup["valor"], backup["tipo_reg"])
            except OSError as e:
                raise IncidentError(f"Não foi possível restaurar a entrada: {e}") from e
            return
        if tipo == "startup_user":
            f, dados = self._validar_inicializar(backup)
            if os.path.lexists(f):
                if sha256_arquivo(f) == backup["sha256"]:
                    return
                raise IncidentError(_EXISTE)
            try:
                fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0))
                with os.fdopen(fd, "wb") as fh:
                    fh.write(dados)
                    fh.flush()
                    os.fsync(fh.fileno())
            except FileExistsError as e:
                raise IncidentError(_EXISTE) from e
            except OSError as e:
                raise IncidentError(f"Não foi possível restaurar o arquivo: {e}") from e
            return
        if tipo == "schtask_user":
            nome = self._validar_tarefa(backup)
            atual = self._xml_tarefa(nome)
            if atual is not None:
                if atual == backup["xml"]:
                    return
                raise IncidentError(_EXISTE)
            fd, caminho = tempfile.mkstemp(suffix=".xml")
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(backup["xml"].encode("utf-16"))  # o XML do schtasks declara UTF-16
                # Sem /F: se outra tarefa com esse nome surgir no meio do caminho, o schtasks recusa.
                self._schtasks_ok(["/Create", "/TN", nome, "/XML", caminho], "restaurar a tarefa")
            finally:
                try:
                    os.remove(caminho)
                except OSError:
                    pass
            return
        raise IncidentError(_ADULTERADO)

    # ---------- auxiliares ----------
    def _executar(self, args: list[str]) -> tuple[int, str]:
        if self._run is None:
            raise IncidentError("O Agendador de Tarefas não está disponível.")
        try:
            return self._run([_schtasks(), *args], _TIMEOUT)
        except (OSError, subprocess.SubprocessError) as e:
            raise IncidentError(f"Não foi possível executar o schtasks: {e}") from e

    def _xml_tarefa(self, nome: str) -> str | None:
        """XML completo da tarefa, ou None se ela não existe (ou não pode ser lida)."""
        rc, saida = self._executar(["/Query", "/TN", nome, "/XML"])
        return saida if rc == 0 else None

    def _schtasks_ok(self, args: list[str], acao: str) -> None:
        rc, saida = self._executar(args)
        if rc != 0:
            raise IncidentError(f"Não foi possível {acao}: {exibivel(saida.strip(), 300)}")

    @staticmethod
    def _validar_tarefa(b: dict) -> str:
        if not _nome_tarefa_valido(b.get("nome")) or not isinstance(b.get("xml"), str) or not b["xml"].strip():
            raise IncidentError(_ADULTERADO)
        return b["nome"]

    def _valor_registro(self, chave: str, nome: str) -> tuple[str, int] | None:
        if self._registro is None:
            raise IncidentError("O registro do Windows não está disponível.")
        try:
            valores = self._registro.valores(chave)
        except OSError as e:
            raise IncidentError(f"Não foi possível ler o registro: {e}") from e
        for n, v, t in valores:
            if n == nome:
                return (v, t) if isinstance(v, str) else None
        return None

    def _validar_registro(self, b: dict) -> tuple[str, str]:
        if (b.get("chave") != _CHAVES[b["tipo"]] or not isinstance(b.get("nome"), str)
                or not isinstance(b.get("valor"), str) or b.get("tipo_reg") not in (REG_SZ, REG_EXPAND_SZ)):
            raise IncidentError(_ADULTERADO)
        return b["chave"], b["nome"]

    def _ler_inicializar(self, pasta: str, nome: str) -> bytes:
        if self._pasta is None or pasta != str(self._pasta) or not _nome_seguro(nome):
            raise IncidentError(_MUDOU)
        f = self._pasta / nome
        try:
            st = os.lstat(f)
            if not stat.S_ISREG(st.st_mode):
                raise IncidentError(_MUDOU)
            if st.st_size > LIMITE_INICIALIZAR:
                raise IncidentError(_GRANDE)
            return f.read_bytes()
        except FileNotFoundError as e:
            raise IncidentError(_MUDOU) from e
        except OSError as e:
            raise IncidentError(f"Não foi possível ler o arquivo: {e}") from e

    def _validar_inicializar(self, b: dict) -> tuple[Path, bytes]:
        if (self._pasta is None or b.get("pasta") != str(self._pasta) or not _nome_seguro(b.get("nome"))
                or not isinstance(b.get("sha256"), str) or not isinstance(b.get("conteudo"), str)):
            raise IncidentError(_ADULTERADO)
        try:
            dados = _embaralhar(base64.b64decode(b["conteudo"], validate=True))
        except (binascii.Error, ValueError) as e:
            raise IncidentError(_ADULTERADO) from e
        if hashlib.sha256(dados).hexdigest() != b["sha256"]:
            raise IncidentError(_ADULTERADO)
        return self._pasta / b["nome"], dados


if sys.platform == "win32":
    import winreg

    class RegistroWindows:
        """Valores do HKEY_CURRENT_USER (sem administrador)."""

        def valores(self, chave: str) -> list[tuple[str, object, int]]:
            try:
                k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, chave)
            except FileNotFoundError:
                return []
            saida = []
            with k:
                i = 0
                while True:
                    try:
                        saida.append(winreg.EnumValue(k, i))
                    except OSError:
                        break
                    i += 1
            return saida

        def apagar(self, chave: str, nome: str) -> None:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, chave, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, nome)

        def gravar(self, chave: str, nome: str, valor: str, tipo_reg: int) -> None:
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, chave, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, nome, 0, tipo_reg, valor)
