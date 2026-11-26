"""MandacaruGuard: o serviço opcional "Proteção avançada", que roda como SYSTEM.

Executa só as ações do protocolo fechado (`guard_protocol`), pedidas pela janela sem privilégio
por um named pipe. Regras que impedem o serviço de virar um caminho de escalação de privilégio:

- nada do Windows, do Defender nem do próprio Guard (`proibido`) é encerrado, posto em quarentena,
  bloqueado ou desativado, mesmo com SHA-256 correto;
- toda decisão sobre arquivo usa o caminho final do handle aberto, e apagar/criar usa o mesmo
  handle: trocar uma pasta por junção no meio do caminho não redireciona o SYSTEM;
- os backups do Desfazer ficam na pasta do serviço (só administradores); o cliente recebe um id
  e nunca manda conteúdo para o serviço gravar;
- serviços do Windows são desativados, nunca apagados.

A lógica abaixo é pura e testável fora do Windows (backends injetados). O que fala com o Windows
real (pipe, handles, registro HKLM, SCM) fica no bloco `win32` no fim do arquivo.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import ntpath
import os
import re
import threading
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from mandacaru.projeto.achado import exibivel
from mandacaru_win import __version__
from mandacaru_win.guard_protocol import (
    ID_RE,
    GuardError,
    caminho_valido,
    codificar,
    decodificar,
    resposta_erro,
    resposta_ok,
    validar_pedido,
)
from mandacaru_win.incident import sha256_arquivo
from mandacaru_win.incident_persist import (
    LIMITE_INICIALIZAR,
    _embaralhar,
    _nome_seguro,
    _nome_tarefa_valido,
)
from mandacaru_win.incident_proc import Processos, encerrar_arvore
from mandacaru_win.quarantine import _xor
from mandacaru_win.store import _atomic_write_json

NOME_SERVICO = "MandacaruGuard"
CHAVE_RUN_HKLM = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
CHAVE_RUNONCE_HKLM = CHAVE_RUN_HKLM + "Once"
_CHAVES_HKLM = {"hklm_run": CHAVE_RUN_HKLM, "hklm_runonce": CHAVE_RUNONCE_HKLM}
_CHAVE_SERVICOS = "SYSTEM\\CurrentControlSet\\Services\\"
_INICIO = {2: "auto", 3: "demand", 4: "disabled"}
_TIMEOUT = 60.0
log = logging.getLogger("mandacaru.guard")

_LINK = "O caminho passa por um link simbólico ou junção; nada foi feito."
_MUDOU_ARQ = "O arquivo mudou desde a detecção; nada foi movido."
_MUDOU = "A entrada mudou desde a detecção; nada foi removido."
_EXISTE = "Já existe outra entrada com esse nome; nada foi alterado."
_SEM_BACKUP = "Backup não encontrado: já foi restaurado ou não existe."
_ADULTERADO = "O backup desta ação está inválido ou foi alterado; nada foi restaurado."


# ---------- política de caminhos ----------
@dataclass(frozen=True)
class Ambiente:
    system_root: str
    program_files: tuple[str, ...]
    program_data: str
    pasta_guard: str

    @staticmethod
    def atual(pasta_guard: str) -> Ambiente:
        e = os.environ
        pfs = tuple(dict.fromkeys(p for p in (e.get("ProgramW6432"), e.get("ProgramFiles"),
                                              e.get("ProgramFiles(x86)")) if p))
        return Ambiente(e.get("SystemRoot") or r"C:\Windows", pfs or (r"C:\Program Files",),
                        e.get("ProgramData") or r"C:\ProgramData", pasta_guard)

    def proibidas(self) -> list[str]:
        saida = [self.system_root, ntpath.join(self.program_data, "Microsoft", "Windows Defender"),
                 self.pasta_guard]
        for pf in self.program_files:
            saida += [ntpath.join(pf, "Windows Defender"), ntpath.join(pf, "WindowsApps"),
                      ntpath.join(pf, "Windows Defender Advanced Threat Protection")]
        return saida


def _n(caminho: str) -> str:
    return ntpath.normcase(ntpath.normpath(caminho))


def _sob(caminho: str, base: str) -> bool:
    c, b = _n(caminho), _n(base).rstrip("\\")
    return c == b or c.startswith(b + "\\")


def proibido(caminho: str, amb: Ambiente) -> bool:
    """O caminho é do Windows, do Defender ou do próprio Guard: o serviço não toca."""
    return any(_sob(caminho, b) for b in amb.proibidas())


def _mesmo(a: str, b: str) -> bool:
    return _n(a) == _n(b)


# ---------- backends ----------
class ArquivoAberto(Protocol):
    caminho_final: str

    def __enter__(self) -> ArquivoAberto: ...
    def __exit__(self, *exc) -> None: ...
    def ler(self) -> Iterator[bytes]: ...
    def escrever(self, dados: bytes) -> None: ...
    def apagar(self) -> None: ...


class Arquivos(Protocol):
    def abrir(self, caminho: str) -> ArquivoAberto: ...
    def criar_novo(self, caminho: str) -> ArquivoAberto: ...


class Registro(Protocol):
    def valores(self, chave: str) -> list[tuple[str, object, int]]: ...
    def apagar(self, chave: str, nome: str) -> None: ...
    def gravar(self, chave: str, nome: str, valor: str, tipo_reg: int) -> None: ...


Executor = Callable[[list[str], float], tuple[int, str]]


# ---------- ações ----------
class AcoesGuard:
    """Uma função por ação do protocolo; cada uma devolve a resposta e nunca levanta exceção."""

    def __init__(self, amb: Ambiente, *, processos: Processos, arquivos: Arquivos, registro: Registro,
                 run: Executor, pasta_dados: Path, pasta_inicializar_global: str,
                 hash_fn: Callable[[Path], str | None] = sha256_arquivo):
        self._amb = amb
        self._processos = processos
        self._arquivos = arquivos
        self._registro = registro
        self._run = run
        self._dados = Path(pasta_dados)
        self._inicializar = pasta_inicializar_global
        self._hash = hash_fn

    # ----- auxiliares -----
    def _sys32(self, exe: str) -> str:
        return ntpath.join(self._amb.system_root, "System32", exe)

    def _executar(self, args: list[str]) -> tuple[int, str]:
        try:
            return self._run(args, _TIMEOUT)
        except Exception as e:  # noqa: BLE001 - OSError, TimeoutExpired…: vira resposta de erro
            return 1, str(e)

    @property
    def _quarentena(self) -> Path:
        return self._dados / "quarentena"

    @property
    def _backups(self) -> Path:
        return self._dados / "backups"

    def _guardar_backup(self, backup: dict) -> str:
        bid = uuid.uuid4().hex
        _atomic_write_json(self._backups / f"{bid}.json", backup)
        return bid

    def _descartar_backup(self, bid: str) -> None:
        try:
            (self._backups / f"{bid}.json").unlink(missing_ok=True)
        except OSError:
            pass

    def _ler_backup(self, bid: str) -> dict | None:
        if not ID_RE.fullmatch(bid):
            return None
        try:
            d = json.loads((self._backups / f"{bid}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return d if isinstance(d, dict) else None

    # ----- ping -----
    def ping(self) -> dict:
        return resposta_ok(servico=NOME_SERVICO, versao=__version__)

    # ----- Conter: processo -----
    def terminate_process(self, *, pid: int, exe: str, sha256: str) -> dict:
        if proibido(exe, self._amb):
            return resposta_erro("Programa do sistema: o serviço não encerra este processo.")
        try:
            r = encerrar_arvore(self._processos, pid, exe, sha256, hash_fn=self._hash, proprio_pid=os.getpid())
        except OSError as e:
            return resposta_erro(f"Não foi possível listar os processos: {e}")
        if r.recusa:
            return resposta_erro(r.recusa)
        return resposta_ok(encerrados=r.encerrados, falhas=[[p, m] for p, m in r.falhas])

    # ----- Conter: quarentena -----
    def quarantine_file(self, *, caminho: str, sha256: str) -> dict:
        qid = uuid.uuid4().hex
        binp, jsonp = self._quarentena / f"{qid}.bin", self._quarentena / f"{qid}.json"
        try:
            with self._arquivos.abrir(caminho) as h:
                final = h.caminho_final
                if not _mesmo(final, caminho):
                    return resposta_erro(_LINK)
                if proibido(final, self._amb):
                    return resposta_erro("Arquivo do sistema: o serviço não o põe em quarentena.")
                self._quarentena.mkdir(parents=True, exist_ok=True)
                hs, off = hashlib.sha256(), 0
                with open(binp, "wb") as dst:
                    for bloco in h.ler():
                        hs.update(bloco)
                        dst.write(_xor(bloco, off))
                        off += len(bloco)
                    dst.flush()
                    os.fsync(dst.fileno())
                if hs.hexdigest() != sha256:
                    self._limpar(binp, jsonp)
                    return resposta_erro(_MUDOU_ARQ)
                _atomic_write_json(jsonp, {"id": qid, "caminho_original": final, "sha256": sha256,
                                           "data": datetime.now().astimezone().isoformat(timespec="seconds")})
                try:
                    h.apagar()  # pelo MESMO handle que foi conferido
                except OSError:
                    self._limpar(binp, jsonp)
                    return resposta_erro("O arquivo está em uso; encerre o processo e tente de novo.")
        except FileNotFoundError:
            self._limpar(binp, jsonp)
            return resposta_erro("O arquivo não existe mais.")
        except OSError as e:
            self._limpar(binp, jsonp)
            return resposta_erro(f"Não foi possível pôr o arquivo em quarentena: {e}")
        return resposta_ok(id=qid)

    @staticmethod
    def _limpar(*caminhos: Path) -> None:
        for p in caminhos:
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass

    def quarantine_restore(self, *, id: str) -> dict:  # noqa: A002 - nome do campo no protocolo
        binp, jsonp = self._quarentena / f"{id}.bin", self._quarentena / f"{id}.json"
        try:
            meta = json.loads(jsonp.read_text(encoding="utf-8"))
            cifrado = binp.read_bytes()
        except (OSError, ValueError):
            return resposta_erro("Item não encontrado na quarentena do serviço.")
        caminho, sha = meta.get("caminho_original"), meta.get("sha256")
        dados = _xor(cifrado, 0)
        if not caminho_valido(caminho) or not isinstance(sha, str) or hashlib.sha256(dados).hexdigest() != sha:
            return resposta_erro("O item da quarentena foi alterado e não será restaurado.")
        if proibido(caminho, self._amb):
            return resposta_erro("Arquivo do sistema: o serviço não o restaura.")
        erro = self._criar_arquivo(caminho, dados, "Já existe um arquivo nesse caminho; nada foi restaurado.")
        if erro:
            return resposta_erro(erro)
        self._limpar(binp, jsonp)
        return resposta_ok(caminho=caminho)

    def _criar_arquivo(self, caminho: str, dados: bytes, msg_existe: str) -> str | None:
        """Cria SEM sobrescrever e confere pelo handle onde o arquivo foi parar; None se deu certo."""
        try:
            h = self._arquivos.criar_novo(caminho)
        except FileExistsError:
            return msg_existe
        except OSError as e:
            return f"Não foi possível criar o arquivo: {e}"
        with h:
            if not _mesmo(h.caminho_final, caminho) or proibido(h.caminho_final, self._amb):
                h.apagar()
                return _LINK
            try:
                h.escrever(dados)
            except OSError as e:
                h.apagar()
                return f"Não foi possível gravar o arquivo: {e}"
        return None

    # ----- Conter: firewall -----
    def firewall_block(self, *, regra: str, exe: str) -> dict:
        try:
            with self._arquivos.abrir(exe) as h:
                final = h.caminho_final
        except FileNotFoundError:
            return resposta_erro("Executável não encontrado.")
        except OSError as e:
            return resposta_erro(f"Não foi possível conferir o executável: {e}")
        if not _mesmo(final, exe):
            return resposta_erro(_LINK)
        if proibido(final, self._amb):
            return resposta_erro("Programa do sistema: o serviço não bloqueia a rede dele.")
        netsh = self._sys32("netsh.exe")
        rc, _ = self._executar([netsh, "advfirewall", "firewall", "show", "rule", f"name={regra}"])
        if rc == 0:
            return resposta_erro("Já existe uma regra com esse nome.")
        rc, saida = self._executar([netsh, "advfirewall", "firewall", "add", "rule", f"name={regra}",
                                    "dir=out", "action=block", f"program={final}", "enable=yes"])
        if rc != 0:
            return resposta_erro(f"O Firewall do Windows recusou a regra: {exibivel(saida.strip(), 300)}")
        return resposta_ok(regra=regra)

    def firewall_unblock(self, *, regra: str) -> dict:
        rc, _ = self._executar([self._sys32("netsh.exe"), "advfirewall", "firewall", "delete", "rule",
                                f"name={regra}"])
        if rc != 0:
            return resposta_erro("A regra não foi encontrada ou não pôde ser removida.")
        return resposta_ok()

    def remover_todas_regras(self) -> dict:
        """Na desinstalação: apaga toda regra Mandacaru-* (o prefixo é fixo; nada mais é tocado)."""
        ps = ntpath.join(self._amb.system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
        rc, saida = self._executar([ps, "-NoProfile", "-NonInteractive", "-Command",
                                    "Get-NetFirewallRule -DisplayName 'Mandacaru-*' -ErrorAction "
                                    "SilentlyContinue | Remove-NetFirewallRule"])
        return resposta_ok() if rc == 0 else resposta_erro(exibivel(saida.strip(), 300))

    # ----- Neutralizar: persistência -----
    def persistence_remove(self, *, tipo: str, nome: str, valor: str) -> dict:
        try:
            if tipo in _CHAVES_HKLM:
                return self._remover_hklm(tipo, nome, valor)
            if tipo == "startup_all":
                return self._remover_inicializar(nome, valor)
            if tipo == "schtask":
                return self._remover_tarefa(nome)
            if tipo == "service":
                return self._remover_servico(nome)
        except OSError as e:
            return resposta_erro(f"Não foi possível remover a entrada: {e}")
        return resposta_erro("Tipo de persistência não aceito pelo serviço.")

    def _valor_hklm(self, chave: str, nome: str) -> tuple[object, int] | None:
        for n, v, t in self._registro.valores(chave):
            if n == nome:
                return v, t
        return None

    def _remover_hklm(self, tipo: str, nome: str, valor: str) -> dict:
        chave = _CHAVES_HKLM[tipo]
        atual = self._valor_hklm(chave, nome)
        if atual is None or not isinstance(atual[0], str) or atual[0] != valor:
            return resposta_erro(_MUDOU)
        bid = self._guardar_backup({"tipo": tipo, "chave": chave, "nome": nome, "valor": valor,
                                    "tipo_reg": atual[1]})
        try:
            self._registro.apagar(chave, nome)
        except OSError as e:
            self._descartar_backup(bid)
            return resposta_erro(f"Não foi possível remover a entrada: {e}")
        return resposta_ok(id=bid)

    def _remover_inicializar(self, nome: str, sha256: str) -> dict:
        f = ntpath.join(self._inicializar, nome)
        with self._arquivos.abrir(f) as h:
            if not _mesmo(h.caminho_final, f):
                return resposta_erro(_LINK)
            dados = bytearray()
            for bloco in h.ler():
                dados += bloco
                if len(dados) > LIMITE_INICIALIZAR:
                    return resposta_erro("Arquivo grande demais para guardar no backup; use a quarentena.")
            if hashlib.sha256(dados).hexdigest() != sha256:
                return resposta_erro(_MUDOU)
            bid = self._guardar_backup({"tipo": "startup_all", "pasta": self._inicializar, "nome": nome,
                                        "sha256": sha256,
                                        "conteudo": base64.b64encode(_embaralhar(bytes(dados))).decode("ascii")})
            try:
                h.apagar()
            except OSError as e:
                self._descartar_backup(bid)
                return resposta_erro(f"Não foi possível remover o arquivo: {e}")
        return resposta_ok(id=bid)

    @staticmethod
    def _tarefa_do_windows(nome: str) -> bool:
        return nome.casefold().startswith("\\microsoft\\")

    def _remover_tarefa(self, nome: str) -> dict:
        if not _nome_tarefa_valido(nome) or self._tarefa_do_windows(nome):
            return resposta_erro("Tarefa do próprio Windows: o serviço não a remove.")
        schtasks = self._sys32("schtasks.exe")
        rc, xml = self._executar([schtasks, "/Query", "/TN", nome, "/XML"])
        if rc != 0 or not xml.strip():
            return resposta_erro("Tarefa não encontrada.")
        bid = self._guardar_backup({"tipo": "schtask", "nome": nome, "xml": xml})
        rc, saida = self._executar([schtasks, "/Delete", "/TN", nome, "/F"])
        if rc != 0:
            self._descartar_backup(bid)
            return resposta_erro(f"Não foi possível remover a tarefa: {exibivel(saida.strip(), 300)}")
        return resposta_ok(id=bid)

    def _programa_do_servico(self, imagem: str) -> str:
        """Executável de um ImagePath ("…\\svc.exe" -k x, %SystemRoot%\\…, \\SystemRoot\\…, System32\\…)."""
        s = imagem.strip()
        if s.startswith('"'):
            prog = s[1:].split('"', 1)[0]
        else:
            m = re.match(r"(.+?\.(?:exe|sys|dll))(?=\s|$)", s, re.IGNORECASE)
            prog = m.group(1) if m else s.split(" ", 1)[0]
        raiz = self._amb.system_root
        prog = re.sub(r"(?i)^\\\?\?\\", "", prog)
        prog = re.sub(r"(?i)%(systemroot|windir)%", lambda _m: raiz, prog)
        prog = re.sub(r"(?i)^\\systemroot\\", lambda _m: raiz + "\\", prog)
        if not re.match(r"[A-Za-z]:[\\/]", prog):
            prog = ntpath.join(raiz, prog.lstrip("\\"))
        return prog

    def _remover_servico(self, nome: str) -> dict:
        vals = {n: v for n, v, _t in self._registro.valores(_CHAVE_SERVICOS + nome)}
        imagem, tipo_svc, inicio = vals.get("ImagePath"), vals.get("Type"), vals.get("Start")
        if not isinstance(imagem, str) or not isinstance(tipo_svc, int) or not isinstance(inicio, int):
            return resposta_erro("Serviço não encontrado.")
        if tipo_svc & 0x3:
            return resposta_erro("Drivers não são alterados pelo serviço.")
        if proibido(self._programa_do_servico(imagem), self._amb):
            return resposta_erro("Serviço do Windows: o serviço não o desativa.")
        if inicio not in _INICIO:
            return resposta_erro("Tipo de início do serviço não suportado.")
        bid = self._guardar_backup({"tipo": "service", "nome": nome, "start": inicio,
                                    "atrasado": vals.get("DelayedAutostart") == 1})
        sc = self._sys32("sc.exe")
        rc, saida = self._executar([sc, "config", nome, "start=", "disabled"])
        if rc != 0:
            self._descartar_backup(bid)
            return resposta_erro(f"O Windows recusou desativar o serviço: {exibivel(saida.strip(), 300)}")
        self._executar([sc, "stop", nome])  # já parado também serve
        return resposta_ok(id=bid)

    def persistence_restore(self, *, id: str) -> dict:  # noqa: A002 - nome do campo no protocolo
        b = self._ler_backup(id)
        if b is None:
            return resposta_erro(_SEM_BACKUP)
        try:
            resp = self._restaurar(b)
        except OSError as e:
            return resposta_erro(f"Não foi possível restaurar: {e}")
        if resp["ok"]:
            self._descartar_backup(id)
        return resp

    def _restaurar(self, b: dict) -> dict:
        tipo = b.get("tipo")
        if tipo in _CHAVES_HKLM:
            chave, nome, valor, treg = b.get("chave"), b.get("nome"), b.get("valor"), b.get("tipo_reg")
            if chave != _CHAVES_HKLM[tipo] or not isinstance(nome, str) or not isinstance(valor, str) \
                    or treg not in (1, 2):
                return resposta_erro(_ADULTERADO)
            atual = self._valor_hklm(chave, nome)
            if atual is not None:
                return resposta_ok() if atual[0] == valor else resposta_erro(_EXISTE)
            self._registro.gravar(chave, nome, valor, treg)
            return resposta_ok()
        if tipo == "startup_all":
            nome, sha, cont = b.get("nome"), b.get("sha256"), b.get("conteudo")
            if b.get("pasta") != self._inicializar or not _nome_seguro(nome) or not isinstance(sha, str) \
                    or not isinstance(cont, str):
                return resposta_erro(_ADULTERADO)
            try:
                dados = _embaralhar(base64.b64decode(cont, validate=True))
            except (binascii.Error, ValueError):
                return resposta_erro(_ADULTERADO)
            if hashlib.sha256(dados).hexdigest() != sha:
                return resposta_erro(_ADULTERADO)
            erro = self._criar_arquivo(ntpath.join(self._inicializar, nome), dados, _EXISTE)
            return resposta_erro(erro) if erro else resposta_ok()
        if tipo == "schtask":
            return self._restaurar_tarefa(b)
        if tipo == "service":
            nome, inicio = b.get("nome"), b.get("start")
            if not isinstance(nome, str) or not nome or any(c in nome for c in '\\/"') or inicio not in _INICIO:
                return resposta_erro(_ADULTERADO)
            modo = "delayed-auto" if inicio == 2 and b.get("atrasado") is True else _INICIO[inicio]
            rc, saida = self._executar([self._sys32("sc.exe"), "config", nome, "start=", modo])
            if rc != 0:
                return resposta_erro(f"O Windows recusou reativar o serviço: {exibivel(saida.strip(), 300)}")
            return resposta_ok()
        return resposta_erro(_ADULTERADO)

    def _restaurar_tarefa(self, b: dict) -> dict:
        nome, xml = b.get("nome"), b.get("xml")
        if not _nome_tarefa_valido(nome) or self._tarefa_do_windows(nome) or not isinstance(xml, str) \
                or not xml.strip():
            return resposta_erro(_ADULTERADO)
        schtasks = self._sys32("schtasks.exe")
        rc, atual = self._executar([schtasks, "/Query", "/TN", nome, "/XML"])
        if rc == 0:
            return resposta_ok() if atual == xml else resposta_erro(_EXISTE)
        tmp = self._dados / "tmp"
        tmp.mkdir(parents=True, exist_ok=True)
        arq = tmp / f"{uuid.uuid4().hex}.xml"
        try:
            arq.write_bytes(xml.encode("utf-16"))  # o XML do schtasks declara UTF-16
            rc, saida = self._executar([schtasks, "/Create", "/TN", nome, "/XML", str(arq)])  # sem /F
        finally:
            self._limpar(arq)
        if rc != 0:
            return resposta_erro(f"Não foi possível restaurar a tarefa: {exibivel(saida.strip(), 300)}")
        return resposta_ok()


# ---------- despachante ----------
class Despachante:
    """Uma linha de pedido → uma linha de resposta. As ações rodam uma de cada vez."""

    def __init__(self, acoes: AcoesGuard):
        self._acoes = acoes
        self._trava = threading.Lock()

    def tratar(self, linha: bytes, cliente_pid: int) -> bytes:
        acao, params = "?", {}
        try:
            acao, params = validar_pedido(decodificar(linha.rstrip(b"\r\n")))
            with self._trava:
                resp = getattr(self._acoes, acao)(**params)
        except GuardError as e:
            resp = resposta_erro(str(e))
        except Exception:  # noqa: BLE001 - nunca derruba o serviço
            log.exception("erro interno: cliente=%d acao=%s", cliente_pid, acao)
            resp = resposta_erro("Erro interno do serviço.")
        log.info("cliente=%d acao=%s ok=%s params=%s erro=%s", cliente_pid, acao, resp.get("ok"),
                 exibivel(json.dumps(params, ensure_ascii=False), 300), resp.get("erro", ""))
        return codificar(resp)
