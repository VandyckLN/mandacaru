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
import sys
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
    CHAVE_RUN_HKLM,
    CHAVE_RUNONCE_HKLM,
    LIMITE_INICIALIZAR,
    _embaralhar,
    _nome_seguro,
    _nome_tarefa_valido,
    programa_de_comando,
)
from mandacaru_win.incident_proc import Processos, encerrar_arvore
from mandacaru_win.quarantine import _xor
from mandacaru_win.store import _atomic_write_json

NOME_SERVICO = "MandacaruGuard"
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

    def _remover_servico(self, nome: str) -> dict:
        vals = {n: v for n, v, _t in self._registro.valores(_CHAVE_SERVICOS + nome)}
        imagem, tipo_svc, inicio = vals.get("ImagePath"), vals.get("Type"), vals.get("Start")
        if not isinstance(imagem, str) or not isinstance(tipo_svc, int) or not isinstance(inicio, int):
            return resposta_erro("Serviço não encontrado.")
        if tipo_svc & 0x3:
            return resposta_erro("Drivers não são alterados pelo serviço.")
        if proibido(programa_de_comando(imagem, self._amb.system_root), self._amb):
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


# ---------- configuração e cliente autorizado ----------
def pasta_protegida(pasta: str | os.PathLike, amb: Ambiente) -> bool:
    """O serviço só roda de uma pasta sob Arquivos de Programas (só administradores escrevem lá).

    Um serviço SYSTEM rodando de uma pasta do usuário seria escalação de privilégio trivial: bastaria
    trocar o executável.
    """
    return any(_sob(os.fspath(pasta), pf) for pf in amb.program_files)


def carregar_config(pasta: str | os.PathLike) -> list[str]:
    """Executáveis autorizados a falar com o serviço, de `guard.json` (gravado pelo instalador elevado)."""
    try:
        d = json.loads((Path(pasta) / "guard.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        log.warning("guard.json ausente ou inválido (%s): nenhum cliente autorizado", e)
        return []
    clientes = d.get("clientes") if isinstance(d, dict) else None
    return [c for c in clientes if caminho_valido(c)] if isinstance(clientes, list) else []


def verificador_de_clientes(permitidos: list[str], *,
                            exe_do_pid: Callable[[int], str | None] | None = None) -> Callable[[int], bool]:
    """Função que diz se o processo do outro lado do pipe roda um dos executáveis autorizados."""
    exe_fn = exe_do_pid if exe_do_pid is not None else globals().get("exe_do_pid")
    autorizados = {_n(p) for p in permitidos}

    def verificar(pid: int) -> bool:
        exe = exe_fn(pid) if exe_fn else None
        return bool(exe) and _n(exe) in autorizados
    return verificar


def main(argv: list[str]) -> int:
    """`servico`: roda sob o SCM. `remover-regras`: apaga as regras Mandacaru-* (desinstalação)."""
    if argv == ["servico"] and sys.platform == "win32":
        executar_servico()
        return 0
    if argv == ["remover-regras"] and sys.platform == "win32":
        pasta = Path(sys.executable).resolve().parent
        resp = _montar_acoes(pasta).remover_todas_regras()
        print(resp.get("erro") or "Regras Mandacaru-* removidas.")
        return 0 if resp["ok"] else 1
    print("uso: guard_service (servico | remover-regras)", file=sys.stderr)
    return 2


if sys.platform == "win32":
    import ctypes
    import logging.handlers
    import msvcrt
    import winreg
    from ctypes import wintypes

    from mandacaru_win.guard_protocol import MAX_MENSAGEM
    from mandacaru_win.incident_persist import _run_oem
    from mandacaru_win.incident_proc import ProcessosWindows

    NOME_PIPE = r"\\.\pipe\MandacaruGuard"
    # SYSTEM e Administradores: tudo. Usuários interativos: ler e escrever, SEM FILE_CREATE_PIPE_INSTANCE
    # (0x4), então nenhum usuário consegue abrir uma instância "servidor" com este nome.
    SDDL_PIPE = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)"

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _adv = ctypes.WinDLL("advapi32", use_last_error=True)
    _INVALIDO = wintypes.HANDLE(-1).value
    _GENERIC_READ, _GENERIC_WRITE, _DELETE = 0x80000000, 0x40000000, 0x00010000
    _SHARE_TODOS = 0x1 | 0x2 | 0x4
    _OPEN_EXISTING, _CREATE_NEW = 3, 1
    _FLAG_REPARSE, _ATTR_NORMAL = 0x00200000, 0x80
    _ATTR_DIRETORIO, _ATTR_REPARSE = 0x10, 0x400
    _FILE_DISPOSITION_INFO = 4
    _ERROS_NAO_EXISTE = (2, 3)
    _ERROS_EXISTE = (80, 183)
    _ERROS_ACESSO = (5, 32)
    _PIPE_ACCESS_DUPLEX, _FIRST_INSTANCE = 0x3, 0x00080000
    _PIPE_REJECT_REMOTE = 0x8
    _PIPE_CONNECTED = 535

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", wintypes.LPVOID),
                    ("bInheritHandle", wintypes.BOOL)]

    class _DISPOSICAO(ctypes.Structure):
        _fields_ = [("DeleteFile", wintypes.BOOLEAN)]

    def _sig(f, args, res):
        f.argtypes, f.restype = args, res

    _sig(_k32.CreateFileW, [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                            wintypes.DWORD, wintypes.HANDLE], wintypes.HANDLE)
    _sig(_k32.GetFinalPathNameByHandleW, [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD],
         wintypes.DWORD)
    _sig(_k32.SetFileInformationByHandle, [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD],
         wintypes.BOOL)
    _sig(_k32.CloseHandle, [wintypes.HANDLE], wintypes.BOOL)
    _sig(_k32.CreateNamedPipeW, [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                 wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                 ctypes.POINTER(_SECURITY_ATTRIBUTES)], wintypes.HANDLE)
    _sig(_k32.ConnectNamedPipe, [wintypes.HANDLE, wintypes.LPVOID], wintypes.BOOL)
    _sig(_k32.DisconnectNamedPipe, [wintypes.HANDLE], wintypes.BOOL)
    _sig(_k32.FlushFileBuffers, [wintypes.HANDLE], wintypes.BOOL)
    _sig(_k32.GetNamedPipeClientProcessId, [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)], wintypes.BOOL)
    _sig(_k32.ReadFile, [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                         wintypes.LPVOID], wintypes.BOOL)
    _sig(_k32.WriteFile, [wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                          wintypes.LPVOID], wintypes.BOOL)
    _sig(_k32.OpenProcess, [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE)
    _sig(_k32.QueryFullProcessImageNameW, [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                           ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL)
    _sig(_adv.ConvertStringSecurityDescriptorToSecurityDescriptorW,
         [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.ULONG)],
         wintypes.BOOL)

    def _erro_win(n: int | None = None) -> OSError:
        n = ctypes.get_last_error() if n is None else n
        if n in _ERROS_NAO_EXISTE:
            return FileNotFoundError(n, ctypes.FormatError(n).strip())
        if n in _ERROS_EXISTE:
            return FileExistsError(n, ctypes.FormatError(n).strip())
        return OSError(n, ctypes.FormatError(n).strip())

    def _caminho_final(h) -> str:
        buf = ctypes.create_unicode_buffer(32768)
        n = _k32.GetFinalPathNameByHandleW(h, buf, len(buf), 0)
        if not n:
            raise _erro_win()
        s = buf.value
        return s[4:] if s.startswith("\\\\?\\") and not s.startswith("\\\\?\\UNC\\") else s

    class _Aberto:
        """Arquivo aberto por handle: o caminho final, a leitura e o apagar falam do MESMO arquivo."""

        def __init__(self, h, pode_apagar: bool):
            """Toma posse do handle: em qualquer falha aqui dentro, ele é fechado UMA vez, aqui."""
            self._h = h
            self._pode_apagar = pode_apagar
            try:
                self.caminho_final = _caminho_final(h)
                fd = msvcrt.open_osfhandle(h, os.O_RDWR | os.O_BINARY)
            except Exception:
                _k32.CloseHandle(h)
                raise
            try:
                self._arq = os.fdopen(fd, "r+b", buffering=0)
            except Exception:
                os.close(fd)  # o fd é dono do handle
                raise
            try:
                attrs = os.fstat(self._arq.fileno()).st_file_attributes
            except Exception:
                self._arq.close()
                raise
            if attrs & (_ATTR_DIRETORIO | _ATTR_REPARSE):
                self._arq.close()
                raise OSError(_LINK)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._arq.close()

        def ler(self):
            self._arq.seek(0)
            while bloco := self._arq.read(1024 * 1024):
                yield bloco

        def escrever(self, dados: bytes) -> None:
            vista = memoryview(dados)
            while vista:
                n = self._arq.write(vista)
                vista = vista[n:]
            os.fsync(self._arq.fileno())

        def apagar(self) -> None:
            if not self._pode_apagar:
                raise PermissionError("arquivo aberto sem permissão de apagar")
            info = _DISPOSICAO(True)
            if not _k32.SetFileInformationByHandle(self._h, _FILE_DISPOSITION_INFO, ctypes.byref(info),
                                                   ctypes.sizeof(info)):
                raise _erro_win()

    class ArquivosWindows:
        """Abre sem seguir link (FILE_FLAG_OPEN_REPARSE_POINT); o caminho final mostra junções do caminho."""

        @staticmethod
        def _criar(caminho: str, acesso: int, compart: int, disposicao: int):
            h = _k32.CreateFileW(caminho, acesso, compart, None, disposicao, _ATTR_NORMAL | _FLAG_REPARSE, None)
            if h == _INVALIDO or not h:
                raise _erro_win()
            return h

        def abrir(self, caminho: str) -> _Aberto:
            try:
                h, apagar = self._criar(caminho, _GENERIC_READ | _DELETE, _SHARE_TODOS, _OPEN_EXISTING), True
            except OSError as e:
                if e.errno not in _ERROS_ACESSO:  # executável em uso: abre só para ler (firewall)
                    raise
                h, apagar = self._criar(caminho, _GENERIC_READ, _SHARE_TODOS, _OPEN_EXISTING), False
            return _Aberto(h, apagar)  # _Aberto fecha o handle se falhar

        def criar_novo(self, caminho: str) -> _Aberto:
            h = self._criar(caminho, _GENERIC_READ | _GENERIC_WRITE | _DELETE, 0, _CREATE_NEW)
            return _Aberto(h, True)

    class RegistroHKLM:
        """HKEY_LOCAL_MACHINE, sempre na visão de 64 bits."""

        _VISAO = winreg.KEY_WOW64_64KEY

        def valores(self, chave: str) -> list[tuple[str, object, int]]:
            try:
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, chave, 0, winreg.KEY_READ | self._VISAO)
            except FileNotFoundError:
                return []
            saida, i = [], 0
            with k:
                while True:
                    try:
                        saida.append(winreg.EnumValue(k, i))
                    except OSError:
                        break
                    i += 1
            return saida

        def apagar(self, chave: str, nome: str) -> None:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, chave, 0, winreg.KEY_SET_VALUE | self._VISAO) as k:
                winreg.DeleteValue(k, nome)

        def gravar(self, chave: str, nome: str, valor: str, tipo_reg: int) -> None:
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, chave, 0,
                                    winreg.KEY_SET_VALUE | self._VISAO) as k:
                winreg.SetValueEx(k, nome, 0, tipo_reg, valor)

    def exe_do_pid(pid: int) -> str | None:
        h = _k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return None
        try:
            buf = ctypes.create_unicode_buffer(32768)
            n = wintypes.DWORD(len(buf))
            return buf.value if _k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)) else None
        finally:
            _k32.CloseHandle(h)

    class ServidorPipe:
        """Uma instância do pipe por conexão, cada uma numa thread (no máximo `max_conexoes`)."""

        def __init__(self, nome: str, despachante: Despachante, verificar_cliente: Callable[[int], bool], *,
                     max_conexoes: int = 4, prazo: float = 10.0):
            self._nome = nome
            self._desp = despachante
            self._verificar = verificar_cliente
            self._vagas = threading.Semaphore(max_conexoes)
            self._prazo = prazo
            self._parar = threading.Event()
            psd = wintypes.LPVOID()
            if not _adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(SDDL_PIPE, 1, ctypes.byref(psd),
                                                                             None):
                raise _erro_win()
            self._sa = _SECURITY_ATTRIBUTES(ctypes.sizeof(_SECURITY_ATTRIBUTES), psd, False)

        def _instancia(self, primeira: bool):
            modo = _PIPE_ACCESS_DUPLEX | (_FIRST_INSTANCE if primeira else 0)
            h = _k32.CreateNamedPipeW(self._nome, modo, _PIPE_REJECT_REMOTE, 255, MAX_MENSAGEM, MAX_MENSAGEM, 0,
                                      ctypes.byref(self._sa))
            if h == _INVALIDO or not h:
                raise _erro_win()  # primeira instância: outro processo já tem o nome (sequestro)
            return h

        def servir(self) -> None:
            primeira = True
            while not self._parar.is_set():
                h = self._instancia(primeira)
                primeira = False
                if not _k32.ConnectNamedPipe(h, None) and ctypes.get_last_error() != _PIPE_CONNECTED:
                    _k32.CloseHandle(h)
                    continue
                if self._parar.is_set():
                    _k32.CloseHandle(h)
                    break
                if not self._vagas.acquire(blocking=False):
                    _k32.DisconnectNamedPipe(h)
                    _k32.CloseHandle(h)
                    continue
                threading.Thread(target=self._atender, args=(h,), daemon=True).start()

        def parar(self) -> None:
            self._parar.set()
            try:  # acorda o ConnectNamedPipe que está esperando
                with open(self._nome, "r+b", buffering=0):
                    pass
            except OSError:
                pass

        def _ler_linha(self, h) -> bytes | None:
            buf = ctypes.create_string_buffer(4096)
            lido = wintypes.DWORD()
            dados = b""
            while not dados.endswith(b"\n"):
                if not _k32.ReadFile(h, buf, len(buf), ctypes.byref(lido), None) or lido.value == 0:
                    return None
                dados += buf.raw[:lido.value]
                if len(dados) > MAX_MENSAGEM:
                    return dados  # o despachante recusa por tamanho
            return dados

        def _escrever(self, h, dados: bytes) -> None:
            escrito = wintypes.DWORD()
            _k32.WriteFile(h, dados, len(dados), ctypes.byref(escrito), None)
            _k32.FlushFileBuffers(h)

        def _atender(self, h) -> None:
            # Cliente parado no meio da conversa não prende a vaga para sempre.
            relogio = threading.Timer(self._prazo, _k32.DisconnectNamedPipe, args=(h,))
            relogio.start()
            try:
                pid = wintypes.ULONG()
                ok_pid = _k32.GetNamedPipeClientProcessId(h, ctypes.byref(pid))
                if not ok_pid or not self._verificar(pid.value):
                    log.warning("cliente recusado: pid=%s", pid.value if ok_pid else "?")
                    self._escrever(h, codificar(resposta_erro("Cliente não autorizado.")))
                    return
                linha = self._ler_linha(h)
                if linha is not None:
                    self._escrever(h, self._desp.tratar(linha, pid.value))
            finally:
                relogio.cancel()
                _k32.DisconnectNamedPipe(h)
                _k32.CloseHandle(h)
                self._vagas.release()

    def _montar_acoes(pasta: Path) -> AcoesGuard:
        amb = Ambiente.atual(str(pasta))
        return AcoesGuard(
            amb, processos=ProcessosWindows(), arquivos=ArquivosWindows(), registro=RegistroHKLM(),
            run=_run_oem, pasta_dados=pasta / "dados",
            pasta_inicializar_global=ntpath.join(amb.program_data, "Microsoft", "Windows", "Start Menu",
                                                 "Programs", "StartUp"))

    # ----- anfitrião do SCM (Gerenciador de Controle de Serviços) -----
    _SERVICE_WIN32_OWN_PROCESS = 0x10
    _PARADO, _INICIANDO, _PARANDO, _RODANDO = 1, 2, 3, 4
    _ACEITA_STOP_SHUTDOWN = 0x1 | 0x4
    _CTRL_STOP, _CTRL_INTERROGATE, _CTRL_SHUTDOWN = 1, 4, 5

    class _SERVICE_STATUS(ctypes.Structure):
        _fields_ = [("dwServiceType", wintypes.DWORD), ("dwCurrentState", wintypes.DWORD),
                    ("dwControlsAccepted", wintypes.DWORD), ("dwWin32ExitCode", wintypes.DWORD),
                    ("dwServiceSpecificExitCode", wintypes.DWORD), ("dwCheckPoint", wintypes.DWORD),
                    ("dwWaitHint", wintypes.DWORD)]

    _MAIN = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))
    _HANDLER = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                  wintypes.LPVOID)

    class _SERVICE_TABLE_ENTRYW(ctypes.Structure):
        _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpServiceProc", _MAIN)]

    _sig(_adv.StartServiceCtrlDispatcherW, [ctypes.POINTER(_SERVICE_TABLE_ENTRYW)], wintypes.BOOL)
    _sig(_adv.RegisterServiceCtrlHandlerExW, [wintypes.LPCWSTR, _HANDLER, wintypes.LPVOID], wintypes.HANDLE)
    _sig(_adv.SetServiceStatus, [wintypes.HANDLE, ctypes.POINTER(_SERVICE_STATUS)], wintypes.BOOL)

    _estado: dict = {}  # referências vivas dos callbacks (o GC não pode levá-los)

    def _status(estado: int, saida: int = 0) -> None:
        st = _SERVICE_STATUS(_SERVICE_WIN32_OWN_PROCESS, estado,
                             _ACEITA_STOP_SHUTDOWN if estado == _RODANDO else 0, saida, 0, 0, 5000)
        _adv.SetServiceStatus(_estado["handle"], ctypes.byref(st))

    def _controle(ctrl, _tipo, _dados, _ctx):
        if ctrl in (_CTRL_STOP, _CTRL_SHUTDOWN):
            _status(_PARANDO)
            srv = _estado.get("servidor")
            if srv is not None:
                srv.parar()
            return 0
        return 0 if ctrl == _CTRL_INTERROGATE else 120  # ERROR_CALL_NOT_IMPLEMENTED

    def _servico_main(_argc, _argv):
        _estado["handler"] = _HANDLER(_controle)
        _estado["handle"] = _adv.RegisterServiceCtrlHandlerExW(NOME_SERVICO, _estado["handler"], None)
        _status(_INICIANDO)
        pasta = Path(sys.executable).resolve().parent
        try:
            arq_log = logging.handlers.RotatingFileHandler(pasta / "guard.log", maxBytes=1_000_000,
                                                           backupCount=3, encoding="utf-8")
            arq_log.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            log.addHandler(arq_log)
            log.setLevel(logging.INFO)
            amb = Ambiente.atual(str(pasta))
            if not pasta_protegida(pasta, amb):
                log.error("recusado: a pasta %s não fica sob Arquivos de Programas", pasta)
                _status(_PARADO, 1)
                return
            srv = ServidorPipe(NOME_PIPE, Despachante(_montar_acoes(pasta)),
                               verificador_de_clientes(carregar_config(pasta)))
            _estado["servidor"] = srv
            _status(_RODANDO)
            log.info("MandacaruGuard %s iniciado", __version__)
            srv.servir()
        except Exception:  # noqa: BLE001
            log.exception("falha no serviço")
            _status(_PARADO, 1)
            return
        _status(_PARADO)

    def executar_servico() -> None:
        _estado["main"] = _MAIN(_servico_main)
        tabela = (_SERVICE_TABLE_ENTRYW * 2)(_SERVICE_TABLE_ENTRYW(NOME_SERVICO, _estado["main"]),
                                            _SERVICE_TABLE_ENTRYW(None, _MAIN()))
        if not _adv.StartServiceCtrlDispatcherW(tabela):
            raise _erro_win()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
