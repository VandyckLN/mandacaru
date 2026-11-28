"""A porta única do painel "Resposta a incidente" (c.2) para agir no sistema.

Toda ação é gravada no incidente com `resultado="em_andamento"` (e o backup do Desfazer) ANTES de
mexer em qualquer coisa; se nem isso der para gravar, nada é feito. Os métodos de ação nunca
levantam exceção: uma falha vira `Acao` com `resultado="falhou"` e o motivo em `detalhe`.
"""
from __future__ import annotations

import ntpath
import os
import re
import sys
import uuid
from collections.abc import Callable
from pathlib import Path

from mandacaru.events import Alert, Severity
from mandacaru_win.guard_protocol import GuardError
from mandacaru_win.incident import (
    Acao,
    Incidente,
    IncidentError,
    IncidentStore,
    agora,
    sha256_arquivo,
    sha256_valido,
)
from mandacaru_win.incident_cred import CATALOGO
from mandacaru_win.incident_persist import Entrada, Persistencia, menciona
from mandacaru_win.incident_proc import ProcessoInfo, Processos, encerrar_arvore
from mandacaru_win.quarantine import QuarantineError
from mandacaru_win.scan import Finding

_PADRAO = object()
_NAO_DESFAZ = "Esta ação não pode ser desfeita."
_PASTA_AMPLA_RE = re.compile(
    r"(?i)^[a-z]:\\(?:"
    r"|windows|program files(?: \(x86\))?|programdata|users"
    r"|users\\[^\\]+"
    r"|users\\[^\\]+\\appdata(?:\\(?:local|roaming|locallow)(?:\\temp)?)?"
    r")$"
)


def _processos_padrao() -> Processos | None:
    if sys.platform != "win32":
        return None
    from mandacaru_win.incident_proc import ProcessosWindows
    return ProcessosWindows()


def _absoluto(c: object) -> bool:
    """Só caminhos completos do Windows: "AGENTS.md" casaria com qualquer texto."""
    return isinstance(c, str) and bool(ntpath.splitdrive(c)[0]) and ntpath.isabs(c)


def _pastas_protegidas_env() -> set[str]:
    protegidas: set[str] = set()
    for var in ("USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP",
                "WINDIR", "SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "PUBLIC"):
        val = os.environ.get(var)
        if val and _absoluto(val):
            protegidas.add(ntpath.normpath(val).rstrip("\\").casefold())
    return protegidas


def _pasta_projeto_segura(pasta: object) -> bool:
    """Recusa raízes de disco, pastas do sistema e a raiz do perfil do usuário como alvo de prefixo."""
    if not _absoluto(pasta):
        return False
    norm = ntpath.normpath(str(pasta)).rstrip("\\")
    _drv, resto = ntpath.splitdrive(norm)
    if resto in ("", "\\") or _PASTA_AMPLA_RE.match(norm):
        return False
    return norm.casefold() not in _pastas_protegidas_env()


_REQUER_GUARD = "Requer Proteção avançada: ative-a executando o instalador de novo."
_GUARD_FORA = "Requer Proteção avançada: o serviço não está respondendo agora; nada foi feito."
# Entrada detectada pelo app -> tipo aceito pelo MandacaruGuard.
_TIPO_GUARD = {"hklm_run": "hklm_run", "hklm_runonce": "hklm_runonce", "startup_all": "startup_all",
               "service": "service", "schtask_sistema": "schtask"}


class Resposta:
    def __init__(self, store: IncidentStore, inc: Incidente, *, processos=_PADRAO, persistencia=None,
                 hash_fn: Callable[[Path], str | None] = sha256_arquivo, guard=None, quarentena=None):
        self._store = store
        self.inc = inc
        self._processos = _processos_padrao() if processos is _PADRAO else processos
        self._pers = persistencia if persistencia is not None else Persistencia()
        self._hash = hash_fn
        self._guard = guard  # GuardClient (ou falso nos testes); None = sem Proteção avançada
        self._quarentena = quarentena

    def guard_disponivel(self) -> bool:
        """A Proteção avançada está instalada e respondendo agora (um ping, alguns milissegundos)."""
        try:
            return self._guard is not None and bool(self._guard.disponivel())
        except Exception:  # noqa: BLE001 - qualquer falha do pipe = indisponível
            return False

    def _pedir_guard(self, acao: str, **params) -> dict:
        """Pedido ao Guard; GuardError com a mensagem do serviço ou de indisponibilidade."""
        if not self.guard_disponivel():
            raise GuardError(_REQUER_GUARD if self._guard is None else _GUARD_FORA)
        return self._guard.chamar(acao, **params)

    # ---------- registro ----------
    def _comecar(self, acao: Acao) -> bool:
        """Grava a ação antes de agir; False (e a ação fora do incidente) se não deu para gravar."""
        try:
            self._store.registrar(self.inc, acao)
        except IncidentError as e:
            if self.inc.acoes and self.inc.acoes[-1] is acao:
                self.inc.acoes.pop()
            acao.resultado, acao.detalhe = "falhou", f"{e} Nada foi feito."
            return False
        return True

    def _terminar(self, acao: Acao, resultado: str, detalhe: str) -> Acao:
        acao.resultado, acao.detalhe = resultado, detalhe
        try:
            self._store.salvar(self.inc)
        except IncidentError as e:
            acao.detalhe += f" Aviso: {e}"
        return acao

    # ---------- Conter ----------
    def _alvos_e_hashes(self) -> tuple[list[str], set[str]]:
        alvos = [a["caminho"] for a in self.inc.achados if _absoluto(a.get("caminho"))]
        if _pasta_projeto_segura(self.inc.pasta):
            alvos.append(self.inc.pasta)
        hashes = {a["sha256"].lower() for a in self.inc.achados if sha256_valido(a.get("sha256"))}
        return alvos, hashes

    def detectar_processos(self) -> list[ProcessoInfo]:
        """Processos ativos ligados aos caminhos, pasta do projeto ou hashes do incidente."""
        if self._processos is None:
            return []
        alvos, hashes = self._alvos_e_hashes()
        if not alvos and not hashes:
            return []
        try:
            todos = self._processos.listar()
        except OSError:
            return []
        proprio = os.getpid()
        cache_sha: dict[str, str | None] = {}
        achados: list[ProcessoInfo] = []
        for p in todos:
            if p.pid <= 4 or p.pid == proprio or not p.exe:
                continue
            if any(menciona(p.exe, a) for a in alvos):
                achados.append(p)
                continue
            if hashes:
                chave = ntpath.normcase(p.exe)
                if chave not in cache_sha:
                    sha = self._hash(Path(p.exe))
                    cache_sha[chave] = sha.lower() if sha else None
                if cache_sha[chave] in hashes:
                    achados.append(p)
        return achados

    def sha_para_encerrar(self, proc: ProcessoInfo) -> tuple[str | None, str | None]:
        """(SHA-256 esperado, motivo de recusa). Nunca confia no disco quando o achado diz outra coisa.

        Se um achado aponta para o executável do processo, só serve o SHA-256 desse achado: se o arquivo
        no disco tem outro hash, não é mais o programa detectado (ex.: o instalador legítimo baixado
        com o mesmo nome). Sem achado para o caminho (o processo casou pela pasta ou pelo hash), vale o
        hash do disco.
        """
        if not proc.exe:
            return None, "Não foi possível saber o executável deste processo."
        do_achado = next((a["sha256"].lower() for a in self.inc.achados
                          if isinstance(a.get("caminho"), str) and sha256_valido(a.get("sha256"))
                          and ntpath.normcase(a["caminho"]) == ntpath.normcase(proc.exe)), None)
        disco = self._hash(Path(proc.exe))
        disco = disco.lower() if disco else None
        if do_achado is not None:
            if disco != do_achado:
                return None, "O executável mudou desde a detecção; não dá para confirmar que é o mesmo programa."
            return do_achado, None
        if disco is None:
            return None, "Não foi possível ler o executável para confirmar o processo."
        return disco, None

    def encerrar_processo(self, pid: int, exe: str | os.PathLike, sha256: str, *, modo: str = "guiada") -> Acao:
        acao = Acao("encerrar_processo", "conter", modo, "em_andamento", "",
                    {"pid": pid, "exe": os.fspath(exe), "sha256": sha256}, agora())
        if not self._comecar(acao):
            return acao
        if self._processos is None:
            return self._terminar(acao, "falhou", "Encerrar processos só funciona no Windows.")
        try:
            r = encerrar_arvore(self._processos, pid, exe, sha256, hash_fn=self._hash)
        except OSError as e:
            return self._terminar(acao, "falhou", f"Não foi possível listar os processos: {e}")
        if r.recusa:
            return self._terminar(acao, "falhou", r.recusa)
        pelo_guard = False
        if any(p == pid for p, _m in r.falhas) and self.guard_disponivel():
            # Processo de outro usuário ou elevado: o Windows negou; o Guard (SYSTEM) confere e encerra.
            try:
                g = self._pedir_guard("terminate_process", pid=pid, exe=os.fspath(exe), sha256=sha256)
            except GuardError as e:
                r.falhas = [(p, m) for p, m in r.falhas if p != pid] + [(pid, str(e))]
            else:
                feitos = [p for p in g.get("encerrados", []) if isinstance(p, int)]
                r.encerrados = list(dict.fromkeys([*r.encerrados, *feitos]))
                r.falhas = [(p, m) for p, m in r.falhas if p not in feitos] + [
                    (p, str(m)) for p, m in g.get("falhas", []) if isinstance(p, int)]
                pelo_guard = True
        acao.alvo["encerrados"] = r.encerrados
        detalhe = f"{len(r.encerrados)} processo(s) encerrado(s)."
        if pelo_guard:
            detalhe += " A Proteção avançada encerrou o que o Windows negou ao seu usuário."
        if r.falhas:
            detalhe += " Não encerrados: " + "; ".join(f"PID {p}: {m}" for p, m in r.falhas)
        resultado = "concluida" if not r.falhas else ("parcial" if r.encerrados else "falhou")
        return self._terminar(acao, resultado, detalhe)

    # ---------- Neutralizar ----------
    def detectar_persistencia(self) -> list[Entrada]:
        alvos, hashes = self._alvos_e_hashes()
        return self._pers.detectar(alvos, hashes)

    def remover_persistencia(self, e: Entrada, *, modo: str = "guiada") -> Acao:
        acao = Acao("remover_persistencia", "neutralizar", modo, "em_andamento", "",
                    {"tipo": e.tipo, "local": e.local, "nome": e.nome, "comando": e.comando}, agora())
        if e.exige_servico:
            return self._remover_pelo_guard(e, acao)
        try:
            acao.backup = self._pers.backup(e)
        except IncidentError as err:
            if self._comecar(acao):
                self._terminar(acao, "falhou", str(err))
            return acao
        if not self._comecar(acao):
            return acao
        try:
            self._pers.remover(acao.backup)
        except IncidentError as err:
            return self._terminar(acao, "falhou", str(err))
        return self._terminar(acao, "concluida", "Entrada removida; dá para desfazer.")

    def _remover_pelo_guard(self, e: Entrada, acao: Acao) -> Acao:
        tipo = _TIPO_GUARD.get(e.tipo)
        if not self._comecar(acao):
            return acao
        if tipo is None:
            return self._terminar(acao, "falhou", "Tipo de entrada não aceito pela Proteção avançada.")
        valor = e.sha256 or "" if tipo == "startup_all" else ("" if tipo in ("schtask", "service") else e.comando)
        try:
            resp = self._pedir_guard("persistence_remove", tipo=tipo, nome=e.nome, valor=valor)
        except GuardError as err:
            return self._terminar(acao, "falhou", str(err))
        acao.backup = {"guard": "persistencia", "id": resp.get("id")}
        detalhe = ("Serviço desativado pela Proteção avançada; dá para desfazer." if tipo == "service"
                   else "Entrada removida pela Proteção avançada; dá para desfazer.")
        return self._terminar(acao, "concluida", detalhe)

    # ---------- Conter: rede e quarentena ----------
    def bloquear_rede(self, exe: str | os.PathLike, *, modo: str = "guiada") -> Acao:
        """Regra de saída Mandacaru-<hex> no Firewall do Windows só para este executável (reversível)."""
        regra = f"Mandacaru-{uuid.uuid4().hex[:16]}"
        acao = Acao("bloquear_rede", "conter", modo, "em_andamento", "", {"exe": os.fspath(exe), "regra": regra},
                    agora())
        if not self._comecar(acao):
            return acao
        try:
            self._pedir_guard("firewall_block", regra=regra, exe=os.fspath(exe))
        except GuardError as err:
            return self._terminar(acao, "falhou", str(err))
        acao.backup = {"guard": "firewall", "regra": regra}
        return self._terminar(acao, "concluida", f"Saída de rede bloqueada (regra {regra}); dá para desfazer.")

    def quarentenar(self, caminho: str | os.PathLike, sha256: str, severidade: str, regras: list[str], *,
                    modo: str = "guiada") -> Acao:
        """Quarentena do app; se o usuário não consegue (pasta do sistema, arquivo de outro usuário), o Guard."""
        caminho = os.fspath(caminho)
        acao = Acao("quarentena_arquivo", "conter", modo, "em_andamento", "",
                    {"caminho": caminho, "sha256": sha256}, agora())
        if not self._comecar(acao):
            return acao
        erro_local = "Quarentena indisponível."
        if self._quarentena is not None:
            sev = Severity[severidade] if severidade in Severity.__members__ else Severity.HIGH
            alertas = [Alert(r, sev, r) for r in (regras or ["incidente.arquivo"])]
            try:
                qid = self._quarentena.add(Finding(Path(caminho), sha256, sev, alertas))
            except QuarantineError as e:
                erro_local = str(e)
            else:
                acao.alvo["quarantine_id"] = qid
                acao.backup = {"local": "quarentena", "id": qid}
                return self._terminar(acao, "concluida", "Arquivo movido para a quarentena; dá para desfazer.")
        if not self.guard_disponivel():
            return self._terminar(acao, "falhou", erro_local)
        try:
            resp = self._pedir_guard("quarantine_file", caminho=caminho, sha256=sha256)
        except GuardError as err:
            return self._terminar(acao, "falhou", f"{erro_local} Proteção avançada: {err}")
        acao.backup = {"guard": "quarentena", "id": resp.get("id")}
        return self._terminar(acao, "concluida",
                              "Arquivo movido para a quarentena da Proteção avançada; dá para desfazer.")

    def desfazer(self, indice: int) -> Acao:
        orig = self.inc.acoes[indice] if 0 <= indice < len(self.inc.acoes) else None
        nova = Acao("desfazer", orig.fase if orig else "neutralizar", "guiada", "em_andamento", "",
                    {"indice": indice, **(orig.alvo if orig else {})}, agora())
        if not self._comecar(nova):
            return nova
        if orig is None or orig.backup is None or orig.resultado != "concluida":
            return self._terminar(nova, "falhou", _NAO_DESFAZ)
        if orig.desfeita:
            return self._terminar(nova, "falhou", "Esta ação já foi desfeita.")
        try:
            detalhe = self._restaurar(orig.backup)
        except (IncidentError, GuardError, QuarantineError) as err:
            return self._terminar(nova, "falhou", str(err))
        orig.desfeita = True
        return self._terminar(nova, "concluida", detalhe)

    def _restaurar(self, b: dict) -> str:
        """Desfaz pelo mesmo caminho da ação: Guard, quarentena do app ou persistência do usuário."""
        origem = b.get("guard")
        if origem == "persistencia":
            self._pedir_guard("persistence_restore", id=str(b.get("id")))
            return "Restaurado pela Proteção avançada."
        if origem == "firewall":
            self._pedir_guard("firewall_unblock", regra=str(b.get("regra")))
            return "Regra de firewall removida; a rede do programa voltou."
        if origem == "quarentena":
            resp = self._pedir_guard("quarantine_restore", id=str(b.get("id")))
            return f"Arquivo restaurado em {resp.get('caminho', 'seu lugar original')}."
        qid = b.get("id") if b.get("local") == "quarentena" else (
            b.get("quarantine_id") if b.get("tipo") == "quarantine" else None)  # formato antigo do painel
        if qid is not None:
            if self._quarentena is None:
                raise IncidentError("Quarentena indisponível.")
            return f"Arquivo restaurado em {self._quarentena.restore(str(qid))}."
        self._pers.restaurar(b)
        return "Restaurado como estava antes."

    # ---------- Recuperar ----------
    def marcar_credencial(self, item_id: str, feito: bool) -> None:
        if item_id not in CATALOGO:
            raise IncidentError(f"Item de credencial desconhecido: {item_id}")
        self.inc.credenciais[item_id] = bool(feito)
        self._store.salvar(self.inc)
