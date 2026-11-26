"""A porta única do painel "Resposta a incidente" (c.2) para agir no sistema.

Toda ação é gravada no incidente com `resultado="em_andamento"` (e o backup do Desfazer) ANTES de
mexer em qualquer coisa; se nem isso der para gravar, nada é feito. Os métodos de ação nunca
levantam exceção: uma falha vira `Acao` com `resultado="falhou"` e o motivo em `detalhe`.
"""
from __future__ import annotations

import ntpath
import os
import sys

from mandacaru_win.incident import Acao, Incidente, IncidentError, IncidentStore, agora
from mandacaru_win.incident_cred import CATALOGO
from mandacaru_win.incident_persist import Entrada, Persistencia
from mandacaru_win.incident_proc import Processos, encerrar_arvore

_PADRAO = object()
_NAO_DESFAZ = "Esta ação não pode ser desfeita."


def _processos_padrao() -> Processos | None:
    if sys.platform != "win32":
        return None
    from mandacaru_win.incident_proc import ProcessosWindows
    return ProcessosWindows()


def _absoluto(c: object) -> bool:
    """Só caminhos completos do Windows: "AGENTS.md" casaria com qualquer texto."""
    return isinstance(c, str) and bool(ntpath.splitdrive(c)[0]) and ntpath.isabs(c)


class Resposta:
    def __init__(self, store: IncidentStore, inc: Incidente, *, processos=_PADRAO, persistencia=None):
        self._store = store
        self.inc = inc
        self._processos = _processos_padrao() if processos is _PADRAO else processos
        self._pers = persistencia if persistencia is not None else Persistencia()

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
    def encerrar_processo(self, pid: int, exe: str | os.PathLike, sha256: str, *, modo: str = "guiada") -> Acao:
        acao = Acao("encerrar_processo", "conter", modo, "em_andamento", "",
                    {"pid": pid, "exe": os.fspath(exe), "sha256": sha256}, agora())
        if not self._comecar(acao):
            return acao
        if self._processos is None:
            return self._terminar(acao, "falhou", "Encerrar processos só funciona no Windows.")
        try:
            r = encerrar_arvore(self._processos, pid, exe, sha256)
        except OSError as e:
            return self._terminar(acao, "falhou", f"Não foi possível listar os processos: {e}")
        if r.recusa:
            return self._terminar(acao, "falhou", r.recusa)
        acao.alvo["encerrados"] = r.encerrados
        detalhe = f"{len(r.encerrados)} processo(s) encerrado(s)."
        if r.falhas:
            detalhe += " Não encerrados: " + "; ".join(f"PID {p}: {m}" for p, m in r.falhas)
        resultado = "concluida" if not r.falhas else ("parcial" if r.encerrados else "falhou")
        return self._terminar(acao, resultado, detalhe)

    # ---------- Neutralizar ----------
    def detectar_persistencia(self) -> list[Entrada]:
        alvos = [a["caminho"] for a in self.inc.achados if _absoluto(a.get("caminho"))]
        if _absoluto(self.inc.pasta):
            alvos.append(self.inc.pasta)
        hashes = {a["sha256"] for a in self.inc.achados if isinstance(a.get("sha256"), str)}
        return self._pers.detectar(alvos, hashes)

    def remover_persistencia(self, e: Entrada, *, modo: str = "guiada") -> Acao:
        acao = Acao("remover_persistencia", "neutralizar", modo, "em_andamento", "",
                    {"tipo": e.tipo, "local": e.local, "nome": e.nome, "comando": e.comando}, agora())
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
            self._pers.restaurar(orig.backup)
        except IncidentError as err:
            return self._terminar(nova, "falhou", str(err))
        orig.desfeita = True
        return self._terminar(nova, "concluida", "Restaurado como estava antes.")

    # ---------- Recuperar ----------
    def marcar_credencial(self, item_id: str, feito: bool) -> None:
        if item_id not in CATALOGO:
            raise IncidentError(f"Item de credencial desconhecido: {item_id}")
        self.inc.credenciais[item_id] = bool(feito)
        self._store.salvar(self.inc)
