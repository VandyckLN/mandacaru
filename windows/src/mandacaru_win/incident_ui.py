"""Painel guiado "Resposta a incidente" em 3 fases: Conter -> Neutralizar -> Recuperar."""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from mandacaru.events import Alert, Severity
from mandacaru.projeto.achado import exibivel
from mandacaru_win.incident import Acao, Incidente, IncidentError, IncidentStore, agora
from mandacaru_win.incident_cred import montar_checklist, url_oficial
from mandacaru_win.incident_persist import Entrada
from mandacaru_win.incident_proc import ProcessoInfo
from mandacaru_win.incident_report import exportar_html, exportar_json, salvar_relatorio
from mandacaru_win.incident_resposta import Resposta
from mandacaru_win.quarantine import Quarantine, QuarantineError
from mandacaru_win.scan import Finding
from mandacaru_win.theme import style_button

_ORIGEM_ROTULO = {
    "varredura": "Varredura",
    "projeto": "Verificar projeto",
    "atualizacoes": "Atualizações",
}
_AMEACA_ROTULO = {
    "malware": "Malware",
    "projeto": "Projeto armado",
    "vulnerabilidade": "Vulnerabilidade explorável",
}
_ACAO_ROTULO = {
    "encerrar_processo": "Encerrar processo",
    "quarentena_arquivo": "Quarentena de arquivo",
    "remover_persistencia": "Remover persistência",
    "varredura_completa": "Varredura completa em lotes",
    "destruir_projeto": "Destruir projeto",
    "desfazer": "Desfazer",
}
_INSTRUCOES_GUARD = (
    "Como ativar a Proteção avançada:\n\n"
    "1. Feche o Mandacaru.\n"
    "2. Execute novamente o instalador (Mandacaru-setup.exe).\n"
    "3. Marque a opção opcional \"Proteção avançada\" e confirme a permissão de administrador (UAC) "
    "uma única vez.\n\n"
    "Com a Proteção avançada ativa, o serviço isolado permite bloquear executáveis no Firewall do Windows, "
    "encerrar processos fora do seu usuário e remover persistência em HKLM e Serviços do Windows, mantendo "
    "a janela principal sem privilégio de administrador."
)
_AVISO_PROJETO_FIXO = (
    "Se você já abriu ou instalou este projeto, faça uma varredura completa e troque chaves e tokens. "
    "Destruir a pasta não desfaz o que já foi executado."
)


def _visivel(texto: object) -> str:
    return exibivel("" if texto is None else str(texto), limite=None)


def _limpar_layout(lay) -> None:
    while lay.count():
        item = lay.takeAt(0)
        w = item.widget()
        if w is not None:
            w.hide()
            w.deleteLater()
        elif item.layout() is not None:
            _limpar_layout(item.layout())


def _criar_selo(estado: str, texto: str) -> QLabel:
    lbl = QLabel(texto)
    lbl.setObjectName("incidentBadge")
    lbl.setProperty("state", estado)
    lbl.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
    return lbl


def _selo_da_acao(acao: Acao) -> QLabel:
    if acao.desfeita:
        return _criar_selo("undone", "Desfeita")
    if acao.resultado == "concluida":
        if acao.modo == "automatica":
            return _criar_selo("auto", "Feito automaticamente")
        return _criar_selo("done", "Concluído")
    if acao.resultado == "parcial":
        return _criar_selo("pending", "Parcial")
    if acao.resultado == "falhou":
        return _criar_selo("failed", "Falhou")
    return _criar_selo("pending", "Pendente")


class ExportIncidentDialog(QDialog):
    """Diálogo para exportar o relatório em HTML autocontido ou JSON (sanitizado por padrão)."""

    def __init__(self, inc: Incidente, parent: QWidget | None = None):
        super().__init__(parent)
        self._inc = inc
        self.setWindowTitle("Exportar relatório de incidente")
        self.resize(460, 210)
        lay = QVBoxLayout(self)
        lay.setSpacing(10)

        lbl = QLabel(
            "Escolha o formato para salvar ou enviar o relatório deste incidente. "
            "Os dados internos de restauração (Desfazer) nunca são incluídos."
        )
        lbl.setWordWrap(True)
        lay.addWidget(lbl)

        fmt_row = QHBoxLayout()
        fmt_row.addWidget(QLabel("Formato:"))
        self.cmb_format = QComboBox()
        self.cmb_format.addItem("HTML autocontido — imprimível em PDF (.html)", "html")
        self.cmb_format.addItem("JSON estruturado (.json)", "json")
        fmt_row.addWidget(self.cmb_format, 1)
        lay.addLayout(fmt_row)

        self.chk_sanitize = QCheckBox("Ocultar nome de usuário e caminhos pessoais")
        self.chk_sanitize.setChecked(True)
        lay.addWidget(self.chk_sanitize)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        btns.button(QDialogButtonBox.StandardButton.Save).setText("Escolher local e salvar…")
        btns.button(QDialogButtonBox.StandardButton.Cancel).setText("Cancelar")
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    def selected_format(self) -> str:
        return str(self.cmb_format.currentData() or "html")

    def export_to(self, destino: Path) -> Path:
        """Gera e salva atomicamente o relatório no caminho informado."""
        ocultar = self.chk_sanitize.isChecked()
        if self.selected_format() == "json":
            texto = exportar_json(self._inc, ocultar=ocultar)
        else:
            texto = exportar_html(self._inc, ocultar=ocultar)
        salvar_relatorio(Path(destino), texto)
        return Path(destino)

    def choose_and_export(self) -> Path | None:
        if self.exec() != QDialog.DialogCode.Accepted:
            return None
        fmt = self.selected_format()
        ext = "json" if fmt == "json" else "html"
        filtro = "JSON (*.json)" if fmt == "json" else "Página HTML (*.html)"
        sugestao = f"incidente-{self._inc.id[:8]}.{ext}"
        escolhido, _ = QFileDialog.getSaveFileName(self, "Salvar relatório de incidente", sugestao, filtro)
        if not escolhido:
            return None
        destino = Path(escolhido)
        if not destino.suffix:
            destino = destino.with_suffix(f".{ext}")
        return self.export_to(destino)


class IncidentPanel(QWidget):
    """Painel de resposta guiada nas 3 fases (Conter, Neutralizar e Recuperar)."""

    def __init__(
        self,
        store: IncidentStore,
        quarantine: Quarantine,
        *,
        notify: Callable[[str], None] = lambda _: None,
        info: Callable[[str], None] = lambda _: None,
        confirm: Callable[[str], bool] = lambda _: True,
        on_quarantine_changed: Callable[[], None] = lambda: None,
        on_file_quarantined: Callable[[Path], None] = lambda _: None,
        on_full_scan: Callable[[], bool] | None = None,
        on_shred_project: Callable[[Path], None] | None = None,
        on_open_updates: Callable[[], None] | None = None,
        guard_available: Callable[[], bool] = lambda: False,
        resposta_factory: Callable[[IncidentStore, Incidente], Resposta] = Resposta,
        url_opener: Callable[[str], None] | None = None,
    ):
        super().__init__()
        self._store = store
        self._quarantine = quarantine
        self._notify = notify
        self._info = info
        self._confirm = confirm
        self._on_quarantine_changed = on_quarantine_changed
        self._on_file_quarantined = on_file_quarantined
        self._on_full_scan = on_full_scan
        self._on_shred_project = on_shred_project
        self._on_open_updates = on_open_updates
        self.guard_available = guard_available
        self.resposta_factory = resposta_factory
        self.url_opener: Callable[[str], None] = url_opener or (
            lambda u: QDesktopServices.openUrl(QUrl(u))
        )

        self._inc: Incidente | None = None
        self._detected_procs: list[ProcessoInfo] = []
        self._detected_pers: list[Entrada] = []
        self.cred_checkboxes: dict[str, QCheckBox] = {}
        self.cred_link_buttons: dict[str, QPushButton] = {}

        self._build_ui()
        self.reload_list()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(8)

        # Barra superior: seletor de incidentes + atualizar + exportar
        top = QHBoxLayout()
        top.setSpacing(8)
        top.addWidget(QLabel("Incidente:"))
        self.cmb_incidents = QComboBox()
        self.cmb_incidents.currentIndexChanged.connect(self._on_combo_changed)
        top.addWidget(self.cmb_incidents, 1)
        self.btn_refresh = style_button(QPushButton("Atualizar"), "neutral", compact=True)
        self.btn_refresh.clicked.connect(self.refresh)
        self.btn_export = style_button(QPushButton("Exportar relatório…"), "analyze", compact=True)
        self.btn_export.clicked.connect(self.open_export_dialog)
        top.addWidget(self.btn_refresh)
        top.addWidget(self.btn_export)
        outer.addLayout(top)

        # Estado vazio quando ainda não há nenhum incidente salvo
        self.lbl_empty = QLabel(
            "Nenhum incidente registrado até agora. Ao detectar um achado grave em Varredura, "
            "Verificar projeto ou Atualizações, clique em \"Responder\" para iniciar a resposta em cadeia."
        )
        self.lbl_empty.setObjectName("mutedLabel")
        self.lbl_empty.setWordWrap(True)
        outer.addWidget(self.lbl_empty)

        # Área rolável com aviso de projeto, as 3 fases e a linha do tempo
        self.scroll = QScrollArea()
        self.scroll.setObjectName("settingsScroll")
        self.scroll.setWidgetResizable(True)
        body = QWidget()
        self._body_lay = QVBoxLayout(body)
        self._body_lay.setContentsMargins(4, 4, 4, 4)
        self._body_lay.setSpacing(12)

        self.project_warning_bar = QFrame()
        self.project_warning_bar.setObjectName("faixaProjetoAlerta")
        pw_lay = QHBoxLayout(self.project_warning_bar)
        pw_lay.setContentsMargins(10, 8, 10, 8)
        self.lbl_project_warning = QLabel("")
        self.lbl_project_warning.setWordWrap(True)
        pw_lay.addWidget(self.lbl_project_warning, 1)
        self.project_warning_bar.setVisible(False)
        self._body_lay.addWidget(self.project_warning_bar)

        self.lbl_summary = QLabel("")
        self.lbl_summary.setObjectName("mutedLabel")
        self.lbl_summary.setWordWrap(True)
        self._body_lay.addWidget(self.lbl_summary)

        self.phase_conter, self._lay_conter = self._make_phase_card(
            "1. Conter", "Interromper imediatamente a execução e isolar o arquivo suspeito."
        )
        self.phase_neutralizar, self._lay_neutralizar = self._make_phase_card(
            "2. Neutralizar", "Remover pontos de persistência, corrigir vulnerabilidades ou destruir pasta armada."
        )
        self.phase_recuperar, self._lay_recuperar = self._make_phase_card(
            "3. Recuperar", "Varrer o computador por completo, trocar credenciais expostas e exportar o relatório."
        )
        self.timeline_card, self._lay_timeline = self._make_phase_card(
            "Linha do tempo do incidente", "Registro auditável de todas as ações e opções de Desfazer."
        )

        for card in (self.phase_conter, self.phase_neutralizar, self.phase_recuperar, self.timeline_card):
            self._body_lay.addWidget(card)
        self._body_lay.addStretch(1)
        self.scroll.setWidget(body)
        outer.addWidget(self.scroll, 1)

    @staticmethod
    def _make_phase_card(titulo: str, subtitulo: str) -> tuple[QFrame, QVBoxLayout]:
        card = QFrame()
        card.setObjectName("incidentPhaseCard")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(8)
        lbl_t = QLabel(titulo)
        lbl_t.setObjectName("cardTitle")
        lbl_s = QLabel(subtitulo)
        lbl_s.setObjectName("mutedLabel")
        lbl_s.setWordWrap(True)
        lay.addWidget(lbl_t)
        lay.addWidget(lbl_s)
        steps_box = QVBoxLayout()
        steps_box.setSpacing(6)
        lay.addLayout(steps_box)
        return card, steps_box

    @staticmethod
    def _add_step_row(
        parent_lay: QVBoxLayout,
        titulo: str,
        selo: QLabel,
        *,
        descricao: str = "",
        detalhes: list[str] | None = None,
        botoes: list[QPushButton] | None = None,
    ) -> QFrame:
        row = QFrame()
        row.setObjectName("incidentStepRow")
        v = QVBoxLayout(row)
        v.setContentsMargins(0, 8, 0, 4)
        v.setSpacing(4)

        top = QHBoxLayout()
        top.setSpacing(8)
        lbl_t = QLabel(titulo)
        lbl_t.setWordWrap(True)
        lbl_t.setStyleSheet("font-weight: 600;")
        top.addWidget(lbl_t, 1)
        top.addWidget(selo)
        for b in botoes or []:
            b.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
            top.addWidget(b)
        v.addLayout(top)

        if descricao:
            lbl_d = QLabel(descricao)
            lbl_d.setObjectName("mutedLabel")
            lbl_d.setWordWrap(True)
            v.addWidget(lbl_d)

        if detalhes:
            det_lbl = QLabel("\n".join(_visivel(x) for x in detalhes if x))
            det_lbl.setObjectName("incidentDetails")
            det_lbl.setWordWrap(True)
            det_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            det_lbl.setVisible(False)
            btn_det = style_button(QPushButton("Ver detalhes"), "neutral", compact=True)
            btn_det.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)

            def alternar(_checked: bool = False, lb: QLabel = det_lbl, bt: QPushButton = btn_det) -> None:
                vis = not lb.isVisible()
                lb.setVisible(vis)
                bt.setText("Ocultar detalhes" if vis else "Ver detalhes")

            btn_det.clicked.connect(alternar)
            v.addWidget(btn_det)
            v.addWidget(det_lbl)

        parent_lay.addWidget(row)
        return row

    # ---------- estado e navegação ----------
    def current_incident(self) -> Incidente | None:
        return self._inc

    def detected_processes(self) -> list[ProcessoInfo]:
        return list(self._detected_procs)

    def detected_persistence(self) -> list[Entrada]:
        return list(self._detected_pers)

    def _resposta(self, inc: Incidente) -> Resposta:
        return self.resposta_factory(self._store, inc)

    def reload_list(self, select_id: str | None = None) -> None:
        lista = self._store.listar()
        alvo_id = select_id or (self._inc.id if self._inc is not None else None)
        self.cmb_incidents.blockSignals(True)
        self.cmb_incidents.clear()
        idx_escolhido = 0
        for idx, item in enumerate(lista):
            origem = _ORIGEM_ROTULO.get(item.origem, item.origem)
            ameaca = _AMEACA_ROTULO.get(item.ameaca, item.ameaca)
            resumo = _visivel(item.pasta or (item.achados[0].get("caminho", "") if item.achados else item.id[:8]))
            if len(resumo) > 55:
                resumo = "…" + resumo[-54:]
            rotulo = f"{item.criado[:16].replace('T', ' ')} · {origem} ({ameaca}) · {resumo}"
            self.cmb_incidents.addItem(rotulo, item.id)
            if alvo_id and item.id == alvo_id:
                idx_escolhido = idx
        self.cmb_incidents.blockSignals(False)

        if not lista:
            self._inc = None
            self.lbl_empty.setVisible(True)
            self.scroll.setVisible(False)
            self.btn_export.setEnabled(False)
            return

        self.lbl_empty.setVisible(False)
        self.scroll.setVisible(True)
        self.btn_export.setEnabled(True)
        self.cmb_incidents.blockSignals(True)
        self.cmb_incidents.setCurrentIndex(idx_escolhido)
        self.cmb_incidents.blockSignals(False)
        escolhido_id = str(self.cmb_incidents.itemData(idx_escolhido))
        self.load_incident(escolhido_id, update_combo=False)

    def _on_combo_changed(self, index: int) -> None:
        if index < 0:
            return
        inc_id = self.cmb_incidents.itemData(index)
        if isinstance(inc_id, str) and inc_id:
            self.load_incident(inc_id, update_combo=False)

    def load_incident(self, inc_id: str, *, update_combo: bool = True) -> None:
        try:
            self._inc = self._store.carregar(inc_id)
        except IncidentError as e:
            self._notify(str(e))
            return
        if update_combo:
            self.reload_list(select_id=inc_id)
            return
        self._render_current()

    def refresh(self) -> None:
        if self._inc is None:
            self.reload_list()
            return
        self.reload_list(select_id=self._inc.id)

    def show_guard_instructions(self) -> None:
        self._info(_INSTRUCOES_GUARD)

    def open_export_dialog(self) -> Path | None:
        if self._inc is None:
            return None
        dlg = ExportIncidentDialog(self._inc, parent=self)
        try:
            salvo = dlg.choose_and_export()
        except IncidentError as e:
            self._notify(str(e))
            return None
        if salvo is not None:
            self._info(f"Relatório exportado em:\n{_visivel(str(salvo))}")
        return salvo

    # ---------- ações das fases ----------
    def kill_process_step(self, pid: int, exe: str, sha256: str) -> Acao:
        assert self._inc is not None
        acao = self._resposta(self._inc).encerrar_processo(pid, exe, sha256, modo="guiada")
        if acao.resultado == "falhou":
            self._notify(acao.detalhe)
        self._render_current()
        return acao

    def quarantine_file_step(self, path: Path, sha256: str, sev_name: str, rules: list[str]) -> Acao:
        assert self._inc is not None
        sev = Severity[sev_name] if sev_name in Severity.__members__ else Severity.HIGH
        alerts = [Alert(r, sev, r) for r in (rules or ["incidente.arquivo"])]
        acao = Acao(
            tipo="quarentena_arquivo",
            fase="conter",
            modo="guiada",
            resultado="em_andamento",
            detalhe="",
            alvo={"caminho": str(path), "sha256": sha256},
            data=agora(),
        )
        try:
            self._store.registrar(self._inc, acao)
        except IncidentError as e:
            if self._inc.acoes and self._inc.acoes[-1] is acao:
                self._inc.acoes.pop()
            acao.resultado, acao.detalhe = "falhou", f"{e} Nada foi feito."
            self._notify(acao.detalhe)
            return acao

        try:
            qid = self._quarantine.add(Finding(path=Path(path), sha256=sha256, severity=sev, alerts=alerts))
        except QuarantineError as e:
            acao.resultado, acao.detalhe = "falhou", str(e)
            try:
                self._store.salvar(self._inc)
            except IncidentError:
                pass
            self._notify(str(e))
            self._render_current()
            return acao

        acao.alvo["quarantine_id"] = qid
        acao.backup = {"tipo": "quarantine", "quarantine_id": qid}
        acao.resultado = "concluida"
        acao.detalhe = "Arquivo movido para a quarentena; dá para desfazer."
        try:
            self._store.salvar(self._inc)
        except IncidentError as e:
            acao.detalhe += f" Aviso: {e}"
        self._on_file_quarantined(Path(path))
        self._on_quarantine_changed()
        self._render_current()
        return acao

    def remove_persistence_step(self, entrada: Entrada) -> Acao:
        assert self._inc is not None
        acao = self._resposta(self._inc).remover_persistencia(entrada, modo="guiada")
        if acao.resultado == "falhou":
            self._notify(acao.detalhe)
        self._render_current()
        return acao

    def undo_action_step(self, indice: int) -> Acao:
        assert self._inc is not None
        orig = self._inc.acoes[indice] if 0 <= indice < len(self._inc.acoes) else None
        if orig is not None and orig.tipo == "quarentena_arquivo":
            nova = Acao(
                tipo="desfazer",
                fase="conter",
                modo="guiada",
                resultado="em_andamento",
                detalhe="",
                alvo={"indice": indice, **orig.alvo},
                data=agora(),
            )
            try:
                self._store.registrar(self._inc, nova)
            except IncidentError as e:
                if self._inc.acoes and self._inc.acoes[-1] is nova:
                    self._inc.acoes.pop()
                nova.resultado, nova.detalhe = "falhou", str(e)
                self._notify(nova.detalhe)
                return nova
            if orig.desfeita or orig.resultado != "concluida" or not orig.alvo.get("quarantine_id"):
                nova.resultado = "falhou"
                nova.detalhe = "Esta ação já foi desfeita." if orig.desfeita else "Esta ação não pode ser desfeita."
                self._store.salvar(self._inc)
                self._notify(nova.detalhe)
                self._render_current()
                return nova
            try:
                dest = self._quarantine.restore(str(orig.alvo["quarantine_id"]))
            except QuarantineError as e:
                nova.resultado, nova.detalhe = "falhou", str(e)
                self._store.salvar(self._inc)
                self._notify(str(e))
                self._render_current()
                return nova
            orig.desfeita = True
            nova.resultado = "concluida"
            nova.detalhe = f"Arquivo restaurado em {_visivel(str(dest))}."
            self._store.salvar(self._inc)
            self._on_quarantine_changed()
            self._render_current()
            return nova

        acao = self._resposta(self._inc).desfazer(indice)
        if acao.resultado == "falhou":
            self._notify(acao.detalhe)
        self._render_current()
        return acao

    def _trigger_full_scan(self) -> None:
        if self._inc is None or self._on_full_scan is None:
            return
        iniciou = self._on_full_scan()
        if not iniciou:
            self._notify("Já há uma varredura em andamento ou nenhuma pasta disponível.")
            return
        try:
            self._store.registrar(
                self._inc,
                Acao(
                    tipo="varredura_completa",
                    fase="recuperar",
                    modo="guiada",
                    resultado="concluida",
                    detalhe="Varredura completa em lotes iniciada na aba Varredura.",
                    alvo={},
                    data=agora(),
                ),
            )
        except IncidentError:
            pass
        self._render_current()

    def _trigger_shred_project(self, pasta: Path) -> None:
        if self._inc is None or self._on_shred_project is None:
            return
        self._on_shred_project(pasta)
        self._render_current()

    def _toggle_credential(self, item_id: str, checked: bool) -> None:
        if self._inc is None:
            return
        try:
            self._resposta(self._inc).marcar_credencial(item_id, checked)
        except IncidentError as e:
            self._notify(str(e))

    # ---------- renderização das 3 fases ----------
    def _render_current(self) -> None:
        inc = self._inc
        if inc is None:
            return

        eh_projeto = inc.origem == "projeto" or inc.ameaca == "projeto"
        if eh_projeto:
            nome_proj = _visivel(Path(inc.pasta).name if inc.pasta else "projeto")
            self.lbl_project_warning.setText(f"Atenção ({nome_proj}): {_AVISO_PROJETO_FIXO}")
            self.project_warning_bar.setVisible(True)
        else:
            self.project_warning_bar.setVisible(False)

        origem = _ORIGEM_ROTULO.get(inc.origem, inc.origem)
        ameaca = _AMEACA_ROTULO.get(inc.ameaca, inc.ameaca)
        self.lbl_summary.setText(
            f"ID {inc.id[:12]}… · Origem: {origem} · Tipo: {ameaca} · "
            f"{len(inc.achados)} achado(s) · Aberto em {inc.criado.replace('T', ' ')}"
        )

        resp = self._resposta(inc)
        self._detected_procs = resp.detectar_processos()
        self._detected_pers = resp.detectar_persistencia()
        tem_guard = bool(self.guard_available())

        self._render_conter(inc, tem_guard)
        self._render_neutralizar(inc, tem_guard)
        self._render_recuperar(inc)
        self._render_timeline(inc)

    def _render_conter(self, inc: Incidente, tem_guard: bool) -> None:
        _limpar_layout(self._lay_conter)
        sha_padrao = next(
            (str(a["sha256"]) for a in inc.achados if isinstance(a.get("sha256"), str) and len(a["sha256"]) == 64),
            "",
        )

        # 1. Processos suspeitos em execução
        if self._detected_procs:
            for proc in self._detected_procs:
                sha_proc = sha_padrao
                if proc.exe:
                    from mandacaru_win.incident import sha256_arquivo

                    sha_disco = sha256_arquivo(Path(proc.exe))
                    if sha_disco:
                        sha_proc = sha_disco
                btn_kill = style_button(QPushButton("Encerrar processo"), "danger", compact=True)
                if not sha_proc or not proc.exe:
                    btn_kill.setEnabled(False)
                    btn_kill.setToolTip("Não foi possível confirmar o caminho/SHA-256 deste processo.")
                else:
                    btn_kill.clicked.connect(
                        lambda _=False, pid=proc.pid, ex=proc.exe, sh=sha_proc: self.kill_process_step(pid, ex, sh)
                    )
                self._add_step_row(
                    self._lay_conter,
                    f"Encerrar processo ativo (PID {proc.pid})",
                    _criar_selo("pending", "Pendente"),
                    descricao=_visivel(Path(proc.exe).name if proc.exe else f"PID {proc.pid}"),
                    detalhes=[f"PID: {proc.pid}", f"Executável: {proc.exe or 'desconhecido'}", f"SHA-256: {sha_proc}"],
                    botoes=[btn_kill],
                )
        else:
            ja_encerrou = next(
                (a for a in reversed(inc.acoes) if a.tipo == "encerrar_processo" and a.resultado == "concluida"),
                None,
            )
            selo_proc = _selo_da_acao(ja_encerrou) if ja_encerrou else _criar_selo("done", "Concluído")
            desc_proc = (
                ja_encerrou.detalhe
                if ja_encerrou
                else "Nenhum processo suspeito ativo encontrado na sessão do seu usuário."
            )
            self._add_step_row(
                self._lay_conter,
                "Processos do usuário ligados ao incidente",
                selo_proc,
                descricao=desc_proc,
            )

        # 2. Quarentena por arquivo suspeito do incidente
        arqs_vistos: set[str] = set()
        for ach in inc.achados:
            caminho = ach.get("caminho")
            sha = ach.get("sha256")
            regra = str(ach.get("regra") or "incidente.arquivo")
            if not isinstance(caminho, str) or not isinstance(sha, str) or len(sha) != 64:
                continue
            if regra.startswith("projeto.dep."):
                continue
            if caminho in arqs_vistos:
                continue
            arqs_vistos.add(caminho)
            p = Path(caminho)
            idx_q = next(
                (
                    i
                    for i, a in enumerate(inc.acoes)
                    if a.tipo == "quarentena_arquivo"
                    and a.alvo.get("caminho") == str(p)
                    and a.resultado == "concluida"
                    and not a.desfeita
                ),
                None,
            )
            if idx_q is not None:
                acao_q = inc.acoes[idx_q]
                btn_undo = style_button(QPushButton("Desfazer"), "neutral", compact=True)
                btn_undo.clicked.connect(lambda _=False, i=idx_q: self.undo_action_step(i))
                self._add_step_row(
                    self._lay_conter,
                    f"Arquivo em quarentena: {_visivel(p.name or str(p))}",
                    _selo_da_acao(acao_q),
                    descricao=acao_q.detalhe,
                    detalhes=[f"Caminho: {p}", f"SHA-256: {sha}", f"Regra: {regra}"],
                    botoes=[btn_undo],
                )
            elif p.exists():
                btn_q = style_button(QPushButton("Colocar em quarentena"), "quarantine", compact=True)
                sev_nome = str(ach.get("severidade") or "HIGH")
                btn_q.clicked.connect(
                    lambda _=False, al=p, sh=sha, sv=sev_nome, rg=regra: self.quarantine_file_step(al, sh, sv, [rg])
                )
                self._add_step_row(
                    self._lay_conter,
                    f"Isolar arquivo suspeito: {_visivel(p.name)}",
                    _criar_selo("pending", "Pendente"),
                    descricao="Move o arquivo embaralhado para a Quarentena (reversível com Desfazer).",
                    detalhes=[f"Caminho: {p}", f"SHA-256: {sha}", f"Regra: {regra}"],
                    botoes=[btn_q],
                )

        # 3. Bloqueio de saída no Firewall (serviço Proteção avançada)
        if not tem_guard:
            btn_fw = style_button(QPushButton("Bloquear rede"), "neutral", compact=True)
            btn_fw.setEnabled(False)
            btn_fw.setToolTip("Disponível ao instalar o serviço opcional Proteção avançada.")
            btn_como = style_button(QPushButton("Como ativar"), "neutral", compact=True)
            btn_como.clicked.connect(self.show_guard_instructions)
            self._add_step_row(
                self._lay_conter,
                f"Bloquear conexões de saída do executável (regra Mandacaru-{inc.id[:8]})",
                _criar_selo("admin", "Requer Proteção avançada"),
                descricao="Cria regra reversível no Firewall do Windows para cortar comunicação externa do binário.",
                botoes=[btn_fw, btn_como],
            )

        # 4. Orientação manual de desconexão em casos graves
        self._add_step_row(
            self._lay_conter,
            "Isolamento manual da rede (casos críticos)",
            _criar_selo("done", "Orientação"),
            descricao=(
                "Se notar criptografia em massa ou tráfego suspeito contínuo, desconecte imediatamente "
                "o Wi-Fi ou puxe o cabo de rede antes de continuar."
            ),
        )

    def _render_neutralizar(self, inc: Incidente, tem_guard: bool) -> None:
        _limpar_layout(self._lay_neutralizar)

        # 1. Entradas de persistência atualmente ativas
        for ent in self._detected_pers:
            detalhes = [f"Tipo: {ent.tipo}", f"Local: {ent.local}", f"Nome: {ent.nome}", f"Comando: {ent.comando}"]
            if ent.exige_servico and not tem_guard:
                btn_dis = style_button(QPushButton("Remover"), "neutral", compact=True)
                btn_dis.setEnabled(False)
                btn_como = style_button(QPushButton("Como ativar"), "neutral", compact=True)
                btn_como.clicked.connect(self.show_guard_instructions)
                self._add_step_row(
                    self._lay_neutralizar,
                    f"Persistência do sistema: {_visivel(ent.nome)}",
                    _criar_selo("admin", "Requer Proteção avançada"),
                    descricao=_visivel(ent.local),
                    detalhes=detalhes,
                    botoes=[btn_dis, btn_como],
                )
            else:
                btn_rem = style_button(QPushButton("Remover persistência"), "quarantine", compact=True)
                btn_rem.clicked.connect(lambda _=False, e=ent: self.remove_persistence_step(e))
                self._add_step_row(
                    self._lay_neutralizar,
                    f"Persistência encontrada: {_visivel(ent.nome)}",
                    _criar_selo("pending", "Pendente"),
                    descricao=f"{_visivel(ent.local)} — backup salvo antes de remover.",
                    detalhes=detalhes,
                    botoes=[btn_rem],
                )

        # 2. Entradas já removidas neste incidente (com opção Desfazer)
        for idx, acao in enumerate(inc.acoes):
            if acao.tipo != "remover_persistencia" or acao.resultado != "concluida":
                continue
            nome = _visivel(acao.alvo.get("nome", "entrada"))
            botoes_hist: list[QPushButton] = []
            if not acao.desfeita and acao.backup is not None:
                btn_u = style_button(QPushButton("Desfazer"), "neutral", compact=True)
                btn_u.clicked.connect(lambda _=False, i=idx: self.undo_action_step(i))
                botoes_hist.append(btn_u)
            self._add_step_row(
                self._lay_neutralizar,
                f"Persistência removida: {nome}",
                _selo_da_acao(acao),
                descricao=_visivel(acao.detalhe),
                detalhes=[f"{k}: {v}" for k, v in acao.alvo.items()],
                botoes=botoes_hist,
            )

        if not self._detected_pers and not any(a.tipo == "remover_persistencia" for a in inc.acoes):
            self._add_step_row(
                self._lay_neutralizar,
                "Persistência do usuário (HKCU Run/RunOnce, Inicializar e Tarefas do usuário)",
                _criar_selo("done", "Concluído"),
                descricao="Nenhuma entrada automática do usuário ligada a este incidente foi encontrada.",
            )

        if not tem_guard:
            btn_como = style_button(QPushButton("Como ativar"), "neutral", compact=True)
            btn_como.clicked.connect(self.show_guard_instructions)
            self._add_step_row(
                self._lay_neutralizar,
                "Persistência global do sistema (HKLM Run/RunOnce e Serviços do Windows)",
                _criar_selo("admin", "Requer Proteção avançada"),
                descricao="A remoção em chaves HKLM e Serviços do Windows exige o serviço Proteção avançada.",
                botoes=[btn_como],
            )

        # 3. Ação específica de projeto armado: Destruir projeto...
        if inc.pasta and (inc.ameaca == "projeto" or inc.origem == "projeto") and self._on_shred_project is not None:
            pasta_p = Path(inc.pasta)
            existe = pasta_p.exists()
            btn_shred = style_button(QPushButton("Destruir projeto…"), "danger", compact=True)
            btn_shred.setEnabled(existe)
            btn_shred.clicked.connect(lambda _=False, p=pasta_p: self._trigger_shred_project(p))
            self._add_step_row(
                self._lay_neutralizar,
                f"Destruir pasta do projeto: {_visivel(pasta_p.name or str(pasta_p))}",
                _criar_selo("pending", "Pendente") if existe else _criar_selo("done", "Concluído"),
                descricao=(
                    "Sobrescreve com dados aleatórios e apaga a pasta inteira sem passar pela Lixeira."
                    if existe
                    else "A pasta do projeto já não está mais no disco."
                ),
                detalhes=[f"Pasta: {pasta_p}"],
                botoes=[btn_shred] if existe else [],
            )

        # 4. Ação específica de vulnerabilidade: ir para Atualizações (winget)
        if (inc.ameaca == "vulnerabilidade" or inc.origem == "atualizacoes") and self._on_open_updates is not None:
            btn_upd = style_button(QPushButton("Ir para Atualizações (winget)"), "scan", compact=True)
            btn_upd.clicked.connect(self._on_open_updates)
            self._add_step_row(
                self._lay_neutralizar,
                "Atualizar programa vulnerável",
                _criar_selo("pending", "Pendente"),
                descricao="Aplique a versão corrigida na aba Atualizações para fechar a brecha explorável.",
                botoes=[btn_upd],
            )

    def _render_recuperar(self, inc: Incidente) -> None:
        _limpar_layout(self._lay_recuperar)
        self.cred_checkboxes.clear()
        self.cred_link_buttons.clear()

        # 1. Varredura completa em lotes leves
        fez_scan = any(a.tipo == "varredura_completa" and a.resultado == "concluida" for a in inc.acoes)
        botoes_scan: list[QPushButton] = []
        if self._on_full_scan is not None:
            btn_scan = style_button(QPushButton("Iniciar varredura completa (em lotes)"), "scan", compact=True)
            btn_scan.clicked.connect(self._trigger_full_scan)
            botoes_scan.append(btn_scan)
        self._add_step_row(
            self._lay_recuperar,
            "Varredura completa da pasta do usuário (em lotes leves)",
            _criar_selo("done", "Concluído") if fez_scan else _criar_selo("pending", "Recomendado"),
            descricao="Procura outros artefatos deixados no perfil sem travar o computador.",
            botoes=botoes_scan,
        )

        # 2. Checklist marcável de credenciais + links oficiais sob clique
        cred_box = QFrame()
        cred_box.setObjectName("incidentStepRow")
        cv = QVBoxLayout(cred_box)
        cv.setContentsMargins(0, 8, 0, 4)
        cv.setSpacing(6)
        lbl_c = QLabel("Checklist de credenciais para trocar (o progresso fica salvo neste incidente):")
        lbl_c.setStyleSheet("font-weight: 600;")
        lbl_c.setWordWrap(True)
        cv.addWidget(lbl_c)

        try:
            itens = montar_checklist(inc.ameaca)
        except IncidentError:
            itens = []

        for item in itens:
            linha = QHBoxLayout()
            linha.setSpacing(8)
            chk = QCheckBox(item.texto + ("  [prioritário]" if item.destaque else ""))
            chk.setChecked(bool(inc.credenciais.get(item.id, False)))
            if item.destaque:
                chk.setStyleSheet("font-weight: 600;")
            chk.toggled.connect(lambda marcado, iid=item.id: self._toggle_credential(iid, marcado))
            self.cred_checkboxes[item.id] = chk
            linha.addWidget(chk, 1)

            link = url_oficial(item.id)
            if link is not None:
                btn_link = style_button(QPushButton("Abrir página"), "neutral", compact=True)
                btn_link.setToolTip(link)
                btn_link.clicked.connect(lambda _=False, u=link: self.url_opener(u))
                self.cred_link_buttons[item.id] = btn_link
                linha.addWidget(btn_link)
            cv.addLayout(linha)

        lbl_ext = QLabel(
            "Dica adicional: revise também as extensões instaladas nos seus navegadores e remova qualquer "
            "extensão desconhecida. O Mandacaru nunca lê seus arquivos .env, chaves privadas ou cookies."
        )
        lbl_ext.setObjectName("mutedLabel")
        lbl_ext.setWordWrap(True)
        cv.addWidget(lbl_ext)
        self._lay_recuperar.addWidget(cred_box)

        # 3. Exportar relatório
        btn_exp = style_button(QPushButton("Exportar relatório…"), "analyze", compact=True)
        btn_exp.clicked.connect(self.open_export_dialog)
        self._add_step_row(
            self._lay_recuperar,
            "Relatório do incidente (HTML autocontido ou JSON)",
            _criar_selo("done", "Pronto"),
            descricao="Oculta nome de usuário, computador e caminhos pessoais por padrão.",
            botoes=[btn_exp],
        )

    def _render_timeline(self, inc: Incidente) -> None:
        _limpar_layout(self._lay_timeline)
        if not inc.acoes:
            lbl = QLabel("Nenhuma ação executada neste incidente ainda.")
            lbl.setObjectName("mutedLabel")
            self._lay_timeline.addWidget(lbl)
            return

        for idx, acao in enumerate(inc.acoes):
            nome = _ACAO_ROTULO.get(acao.tipo, acao.tipo)
            data_curta = acao.data[:19].replace("T", " ")
            botoes: list[QPushButton] = []
            pode_desfazer = (
                not acao.desfeita
                and acao.resultado == "concluida"
                and (acao.backup is not None or acao.tipo == "quarentena_arquivo")
            )
            if pode_desfazer:
                btn_u = style_button(QPushButton("Desfazer"), "neutral", compact=True)
                btn_u.clicked.connect(lambda _=False, i=idx: self.undo_action_step(i))
                botoes.append(btn_u)
            self._add_step_row(
                self._lay_timeline,
                f"{data_curta} · {nome}",
                _selo_da_acao(acao),
                descricao=_visivel(acao.detalhe),
                detalhes=[f"{k}: {v}" for k, v in acao.alvo.items()],
                botoes=botoes,
            )
