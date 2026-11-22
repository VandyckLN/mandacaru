"""Aba Atualizações da janela principal (serviço falso: nada de winget/rede)."""
import time

import pytest

pytest.importorskip("PySide6")

from mandacaru_win.app import MainWindow  # noqa: E402
from mandacaru_win.store import History  # noqa: E402
from mandacaru_win.updates import (  # noqa: E402
    APP_INSTALLER_URI,
    EXPLORADA_PRODUTO,
    SUSPEITA,
    WINDOWS_UPDATE_URI,
    ApplyResult,
    Assessment,
    CheckResult,
    Program,
    WindowsUpdates,
    WingetUnavailable,
)
from PySide6.QtCore import QCoreApplication, QEvent, Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QTabWidget  # noqa: E402

_windows: list = []

P7 = Program("7-Zip 22.01 (x64)", "7zip.7zip", "22.01", "24.08", "winget")
PX = Program("Programa Parecido", "Fulano.Parecido", "1.0", "2.0", "winget")
PF = Program("Mozilla Firefox", "Mozilla.Firefox", "118.0", "133.0", "winget")


@pytest.fixture(scope="session")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _close_windows():
    yield
    while _windows:
        w = _windows.pop()
        w._apply_thread = None
        w.close()
        w.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


class FakeService:
    def __init__(self, error=None, apply_status=None):
        self.error = error
        self.applied = []
        self.apply_status = apply_status or {}
        self.calls = []

    def _result(self, complete):
        items = [Assessment(P7, EXPLORADA_PRODUTO, "falhas usadas em ataques", True, kev_cves=("CVE-2025-0411",)),
                 Assessment(PF, EXPLORADA_PRODUTO, "idem", True),
                 Assessment(PX, SUSPEITA, "nome parecido", False)]
        wu = WindowsUpdates(True, 3, 1, ["KB1 segurança", "Driver", "Outro"]) if complete else None
        return CheckResult(items, complete, "winget upgrade", ["1 programa(s) não puderam ser lidos."], wu)

    def quick(self, on_progress=None, should_stop=None):
        self.calls.append("quick")
        on_progress("Listando…", 0, 0)
        if self.error:
            raise self.error
        return self._result(False)

    def complete(self, on_progress=None, should_stop=None):
        self.calls.append("complete")
        return self._result(True)

    def apply(self, programs, on_result=None, should_stop=None, on_start=None):
        out = []
        for p in programs:
            on_start(p)
            self.applied.append(p.id)
            status = self.apply_status.get(p.id, "ok")
            r = ApplyResult(p.id, p.name, status, "mensagem " + status)
            on_result(r)
            out.append(r)
        return out


def make_win(tmp_path, service):
    win = MainWindow(tmp_path / "dados", scanner=object())
    _windows.append(win)
    win.msgs, win.asked = [], []
    win.answer = True
    win.confirm = lambda t: (win.asked.append(t), win.answer)[1]
    win.notify = win.msgs.append
    win.updates_service = service
    return win


def wait_until(cond, timeout=10.0):
    end = time.monotonic() + timeout
    while not cond() and time.monotonic() < end:
        QApplication.processEvents()
        time.sleep(0.005)
    QApplication.processEvents()
    assert cond()


def run_check(win, complete=False):
    win.start_update_check(complete)
    wait_until(lambda: win._upd_thread is None)


def test_tab_exists_and_quick_check_fills_table(app, tmp_path):
    win = make_win(tmp_path, FakeService())
    # a faixa de autoatualizacao envolve as abas: procura o QTabWidget em vez de usar centralWidget()
    tabs = win.findChild(QTabWidget)
    assert "Atualizações" in [tabs.tabText(i) for i in range(tabs.count())]
    assert not win.btn_upd_apply.isEnabled()
    run_check(win)
    t = win.tbl_updates
    assert t.rowCount() == 3
    assert [t.item(r, 1).text() for r in range(3)] == [P7.name, PF.name, PX.name]
    assert t.item(0, 2).text() == "22.01 → 24.08" and t.item(0, 3).text() == EXPLORADA_PRODUTO
    assert t.item(0, 3).toolTip() == "falhas usadas em ataques" and t.item(0, 1).toolTip() == "7zip.7zip"
    assert win.checked_updates() == [0, 1]   # suspeita não vem marcada
    assert "não puderam ser lidos" in win.lbl_upd.text()
    assert win.lbl_wu.isHidden() and win.btn_upd_apply.isEnabled()


def test_complete_check_shows_windows_update(app, tmp_path):
    svc = FakeService()
    win = make_win(tmp_path, svc)
    run_check(win, complete=True)
    assert svc.calls == ["complete"]
    assert not win.lbl_wu.isHidden() and "3 atualização(ões)" in win.lbl_wu.text()
    assert "1 de segurança" in win.lbl_wu.text() and "KB1" in win.lbl_wu.toolTip()


def test_missing_winget_offers_store(app, tmp_path, monkeypatch):
    opened = []
    monkeypatch.setattr(MainWindow, "_open_uri", staticmethod(opened.append))
    win = make_win(tmp_path, FakeService(error=WingetUnavailable("sem winget")))
    run_check(win)
    assert "Instalador de Aplicativo" in win.lbl_upd.text() and not win.btn_get_winget.isHidden()
    win.btn_get_winget.click()
    win.btn_open_wu.click()
    assert opened == [APP_INSTALLER_URI, WINDOWS_UPDATE_URI]
    assert win.btn_upd_quick.isEnabled() and win.tbl_updates.rowCount() == 0


def test_apply_selected_warns_uac_runs_only_checked_and_logs_history(app, tmp_path):
    svc = FakeService(apply_status={"Mozilla.Firefox": "fechar"})
    win = make_win(tmp_path, svc)
    run_check(win)
    win.tbl_updates.item(2, 0).setCheckState(Qt.CheckState.Checked)     # marca a suspeita
    win.tbl_updates.item(0, 0).setCheckState(Qt.CheckState.Unchecked)   # desmarca o 7-Zip
    win.apply_selected_updates()
    assert "UAC" in win.asked[0] and "Mozilla Firefox" in win.asked[0] and "7-Zip" not in win.asked[0]
    wait_until(lambda: win._apply_thread is None)
    assert svc.applied == ["Mozilla.Firefox", "Fulano.Parecido"]
    t = win.tbl_updates
    assert t.item(1, 4).text() == "Feche o programa" and t.item(2, 4).text() == "Atualizado"
    assert t.item(0, 4).text() == ""
    assert t.item(2, 0).checkState() == Qt.CheckState.Unchecked   # o que deu certo é desmarcado
    assert "1 de 2" in win.lbl_upd.text() and "Feche os programas" in win.lbl_upd.text()
    row = History(tmp_path / "dados" / "history.jsonl").recent()[0]
    assert row["tipo"] == "atualizacao"
    assert [(p["id"], p["de"], p["para"], p["resultado"]) for p in row["programas"]] == [
        ("Mozilla.Firefox", "118.0", "133.0", "fechar"), ("Fulano.Parecido", "1.0", "2.0", "ok")]
    assert win.tbl_history.item(0, 1).text().startswith("Atualização: Mozilla Firefox (Feche o programa)")
    assert win.tbl_history.item(0, 5).text() == "1 de 2 atualizado(s)"


def test_apply_declined_or_empty_does_nothing(app, tmp_path):
    svc = FakeService()
    win = make_win(tmp_path, svc)
    run_check(win)
    win.answer = False
    win.apply_selected_updates()
    assert svc.applied == [] and win._apply_thread is None
    for r in range(3):
        win.tbl_updates.item(r, 0).setCheckState(Qt.CheckState.Unchecked)
    win.answer = True
    win.apply_selected_updates()
    assert svc.applied == [] and win.msgs == ["Marque ao menos um programa para atualizar."]


def test_close_is_refused_while_applying(app, tmp_path):
    win = make_win(tmp_path, FakeService())
    win._apply_thread = object()  # simula instalador rodando
    assert win.close() is False and "Aguarde" in win.msgs[0]
    win._apply_thread = None
    assert win.close() is True
