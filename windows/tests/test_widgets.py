"""Testes dos componentes visuais leves (MandacaruProgressBar)."""
import pytest

pytest.importorskip("PySide6")

from mandacaru_win.widgets import MandacaruProgressBar  # noqa: E402
from PySide6.QtGui import QColor, QPalette  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def test_progress_bar_timer_runs_only_when_indeterminate_and_visible(app):
    bar = MandacaruProgressBar()
    bar.resize(300, 18)
    bar.setRange(0, 100)
    bar.setValue(40)
    assert not bar._timer.isActive()

    # Indeterminada mas oculta: timer continua desligado (zero CPU)
    bar.setRange(0, 0)
    assert not bar._timer.isActive()

    # Visível e indeterminada: timer liga
    bar.show()
    assert bar._timer.isActive()

    # Voltou para determinada: timer desliga na hora
    bar.setRange(0, 100)
    bar.setValue(60)
    assert not bar._timer.isActive()

    # Ocultou enquanto indeterminada: timer desliga
    bar.setRange(0, 0)
    assert bar._timer.isActive()
    bar.hide()
    assert not bar._timer.isActive()
    bar.close()


def test_progress_bar_tones_and_painting_light_and_dark(app):
    bar = MandacaruProgressBar()
    bar.resize(320, 18)
    bar.show()

    for bg in ("#f5f5f5", "#1e1e1e"):
        pal = bar.palette()
        pal.setColor(QPalette.ColorRole.Window, QColor(bg))
        bar.setPalette(pal)
        for tone in ("normal", "shred", "warning", "error"):
            bar.set_tone(tone)
            assert bar.tone == tone
            bar.setRange(0, 0)
            bar._tick()
            assert not bar.grab().isNull()
            bar.setRange(0, 100)
            for val in (0, 25, 75, 100):
                bar.setValue(val)
                assert not bar.grab().isNull()

    # Tom desconhecido volta ao padrão
    bar.set_tone("invalido")
    assert bar.tone == "normal"
    bar.close()


def test_badge_delegate_and_theme_light_and_dark(app, tmp_path, scanner):
    from mandacaru_win.app import MainWindow
    from mandacaru_win.theme import build_stylesheet
    from mandacaru_win.widgets import BadgeDelegate
    from PySide6.QtWidgets import QTableWidget, QTableWidgetItem

    assert 'role="scan"' in build_stylesheet(False)
    assert 'role="analyze"' in build_stylesheet(True)
    assert 'role="quarantine"' in build_stylesheet(True)
    assert 'role="danger"' in build_stylesheet(False)
    assert "#faixaProjetoAlerta" in build_stylesheet(False)
    assert "#faixaProjetoAlerta" in build_stylesheet(True)

    tbl = QTableWidget(5, 1)
    tbl.setItemDelegateForColumn(0, BadgeDelegate(tbl))
    for i, label in enumerate(("Crítica", "Alta", "Média", "Baixa", "Explorada")):
        tbl.setItem(i, 0, QTableWidgetItem(label))
    tbl.resize(200, 180)
    tbl.show()
    for bg in ("#ffffff", "#1e1e1e"):
        pal = tbl.palette()
        pal.setColor(QPalette.ColorRole.Base, QColor(bg))
        tbl.setPalette(pal)
        assert not tbl.grab().isNull()
    tbl.close()

    win = MainWindow(tmp_path / "dados", scanner)
    try:
        assert win.btn_downloads.property("role") == "scan"
        assert win.btn_shred.property("role") == "danger"
        assert win.btn_shred_project.property("role") == "danger"
        assert win.btn_stop.property("role") == "danger"
        assert isinstance(win.tree.itemDelegateForColumn(0), BadgeDelegate)
        assert isinstance(win.tbl_quarantine.itemDelegateForColumn(2), BadgeDelegate)
        assert isinstance(win.tbl_updates.itemDelegateForColumn(3), BadgeDelegate)
        assert win.styleSheet()
    finally:
        win.close()
