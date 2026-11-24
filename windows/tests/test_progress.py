"""Frase completa nas barras de progresso ("Verificando 1.234 de 2.900 arquivos · 42% · cerca de 1 min")."""
import pytest

pytest.importorskip("PySide6")

from mandacaru_win import progress as pg  # noqa: E402
from mandacaru_win import widgets  # noqa: E402
from mandacaru_win.app import MainWindow  # noqa: E402
from mandacaru_win.scan import ScanSummary  # noqa: E402
from mandacaru_win.shred import ShredSummary  # noqa: E402
from mandacaru_win.update_ui import UpdateBar  # noqa: E402
from mandacaru_win.widgets import MandacaruProgressBar  # noqa: E402
from mandacaru_win.worker import ScanThread  # noqa: E402
from PySide6.QtCore import QCoreApplication, QEvent, QEventLoop, QTimer  # noqa: E402
from PySide6.QtGui import QColor, QPalette  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

_widgets: list = []
MB = 1024 * 1024


@pytest.fixture(scope="session")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _close_widgets():
    yield
    while _widgets:
        w = _widgets.pop()
        w.close()
        w.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def keep(w):
    _widgets.append(w)
    return w


def make_win(tmp_path, scanner):
    win = keep(MainWindow(tmp_path / "dados", scanner))
    win.msgs = []
    win.notify = win.msgs.append
    win.info = win.msgs.append
    win.confirm = lambda _: True
    return win


# ---------- textos ----------
def test_fmt_int_uses_brazilian_thousands_separator():
    assert [pg.fmt_int(n) for n in (0, 999, 1234, 1234567)] == ["0", "999", "1.234", "1.234.567"]


@pytest.mark.parametrize("elapsed, done, total, expected", [
    (10, 0, 100, ""),            # nada feito ainda
    (2, 50, 100, ""),            # cedo demais para estimar
    (30, 100, 100, ""),          # acabou
    (10, 50, 100, "menos de 1 min"),
    (60, 50, 100, "cerca de 1 min"),
    (300, 50, 100, "cerca de 5 min"),
    (3600, 50, 100, "cerca de 1 h"),
    (5400, 50, 100, "cerca de 1 h 30 min"),
])
def test_eta_text(elapsed, done, total, expected):
    assert pg.eta_text(elapsed, done, total) == expected


def test_scan_text_matches_the_agreed_phrase():
    assert (pg.scan_text(1234, 2900, "cerca de 1 min")
            == "Verificando 1.234 de 2.900 arquivos · 42% · cerca de 1 min")
    assert pg.scan_text(0, 1) == "Verificando 0 de 1 arquivo · 0%"
    assert pg.scan_text(5, 0) == "Verificando 5 de 0 arquivos · 0%"  # total zerado não divide por zero


def test_done_shred_count_and_download_texts():
    assert pg.scan_done_text(2900, 2900, True) == "Concluída · 2.900 arquivos verificados"
    assert pg.scan_done_text(1, 1, True) == "Concluída · 1 arquivo verificado"
    assert pg.scan_done_text(1, 3, False) == "Interrompida · 1 de 3 arquivos verificados"
    assert pg.scan_done_text(0, 0, False) == "Interrompida"
    assert pg.shred_text(3, 10) == "Destruindo 3 de 10 arquivos · 30%"
    assert pg.count_text(3, 20, "programas") == "3 de 20 programas · 15%"
    assert pg.download_text(31 * MB, 74 * MB) == "41% · 31 de 74 MB"
    assert pg.download_text(31 * MB, 74 * MB + 1) == "41% · 31 de 75 MB"  # total arredonda para cima
    assert pg.download_text(5 * MB, 0) == "5 MB"


# ---------- widget ----------
def test_bar_shows_caption_and_falls_back_to_percent(app):
    bar = keep(MandacaruProgressBar())
    bar.setRange(0, 200)
    bar.setValue(84)
    assert bar.text() == "42%"
    bar.set_caption("Verificando 84 de 200 arquivos · 42%")
    assert bar.text() == bar.caption() == "Verificando 84 de 200 arquivos · 42%"
    bar.set_caption("")
    assert bar.text() == "42%"


def test_caption_is_literal_even_with_format_placeholders(app):
    bar = keep(MandacaruProgressBar())
    bar.setRange(0, 10)
    bar.setValue(3)
    bar.set_caption("Consultando a NVD: app %p %v %m 100%")
    assert bar.text() == "Consultando a NVD: app %p %v %m 100%"


def _lightness_in(img, x0, x1):
    """Lightness de todos os pixels da faixa central (onde fica o texto) entre x0 e x1."""
    h = img.height()
    return [QColor(img.pixel(x, y)).lightness() for x in range(x0, x1) for y in range(h // 4, h * 3 // 4)]


@pytest.mark.parametrize("window_bg", ["#f5f5f5", "#1e1e1e"])
def test_caption_is_painted_in_two_tones(app, window_bg):
    bar = keep(MandacaruProgressBar())
    pal = bar.palette()
    pal.setColor(QPalette.ColorRole.Window, QColor(window_bg))
    bar.setPalette(pal)
    bar.resize(480, 18)
    bar.setRange(0, 100)
    bar.setValue(50)
    bar.show()
    w = bar.width()
    plain = bar.grab().toImage()
    # sem frase, o "50%" fica no meio: as pontas só têm verde e trilho
    assert max(_lightness_in(plain, 10, int(w * 0.4))) < 200
    # frase comum (glifos de qualquer fonte) que ocupa a barra inteira dos dois lados da ponta
    bar.set_caption("Mandacaru " * 12)
    img = bar.grab().toImage()
    on_green = _lightness_in(img, 10, int(w * 0.45))
    on_track = _lightness_in(img, int(w * 0.55), w - 10)
    assert max(on_green) > 230  # letras brancas sobre o verde
    if window_bg == "#1e1e1e":
        assert max(on_track) > 200  # letras claras sobre o trilho escuro
    else:
        assert min(on_track) < 80  # letras escuras sobre o trilho claro


# ---------- gradiente ----------
GRADIENTE = ("#001000", "#004D00", "#3F8F3A", "#70C06A", "#E1FFDE")


def _close(c: QColor, hexa: str, tol: int = 14) -> bool:
    ref = QColor(hexa)
    return all(abs(a - b) <= tol for a, b in ((c.red(), ref.red()), (c.green(), ref.green()),
                                              (c.blue(), ref.blue())))


def _full_bar(value=100, caption=""):
    bar = keep(MandacaruProgressBar())
    bar.resize(500, 18)
    bar.setRange(0, 100)
    bar.setValue(value)
    bar.set_caption(caption)
    bar.setTextVisible(bool(caption))
    bar.show()
    return bar


def test_normal_tone_uses_the_requested_gradient():
    # linear-gradient(90deg, #001000, #004D00, #3F8F3A, #70C06A, #E1FFDE)
    assert widgets._TONES["normal"] == GRADIENTE
    assert widgets.gradient_color(GRADIENTE, 0.0).name() == "#001000"
    assert widgets.gradient_color(GRADIENTE, 0.5).name() == "#3f8f3a"
    assert widgets.gradient_color(GRADIENTE, 1.0).name() == "#e1ffde"


def test_full_bar_shows_every_stop_left_to_right(app):
    bar = _full_bar(100)
    img = bar.grab().toImage()
    y, w = img.height() // 2, img.width()
    inner_left, inner_w = 2, w - 4  # borda de 1 px + recuo de 1 px
    for t, hexa in ((0.06, None), (0.25, "#004D00"), (0.5, "#3F8F3A"), (0.75, "#70C06A"), (0.97, None)):
        c = QColor(img.pixel(int(inner_left + t * inner_w), y))
        assert _close(c, hexa or widgets.gradient_color(GRADIENTE, t).name()), (t, c.name())


def test_gradient_is_anchored_to_the_whole_bar(app):
    # Pela metade, a ponta tem a cor do meio (#3F8F3A), e não o verde-claro do fim:
    # assim ela nunca some no trilho claro.
    img = _full_bar(50).grab().toImage()
    y, w = img.height() // 2, img.width()
    head = QColor(img.pixel(int(2 + 0.47 * (w - 4)), y))
    assert _close(head, widgets.gradient_color(GRADIENTE, 0.47).name())
    assert head.lightness() < 120


def test_text_is_white_on_dark_green_and_black_on_light_green(app):
    img = _full_bar(100, "Mandacaru " * 12).grab().toImage()
    w = img.width()
    dark_part = _lightness_in(img, 10, int(w * 0.40))
    light_part = _lightness_in(img, int(w * 0.60), w - 10)
    assert max(dark_part) > 230  # branco sobre #001000..#3F8F3A
    assert min(light_part) < 30  # preto sobre #70C06A..#E1FFDE
    assert max(light_part) < 250  # e nada de branco ali


@pytest.mark.parametrize("tone", sorted(widgets._TONES))
def test_text_contrast_is_aa_along_every_gradient(tone):
    stops = widgets._TONES[tone]
    spans = widgets._DARK_SPANS[tone]
    for k in range(201):
        t = k / 200
        bg = widgets.gradient_color(stops, t)
        fg = widgets.TEXT_DARK if any(a <= t <= b for a, b in spans) else widgets.TEXT_LIGHT
        assert widgets.contrast(fg, bg) >= 4.5, (tone, t, bg.name())


def test_long_caption_is_elided_not_overflowing(app):
    bar = keep(MandacaruProgressBar())
    bar.resize(120, 18)
    bar.setRange(0, 10)
    bar.setValue(5)
    bar.set_caption(pg.scan_text(1234, 2900, "cerca de 1 min"))
    bar.show()
    assert not bar.grab().isNull()  # pinta sem estourar; o texto inteiro segue em text()
    assert bar.text().endswith("cerca de 1 min")


def test_eta_uses_injected_clock(app):
    now = [100.0]
    bar = keep(MandacaruProgressBar(clock=lambda: now[0]))
    assert bar.eta() == ""  # relógio não iniciado
    bar.setRange(0, 100)
    bar.start_clock()
    now[0] += 60
    bar.setValue(50)
    assert bar.eta() == "cerca de 1 min"


# ---------- aba Varredura ----------
def test_scan_progress_shows_full_phrase(app, tmp_path, scanner):
    win = make_win(tmp_path, scanner)
    win.progress.start_clock()
    win._on_progress(tmp_path / "a.txt", 1234, 2900)
    assert win.progress.text().startswith("Verificando 1.234 de 2.900 arquivos · 42%")
    assert win.progress.maximum() == 2900 and win.progress.value() == 1234


def test_real_scan_ends_with_done_caption(app, tmp_path, scanner):
    d = tmp_path / "alvo"
    d.mkdir()
    for i in range(3):
        (d / f"{i}.txt").write_text("x")
    win = make_win(tmp_path, scanner)
    box = []
    loop = QEventLoop()
    win.scan_finished.connect(lambda s: (box.append(s), loop.quit()))
    QTimer.singleShot(10000, loop.quit)
    win.start_scan([d])
    assert win.progress.maximum() == 0 and win.progress.caption() == ""  # listando: indeterminado
    loop.exec()
    assert box and box[0].completed
    assert win.progress.text() == "Concluída · 3 arquivos verificados"


def test_interrupted_scan_keeps_progress_and_says_so(app, tmp_path, scanner):
    win = make_win(tmp_path, scanner)
    win._on_progress(tmp_path / "0.txt", 1, 3)
    win._on_done(ScanSummary(0.0, [str(tmp_path)], 1, 0, 0.1, False))
    assert win.progress.maximum() == 3 and win.progress.value() == 1
    assert win.progress.text() == "Interrompida · 1 de 3 arquivos verificados"
    assert win.progress.tone == "warning"


def test_scan_stopped_while_listing_and_failure(app, tmp_path, scanner):
    win = make_win(tmp_path, scanner)
    win.progress.setRange(0, 0)
    win._on_done(ScanSummary(0.0, [str(tmp_path)], 0, 0, 0.1, False))
    assert win.progress.maximum() == 1 and win.progress.text() == "Interrompida"
    win.progress.setRange(0, 0)
    win._on_failed("boom")
    assert win.progress.text() == "A varredura falhou" and win.msgs


def test_shred_uses_its_own_phrase(app, tmp_path, scanner):
    win = make_win(tmp_path, scanner)
    win._on_progress(tmp_path / "a.txt", 2, 4)  # frase de uma varredura anterior
    win._on_shred_progress(tmp_path / "x.bin", 3, 10)
    assert win.progress.text() == "Destruindo 3 de 10 arquivos · 30%"
    win._on_shred_done(ShredSummary(str(tmp_path), 10, 1, [], True))
    assert win.progress.text() == "Destruição concluída"


def test_scan_thread_still_throttles_progress_signals(app):
    t = ScanThread([], None, set())
    got = []
    t.progress.connect(lambda p, i, n: got.append(i))
    for i in range(1, 1001):
        t._emit_progress(None, i, 1000)
    # 1000 arquivos num piscar de olhos: o primeiro, o último e quase nada no meio
    assert got[0] == 1 and got[-1] == 1000 and len(got) <= 5


# ---------- aba Atualizações ----------
def test_updates_tab_progress_caption(app, tmp_path, scanner):
    win = make_win(tmp_path, scanner)
    win._on_upd_progress("Consultando a NVD: 7-Zip", 3, 20)
    assert win.upd_progress.text() == "3 de 20 programas · 15%"
    assert win.lbl_upd.text() == "Consultando a NVD: 7-Zip"
    win._on_upd_progress("Listando programas com versão nova…", 0, 0)  # sem total: mantém a barra
    assert win.upd_progress.text() == "3 de 20 programas · 15%"


# ---------- faixa de autoatualização ----------
def test_update_banner_download_bar(app, tmp_path):
    msgs = []
    bar = keep(UpdateBar(tmp_path, msgs.append, msgs.append))
    assert bar.progress.isHidden()

    class Upd:
        version, current = "9.0.0", "0.7.0"

    bar.pending = Upd()
    bar._on_progress(31 * MB, 74 * MB)
    assert bar.progress.value() == 31 * MB and bar.progress.text() == "41% · 31 de 74 MB"
    bar._on_progress(5 * MB, 0)  # tamanho desconhecido
    assert bar.progress.text() == "5 MB"
    bar.show_update(Upd())
    assert bar.progress.isHidden() and bar.progress.caption() == ""
