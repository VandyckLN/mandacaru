import hashlib
import io
import json

import pytest

pytest.importorskip("PySide6")

from mandacaru_win import updater  # noqa: E402
from mandacaru_win.app import MainWindow  # noqa: E402
from PySide6.QtCore import QCoreApplication, QEvent, QEventLoop, QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

SETUP = b"MZ" + b"instalador falso " * 500
URL = f"{updater.DOWNLOAD_PREFIX}v9.0.0/Mandacaru-9.0.0-setup.exe"
_windows: list = []


def release(digest):
    return {"tag_name": "v9.0.0", "assets": [{
        "name": "Mandacaru-9.0.0-setup.exe", "size": len(SETUP),
        "browser_download_url": URL, "digest": f"sha256:{digest}"}]}


def fake_http(routes):
    def http(req, timeout):
        body = routes[req.full_url]
        if isinstance(body, BaseException):
            raise body
        return io.BytesIO(body if isinstance(body, bytes) else json.dumps(body).encode())
    return http


@pytest.fixture(scope="session")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _close_windows():
    yield
    while _windows:
        w = _windows.pop()
        w.close()
        w.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def make_win(tmp_path, scanner, routes):
    win = MainWindow(tmp_path / "dados", scanner)
    _windows.append(win)
    win.msgs = []
    win.notify = win.msgs.append
    bar = win.update_bar
    bar.http = fake_http(routes)
    bar.now = lambda: 1000.0
    bar.cmds = []
    bar.runner = bar.cmds.append
    return win, bar


def wait(signal, start):
    box = []
    loop = QEventLoop()
    signal.connect(lambda *a: (box.append(a), loop.quit()))
    QTimer.singleShot(10000, loop.quit)
    start()
    loop.exec()
    return box


def test_banner_hidden_by_default_and_shown_when_update_exists(app, tmp_path, scanner):
    win, bar = make_win(tmp_path, scanner, {updater.RELEASES_URL: release("0" * 64)})
    assert bar.isHidden() and win.act_check_updates.text() == "Verificar atualizações"
    wait(bar.checked, win.check_updates)
    assert not bar.isHidden()
    assert bar.label.text() == f"Mandacaru 9.0.0 disponível (você tem {updater.__version__})."
    bar.later()
    assert bar.isHidden()
    wait(bar.checked, lambda: bar.start_check(False))   # adiado: continua escondida
    assert bar.isHidden()


def test_network_failure_keeps_banner_hidden_and_manual_check_says_so(app, tmp_path, scanner):
    win, bar = make_win(tmp_path, scanner, {updater.RELEASES_URL: OSError("sem rede")})
    wait(bar.checked, win.check_updates)
    assert bar.isHidden() and win.msgs == []
    wait(bar.checked, win.act_check_updates.trigger)
    assert bar.isHidden() and "Não foi possível verificar" in win.statusBar().currentMessage()


def test_update_now_downloads_verifies_runs_setup_and_closes(app, tmp_path, scanner):
    digest = hashlib.sha256(SETUP).hexdigest()
    win, bar = make_win(tmp_path, scanner, {updater.RELEASES_URL: release(digest), URL: SETUP})
    wait(bar.checked, win.check_updates)
    closed = []
    bar.quit_requested.connect(lambda: closed.append(True))
    wait(bar.quit_requested, bar.btn_update.click)
    setup = tmp_path / "dados" / "updates" / "Mandacaru-9.0.0-setup.exe"
    assert closed and setup.read_bytes() == SETUP
    assert bar.cmds[0][:4] == [str(setup), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"]
    assert "/ATUALIZACAO" in bar.cmds[0]


def test_update_now_with_wrong_hash_does_not_install(app, tmp_path, scanner):
    win, bar = make_win(tmp_path, scanner, {updater.RELEASES_URL: release("0" * 64), URL: SETUP})
    wait(bar.checked, win.check_updates)
    import time
    bar.btn_update.click()
    assert not bar.btn_update.isEnabled()                 # ocupada durante o download
    deadline = time.monotonic() + 10
    while not win.msgs and time.monotonic() < deadline:
        app.processEvents(QEventLoop.ProcessEventsFlag.WaitForMoreEvents, 50)
    assert win.msgs and "não confere" in win.msgs[0]
    assert bar.cmds == [] and bar._download is None and not bar.isHidden()
    assert bar.btn_update.isEnabled() and "9.0.0 disponível" in bar.label.text()
    assert list((tmp_path / "dados" / "updates").iterdir()) == []
