import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QEventLoop, QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from mandacaru_win.app import MainWindow  # noqa: E402
from mandacaru_win.scan import sha256_file  # noqa: E402
from mandacaru_win.store import History, TrustList  # noqa: E402


@pytest.fixture(scope="session")
def app():
    return QApplication.instance() or QApplication([])


def make_win(tmp_path, scanner):
    win = MainWindow(tmp_path / "dados", scanner)
    win.msgs = []
    win.confirm = lambda _: True
    win.notify = win.msgs.append
    return win


def wait_scan(win, paths):
    box = []
    loop = QEventLoop()
    win.scan_finished.connect(lambda s: (box.append(s), loop.quit()))
    QTimer.singleShot(10000, loop.quit)
    win.start_scan(paths)
    loop.exec()
    return box[0]


def test_window_scans_and_lists_finding(app, tmp_path, scanner, ps_text):
    d = tmp_path / "alvo"; d.mkdir(); (d / "a.ps1").write_text(ps_text)
    win = make_win(tmp_path, scanner)
    summary = wait_scan(win, [d])
    assert summary.completed and list(win.findings) == [d / "a.ps1"]
    assert History(tmp_path / "dados" / "history.jsonl").recent()[0]["findings"] == 1


def test_ignore_removes_row_and_trusts_hash(app, tmp_path, scanner, ps_text):
    d = tmp_path / "alvo"; d.mkdir(); f = d / "a.ps1"; f.write_text(ps_text)
    win = make_win(tmp_path, scanner); wait_scan(win, [d])
    win.ignore_finding(f)
    assert win.findings == {} and sha256_file(f) in TrustList(tmp_path / "dados" / "trust.json").hashes()
    assert wait_scan(win, [d]).findings == 0


def test_quarantine_from_list_and_error_on_vanished_file(app, tmp_path, scanner, ps_text):
    d = tmp_path / "alvo"; d.mkdir(); f = d / "a.ps1"; f.write_text(ps_text); g = d / "b.ps1"; g.write_text(ps_text)
    win = make_win(tmp_path, scanner)
    wait_scan(win, [d])
    win.quarantine_finding(f)
    assert not f.exists() and f not in win.findings
    g.unlink(); win.quarantine_finding(g)
    assert win.msgs and g in win.findings                  # erro mostrado, linha continua


def test_locked_trust_file_disables_ignore_without_overwriting(app, tmp_path, scanner, ps_text, monkeypatch):
    d = tmp_path / "alvo"; d.mkdir(); f = d / "a.ps1"; f.write_text(ps_text)
    dados = tmp_path / "dados"; dados.mkdir()
    (dados / "trust.json").write_text("[]")

    def boom(self):
        raise PermissionError("bloqueado")
    monkeypatch.setattr(TrustList, "_load", boom)
    win = make_win(tmp_path, scanner)
    monkeypatch.undo()
    wait_scan(win, [d])
    win.ignore_finding(f)
    assert win.msgs                                        # avisou ao tentar
    assert f in win.findings and (dados / "trust.json").read_text() == "[]"


def test_stop_scan_is_interruptible(app, tmp_path, scanner, ps_text):
    d = tmp_path / "alvo"; d.mkdir()
    for i in range(30):
        (d / f"{i}.ps1").write_text(ps_text)
    win = make_win(tmp_path, scanner)
    box = []
    loop = QEventLoop()
    win.scan_finished.connect(lambda s: (box.append(s), loop.quit()))
    QTimer.singleShot(10000, loop.quit)
    win.start_scan([d]); win.stop_scan()
    loop.exec()
    assert box and not box[0].completed
