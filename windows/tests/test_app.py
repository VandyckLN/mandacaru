import pytest

pytest.importorskip("PySide6")

from mandacaru_win.app import MainWindow  # noqa: E402
from mandacaru_win.scan import sha256_file  # noqa: E402
from mandacaru_win.store import History, TrustList  # noqa: E402
from PySide6.QtCore import QCoreApplication, QEvent, QEventLoop, QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

_windows: list = []


@pytest.fixture(scope="session")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _close_windows():
    # janelas vivas até o fim do interpretador derrubam o processo no Windows (access violation)
    yield
    while _windows:
        w = _windows.pop()
        w.close()
        w.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def make_win(tmp_path, scanner):
    win = MainWindow(tmp_path / "dados", scanner)
    _windows.append(win)
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
    d = tmp_path / "alvo"
    d.mkdir()
    (d / "a.ps1").write_text(ps_text)
    win = make_win(tmp_path, scanner)
    summary = wait_scan(win, [d])
    assert summary.completed and list(win.findings) == [d / "a.ps1"]
    assert History(tmp_path / "dados" / "history.jsonl").recent()[0]["findings"] == 1


def test_ignore_removes_row_and_trusts_hash(app, tmp_path, scanner, ps_text):
    d = tmp_path / "alvo"
    d.mkdir()
    f = d / "a.ps1"
    f.write_text(ps_text)
    win = make_win(tmp_path, scanner)
    wait_scan(win, [d])
    win.ignore_finding(f)
    assert win.findings == {} and sha256_file(f) in TrustList(tmp_path / "dados" / "trust.json").hashes()
    assert wait_scan(win, [d]).findings == 0


def test_quarantine_from_list_and_error_on_vanished_file(app, tmp_path, scanner, ps_text):
    d = tmp_path / "alvo"
    d.mkdir()
    f = d / "a.ps1"
    f.write_text(ps_text)
    g = d / "b.ps1"
    g.write_text(ps_text)
    win = make_win(tmp_path, scanner)
    wait_scan(win, [d])
    win.quarantine_finding(f)
    assert not f.exists() and f not in win.findings
    g.unlink()
    win.quarantine_finding(g)
    assert win.msgs and g in win.findings                  # erro mostrado, linha continua


def test_locked_trust_file_disables_ignore_without_overwriting(app, tmp_path, scanner, ps_text, monkeypatch):
    d = tmp_path / "alvo"
    d.mkdir()
    f = d / "a.ps1"
    f.write_text(ps_text)
    dados = tmp_path / "dados"
    dados.mkdir()
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
    d = tmp_path / "alvo"
    d.mkdir()
    for i in range(30):
        (d / f"{i}.ps1").write_text(ps_text)
    win = make_win(tmp_path, scanner)
    box = []
    loop = QEventLoop()
    win.scan_finished.connect(lambda s: (box.append(s), loop.quit()))
    QTimer.singleShot(10000, loop.quit)
    win.start_scan([d])
    win.stop_scan()
    loop.exec()
    assert box and not box[0].completed


class BoomScanner:
    def is_excluded(self, _):
        raise RuntimeError("falha inesperada")

    def scan_file(self, _):
        return []


def test_scanner_exception_releases_window(app, tmp_path, ps_text):
    d = tmp_path / "alvo"
    (d / "sub").mkdir(parents=True)
    (d / "a.ps1").write_text(ps_text)
    win = make_win(tmp_path, BoomScanner())
    summary = wait_scan(win, [d])
    assert not summary.completed
    assert win.btn_folder.isEnabled() and not win.btn_stop.isEnabled()
    assert win.msgs and "falhou" in win.msgs[0]
    assert win._thread is None


def test_findings_sorted_by_severity_when_out_of_order(app, tmp_path, scanner):
    from pathlib import Path

    from mandacaru_win.scan import Finding

    from mandacaru.events import Alert, Severity
    win = make_win(tmp_path, scanner)
    for name, sev in (("l", Severity.LOW), ("c", Severity.CRITICAL),
                      ("m", Severity.MEDIUM), ("c2", Severity.CRITICAL)):
        p = Path(name)
        win._on_found(Finding(p, "0" * 64, sev, [Alert("r", sev, "x")]))
    order = [win.tree.topLevelItem(i).text(1) for i in range(4)]
    assert order == ["c", "c2", "m", "l"]


def test_restore_and_delete_from_quarantine_tab(app, tmp_path, scanner, ps_text):
    from mandacaru_win.quarantine import Quarantine
    d = tmp_path / "alvo"
    d.mkdir()
    f = d / "a.ps1"
    f.write_text(ps_text)
    g = d / "b.ps1"
    g.write_text(ps_text)
    win = make_win(tmp_path, scanner)
    wait_scan(win, [d])
    win.quarantine_finding(f)
    win.quarantine_finding(g)
    q = Quarantine(tmp_path / "dados" / "quarantine")
    ids = {i["caminho_original"]: i["id"] for i in q.items()}
    assert win.tbl_quarantine.rowCount() == 2
    win.restore_item(ids[str(f)])
    assert f.read_text() == ps_text
    win.delete_item(ids[str(g)])
    assert q.items() == [] and not g.exists()
    assert win.tbl_quarantine.rowCount() == 0


def test_declined_confirmation_changes_nothing(app, tmp_path, scanner, ps_text):
    from mandacaru_win.quarantine import Quarantine
    d = tmp_path / "alvo"
    d.mkdir()
    f = d / "a.ps1"
    f.write_text(ps_text)
    win = make_win(tmp_path, scanner)
    win.confirm = lambda _: False
    wait_scan(win, [d])
    win.quarantine_finding(f)
    assert f.exists() and f in win.findings
    win.confirm = lambda _: True
    win.quarantine_finding(f)
    qid = Quarantine(tmp_path / "dados" / "quarantine").items()[0]["id"]
    win.confirm = lambda _: False
    win.restore_item(qid)
    win.delete_item(qid)
    assert not f.exists() and len(Quarantine(tmp_path / "dados" / "quarantine").items()) == 1


def test_quarantine_error_is_notified(app, tmp_path, scanner):
    win = make_win(tmp_path, scanner)
    win.restore_item("0" * 32)
    win.delete_item("zzz")
    assert len(win.msgs) == 2


def test_remove_trusted_lets_finding_return(app, tmp_path, scanner, ps_text):
    d = tmp_path / "alvo"
    d.mkdir()
    f = d / "a.ps1"
    f.write_text(ps_text)
    win = make_win(tmp_path, scanner)
    wait_scan(win, [d])
    h = win.findings[f].sha256
    win.ignore_finding(f)
    assert win.tbl_trust.rowCount() == 1
    win.remove_trusted(h)
    assert win.tbl_trust.rowCount() == 0
    assert wait_scan(win, [d]).findings == 1


def test_history_tab_lists_scans(app, tmp_path, scanner, ps_text):
    d = tmp_path / "alvo"
    d.mkdir()
    (d / "a.ps1").write_text(ps_text)
    win = make_win(tmp_path, scanner)
    wait_scan(win, [d])
    assert win.tbl_history.rowCount() == 1
    assert win.tbl_history.item(0, 3).text() == "1"
    assert win.tbl_history.item(0, 5).text() == "Concluída"


def test_trust_tab_without_trust_file(app, tmp_path, scanner, monkeypatch):
    dados = tmp_path / "dados"
    dados.mkdir()
    (dados / "trust.json").write_text("[]")

    def boom(self):
        raise PermissionError("bloqueado")
    monkeypatch.setattr(TrustList, "_load", boom)
    win = make_win(tmp_path, scanner)
    monkeypatch.undo()
    win.refresh_tabs()
    win.remove_trusted("x" * 64)
    assert win.tbl_trust.rowCount() == 0 and "bloqueado" in win.lbl_trust.text()
    assert (dados / "trust.json").read_text() == "[]"


def test_table_resize_modes(app, tmp_path, scanner):
    from PySide6.QtWidgets import QHeaderView
    win = make_win(tmp_path, scanner)
    S, C = QHeaderView.ResizeMode.Stretch, QHeaderView.ResizeMode.ResizeToContents
    for tbl, path_col in ((win.tbl_quarantine, 1), (win.tbl_trust, 0), (win.tbl_history, 1)):
        hh = tbl.horizontalHeader()
        assert not hh.stretchLastSection() and hh.sectionResizeMode(path_col) == S
        assert hh.sectionResizeMode(tbl.columnCount() - 1) == C
    assert win.tbl_quarantine.horizontalHeader().sectionResizeMode(4) == C
    assert win.tbl_trust.horizontalHeader().sectionResizeMode(3) == C


def _scan_one(tmp_path, scanner, ps_text, name="a.ps1"):
    d = tmp_path / "alvo"
    d.mkdir(exist_ok=True)
    f = d / name
    f.write_text(ps_text)
    return d, f


def test_malformed_data_does_not_prevent_window_from_opening(app, tmp_path, scanner):
    dados = tmp_path / "dados"
    (dados / "quarantine").mkdir(parents=True)
    (dados / "quarantine" / ("a" * 32 + ".json")).write_text(
        '{"caminho_original": "c", "sha256": "x", "data": "d", "regras": [1]}')
    (dados / "history.jsonl").write_text(
        '{"started": 1, "paths": [1], "files": 1, "findings": 0, "duration": "abc"}\n'
        '{"started": 1, "paths": ["C:/d"], "files": 1, "findings": 0, "duration": 1}\n')
    (dados / "trust.json").write_text('[{"sha256": 5}, {"sha256": "ab"}]')
    win = make_win(tmp_path, scanner)
    assert win.tbl_quarantine.rowCount() == 1
    assert win.tbl_history.rowCount() == 1 and win.tbl_trust.rowCount() == 1


def test_ignore_removes_all_rows_with_same_hash(app, tmp_path, scanner, ps_text):
    d, f = _scan_one(tmp_path, scanner, ps_text)
    g = d / "copia.ps1"
    g.write_text(ps_text)
    win = make_win(tmp_path, scanner)
    wait_scan(win, [d])
    assert len(win.findings) == 2
    win.ignore_finding(f)
    assert win.findings == {} and win.tree.topLevelItemCount() == 0


def test_found_same_path_twice_keeps_single_row(app, tmp_path, scanner, ps_text):
    d, f = _scan_one(tmp_path, scanner, ps_text)
    win = make_win(tmp_path, scanner)
    wait_scan(win, [d])
    win._on_found(win.findings[f])
    assert win.tree.topLevelItemCount() == 1


def test_open_location_uses_absolute_explorer(app, tmp_path, scanner, monkeypatch):
    import types

    from mandacaru_win import app as appmod
    win = make_win(tmp_path, scanner)
    cmds = []
    monkeypatch.setattr(appmod, "sys", types.SimpleNamespace(platform="win32"))
    monkeypatch.setattr(appmod.subprocess, "Popen", lambda cmd: cmds.append(cmd))
    monkeypatch.setenv("WINDIR", "C:\\Win")
    win.open_location(tmp_path / "a b.ps1")
    assert cmds[0][0].endswith("explorer.exe") and "Win" in cmds[0][0]
    assert cmds[0][1] == "/select," and cmds[0][2] == str(tmp_path / "a b.ps1")
    monkeypatch.setattr(appmod.subprocess, "Popen",
                        lambda cmd: (_ for _ in ()).throw(OSError("x")))
    win.open_location(tmp_path / "a.ps1")
    assert win.msgs


def test_close_during_scan_is_fast(app, tmp_path, scanner):
    import time
    for i in range(300):
        d = tmp_path / "alvo" / f"d{i}"
        d.mkdir(parents=True)
        (d / "a.txt").write_text("x")
    win = make_win(tmp_path, scanner)
    win.start_scan([tmp_path / "alvo"])
    t0 = time.monotonic()
    win.close()
    assert time.monotonic() - t0 < 5


def test_restore_tampered_bin_notifies_and_keeps_row(app, tmp_path, scanner, ps_text):
    d, f = _scan_one(tmp_path, scanner, ps_text)
    win = make_win(tmp_path, scanner)
    wait_scan(win, [d])
    win.quarantine_finding(f)
    (binp,) = (tmp_path / "dados" / "quarantine").glob("*.bin")
    binp.write_bytes(b"zzz")
    win.restore_item(binp.stem)
    assert win.msgs and win.tbl_quarantine.rowCount() == 1 and not f.exists()


def test_stop_scan_midway_keeps_progress(app, tmp_path, scanner):
    d = tmp_path / "alvo"
    d.mkdir()
    for i in range(3):
        (d / f"{i}.txt").write_text("x")
    win = make_win(tmp_path, scanner)
    win._on_progress(d / "0.txt", 1, 3)
    from mandacaru_win.scan import ScanSummary
    win._thread = None
    win._on_done(ScanSummary(0.0, [str(d)], 1, 0, 0.1, False))
    assert win.progress.maximum() == 3 and win.progress.value() == 1


def test_app_icon_and_ico(app):
    import struct
    from pathlib import Path

    from mandacaru_win.__main__ import app_icon

    assert not app_icon().isNull()
    data = (Path(__file__).parents[1] / "assets" / "mandacaru.ico").read_bytes()
    _, kind, count = struct.unpack_from("<HHH", data)
    sizes = {data[6 + 16 * i] or 256 for i in range(count)}
    assert kind == 1 and {16, 32, 48, 256} <= sizes
