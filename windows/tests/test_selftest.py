def test_selftest_passes(tmp_path, monkeypatch):
    monkeypatch.setenv("TEMP", str(tmp_path))
    monkeypatch.setenv("TMP", str(tmp_path))
    from mandacaru_win.__main__ import selftest

    assert selftest() == 0
    assert (tmp_path / "mandacaru-selftest.txt").exists()


def test_excepthook_writes_log_and_shows_dialog(tmp_path, monkeypatch):
    from mandacaru_win import __main__ as m

    shown = []
    monkeypatch.setattr(m.QApplication, "instance", staticmethod(lambda: object()))
    monkeypatch.setattr(m.QMessageBox, "critical", staticmethod(lambda *a: shown.append(a)))
    try:
        raise ValueError("boom")
    except ValueError as e:
        m.log_exception(tmp_path, type(e), e, e.__traceback__)
    assert "ValueError" in (tmp_path / "erros.log").read_text(encoding="utf-8") and shown


def test_second_instance_cannot_take_lock(tmp_path):
    from mandacaru_win.__main__ import acquire_lock

    first = acquire_lock(tmp_path)
    assert first is not None
    assert acquire_lock(tmp_path) is None
    first.unlock()


def test_set_app_id_is_noop_outside_windows(monkeypatch):
    import mandacaru_win.__main__ as m

    monkeypatch.setattr(m.sys, "platform", "linux")
    assert m.set_app_id() is False
    assert m.APP_ID == "VandyckLN.Mandacaru"
