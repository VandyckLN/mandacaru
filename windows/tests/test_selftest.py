def test_selftest_passes():
    from mandacaru_win.__main__ import selftest

    assert selftest() == 0
