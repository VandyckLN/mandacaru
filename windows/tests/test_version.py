def test_version_matches_core():
    import mandacaru
    import mandacaru_win

    assert mandacaru_win.__version__ == mandacaru.__version__
