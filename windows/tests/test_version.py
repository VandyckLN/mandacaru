def test_version_matches_core():
    import mandacaru_win

    import mandacaru

    assert mandacaru_win.__version__ == mandacaru.__version__
