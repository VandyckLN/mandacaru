from pathlib import Path

from mandacaru_win.scan import ScanSummary
from mandacaru_win.store import History, TrustList


def test_trust_add_remove_persists(tmp_path):
    t = TrustList(tmp_path / "trust.json"); t.add("ab" * 32, Path("C:/x/a.ps1"))
    assert TrustList(tmp_path / "trust.json").hashes() == {"ab" * 32}
    t.add("ab" * 32, Path("C:/x/a.ps1"))                    # repetido não duplica
    assert len(t.entries()) == 1
    t.remove("ab" * 32)
    assert TrustList(tmp_path / "trust.json").hashes() == set()


def test_corrupt_trust_starts_empty_and_keeps_file(tmp_path):
    p = tmp_path / "trust.json"; p.write_text("{quebrado")
    assert TrustList(p).hashes() == set()
    assert (tmp_path / "trust.json.corrompido").read_text() == "{quebrado"


def test_history_recent_order_limit_and_bad_line(tmp_path):
    h = History(tmp_path / "history.jsonl")
    for i in range(3):
        h.append(ScanSummary(started=float(i), paths=["C:/d"], files=i, findings=0, duration=1.0, completed=True))
    with open(tmp_path / "history.jsonl", "a") as fh: fh.write("lixo\n")
    assert [r["started"] for r in h.recent(2)] == [2.0, 1.0]


def test_trust_io_error_does_not_move_file(tmp_path, monkeypatch):
    import pytest
    p = tmp_path / "trust.json"
    t = TrustList(p); t.add("ab" * 32, Path("C:/x/a.ps1"))
    original = p.read_text()

    def bloqueado(self):
        raise PermissionError("bloqueado")
    monkeypatch.setattr(Path, "read_bytes", bloqueado)
    with pytest.raises(PermissionError):
        TrustList(p)
    monkeypatch.undo()
    assert p.read_text() == original
    assert not (tmp_path / "trust.json.corrompido").exists()


def test_second_corruption_keeps_both_backups(tmp_path):
    p = tmp_path / "trust.json"
    p.write_text("{um"); TrustList(p)
    p.write_text("{dois"); TrustList(p)
    backups = sorted(f.read_text() for f in tmp_path.glob("trust.json.corrompido*"))
    assert backups == ["{dois", "{um"]
