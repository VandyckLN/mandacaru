import os

import pytest
from mandacaru_win.quarantine import Quarantine, QuarantineError
from mandacaru_win.scan import Finding, sha256_file

from mandacaru.events import Alert, Severity


def finding_for(path):
    return Finding(path, sha256_file(path), Severity.HIGH,
                   [Alert("yara.X", Severity.HIGH, "s")])


def test_roundtrip_preserves_bytes_and_removes_original(tmp_path):
    f = tmp_path / "relatório final.ps1"
    data = b"\x00MZ" + os.urandom(1000)
    f.write_bytes(data)
    q = Quarantine(tmp_path / "q")
    qid = q.add(finding_for(f))
    assert not f.exists()
    assert data not in (tmp_path / "q" / f"{qid}.bin").read_bytes()
    assert q.items()[0]["caminho_original"] == str(f)
    assert q.restore(qid) == f and f.read_bytes() == data
    assert q.items() == [] and list((tmp_path / "q").iterdir()) == []


def test_failed_delete_keeps_original_and_cleans_quarantine(tmp_path, monkeypatch):
    f = tmp_path / "a.ps1"
    f.write_bytes(b"abc")
    q = Quarantine(tmp_path / "q")
    monkeypatch.setattr(os, "remove",
                        lambda *_: (_ for _ in ()).throw(PermissionError("em uso")))
    with pytest.raises(QuarantineError):
        q.add(finding_for(f))
    assert f.read_bytes() == b"abc" and list((tmp_path / "q").iterdir()) == []


def test_changed_or_missing_file_is_refused(tmp_path):
    f = tmp_path / "a.ps1"
    f.write_bytes(b"abc")
    fin = finding_for(f)
    f.write_bytes(b"mudou")
    with pytest.raises(QuarantineError):
        Quarantine(tmp_path / "q").add(fin)
    f.unlink()
    with pytest.raises(QuarantineError):
        Quarantine(tmp_path / "q").add(fin)


def test_restore_when_name_taken(tmp_path):
    f = tmp_path / "a.ps1"
    f.write_bytes(b"abc")
    q = Quarantine(tmp_path / "q")
    qid = q.add(finding_for(f))
    f.write_bytes(b"outro")
    assert q.restore(qid) == tmp_path / "a (restaurado).ps1"
    assert f.read_bytes() == b"outro"


def test_tampered_bin_is_not_restored(tmp_path):
    f = tmp_path / "a.ps1"
    f.write_bytes(b"abc")
    q = Quarantine(tmp_path / "q")
    qid = q.add(finding_for(f))
    (tmp_path / "q" / f"{qid}.bin").write_bytes(b"zzz")
    with pytest.raises(QuarantineError):
        q.restore(qid)
    assert not f.exists() and len(q.items()) == 1


def test_delete(tmp_path):
    f = tmp_path / "a.ps1"
    f.write_bytes(b"abc")
    q = Quarantine(tmp_path / "q")
    q.delete(q.add(finding_for(f)))
    assert q.items() == []
