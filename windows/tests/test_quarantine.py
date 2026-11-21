import json
import os
import stat

import pytest
from mandacaru_win import quarantine
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


def _setup(tmp_path, data=b"abc", name="a.ps1"):
    f = tmp_path / name
    f.write_bytes(data)
    return f, Quarantine(tmp_path / "q")


def test_read_only_original_is_quarantined(tmp_path, monkeypatch):
    f, q = _setup(tmp_path)
    real_remove, chmods = os.remove, []
    real_chmod = os.chmod
    calls = []

    def remove(p):
        calls.append(p)
        if len(calls) == 1:
            raise PermissionError("somente leitura")
        real_remove(p)

    monkeypatch.setattr(os, "remove", remove)
    monkeypatch.setattr(os, "chmod", lambda p, m: (chmods.append(m), real_chmod(p, m)))
    q.add(finding_for(f))
    assert not f.exists() and chmods and chmods[0] & stat.S_IWRITE


def test_read_only_still_failing_restores_mode_and_keeps_original(tmp_path, monkeypatch):
    f, q = _setup(tmp_path)
    f.chmod(0o444)
    monkeypatch.setattr(os, "remove",
                        lambda *_: (_ for _ in ()).throw(PermissionError("em uso")))
    with pytest.raises(QuarantineError):
        q.add(finding_for(f))
    assert stat.S_IMODE(f.stat().st_mode) == 0o444 and f.read_bytes() == b"abc"
    assert list((tmp_path / "q").iterdir()) == []


def test_vanished_original_message(tmp_path, monkeypatch):
    f, q = _setup(tmp_path)
    monkeypatch.setattr(os, "remove",
                        lambda *_: (_ for _ in ()).throw(FileNotFoundError("sumiu")))
    with pytest.raises(QuarantineError, match="não existe mais"):
        q.add(finding_for(f))
    assert list((tmp_path / "q").iterdir()) == []


def test_fsync_failure_keeps_original_and_cleans(tmp_path, monkeypatch):
    f, q = _setup(tmp_path)
    called = []

    def fsync(fd):
        called.append(fd)
        raise OSError("disco cheio")

    monkeypatch.setattr(os, "fsync", fsync)
    with pytest.raises(QuarantineError, match="gravar"):
        q.add(finding_for(f))
    assert called and f.read_bytes() == b"abc" and list((tmp_path / "q").iterdir()) == []


def test_fsync_is_called_before_removing_original(tmp_path, monkeypatch):
    f, q = _setup(tmp_path)
    order = []
    real_fsync, real_remove = os.fsync, os.remove
    monkeypatch.setattr(os, "fsync", lambda fd: (order.append("fsync"), real_fsync(fd)))
    monkeypatch.setattr(os, "remove", lambda p: (order.append("remove"), real_remove(p)))
    q.add(finding_for(f))
    assert order.count("fsync") >= 2 and order[-1] == "remove"


def test_chunked_roundtrip_matches_whole_file_scrambling(tmp_path, monkeypatch):
    monkeypatch.setattr(quarantine, "CHUNK", 7)
    data = os.urandom(200)
    f, q = _setup(tmp_path, data)
    qid = q.add(finding_for(f))
    assert (tmp_path / "q" / f"{qid}.bin").read_bytes() == quarantine._xor(data)
    assert q.restore(qid) == f and f.read_bytes() == data


def test_memory_error_leaves_no_orphans(tmp_path, monkeypatch):
    f, q = _setup(tmp_path)
    monkeypatch.setattr(quarantine, "_xor",
                        lambda *_: (_ for _ in ()).throw(MemoryError()))
    with pytest.raises(QuarantineError):
        q.add(finding_for(f))
    assert f.exists() and list((tmp_path / "q").iterdir()) == []


def test_zone_identifier_is_saved_and_rewritten(tmp_path, monkeypatch):
    zone = "[ZoneTransfer]\r\nZoneId=3\r\n"
    monkeypatch.setattr(quarantine, "_read_zone", lambda p: zone)
    written = []
    monkeypatch.setattr(quarantine, "_write_zone", lambda p, t: written.append((p, t)))
    f, q = _setup(tmp_path)
    qid = q.add(finding_for(f))
    assert q.items()[0]["zone_identifier"] == zone
    q.restore(qid)
    assert written == [(f, zone)]


@pytest.mark.parametrize("bad", ["../x", "abc", "A" * 32, "0" * 31 + "\n", "0" * 32 + "/../a"])
def test_invalid_id_is_refused(tmp_path, bad):
    q = Quarantine(tmp_path / "q")
    for op in (q.restore, q.delete):
        with pytest.raises(QuarantineError):
            op(bad)


def test_items_ignores_unreadable_and_malformed_json(tmp_path):
    f, q = _setup(tmp_path)
    good = q.add(finding_for(f))
    base = tmp_path / "q"
    (base / ("1" * 32 + ".json")).write_text("{quebrado")
    (base / ("2" * 32 + ".json")).write_bytes(b"\xff\xfe\x00")
    (base / ("3" * 32 + ".json")).write_text(json.dumps(
        {"id": "3" * 32, "caminho_original": 5, "sha256": "x", "data": "d"}))
    (base / "nao-e-id.json").write_text(json.dumps(
        {"caminho_original": "c", "sha256": "x", "data": "d"}))
    (base / ("4" * 32 + ".json")).write_text(json.dumps(
        {"caminho_original": "c", "sha256": "x", "data": "d", "regras": [1], "severidade": 3}))
    items = {m["id"]: m for m in q.items()}
    assert set(items) == {good, "4" * 32}
    assert items["4" * 32]["regras"] == [] and items["4" * 32]["severidade"] == ""
    with pytest.raises(QuarantineError):  # sem KeyError
        q.restore("3" * 32)


def test_restore_name_taken_twice(tmp_path):
    f, q = _setup(tmp_path)
    qid = q.add(finding_for(f))
    f.write_bytes(b"1")
    (tmp_path / "a (restaurado).ps1").write_bytes(b"2")
    assert q.restore(qid) == tmp_path / "a (restaurado 2).ps1"


def test_restore_hash_mismatch_removes_destination_and_keeps_quarantine(tmp_path, monkeypatch):
    f, q = _setup(tmp_path)
    qid = q.add(finding_for(f))
    monkeypatch.setattr(quarantine, "_sha_plain", lambda p: "0" * 64)
    with pytest.raises(QuarantineError):
        q.restore(qid)
    assert not f.exists() and len(q.items()) == 1
    assert (tmp_path / "q" / f"{qid}.bin").exists()


def test_restore_write_failure_removes_partial_destination(tmp_path, monkeypatch):
    f, q = _setup(tmp_path)
    qid = q.add(finding_for(f))
    monkeypatch.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("cheio")))
    with pytest.raises(QuarantineError):
        q.restore(qid)
    assert not f.exists() and len(q.items()) == 1
