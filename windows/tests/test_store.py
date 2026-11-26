import json
from pathlib import Path

from mandacaru_win.scan import ScanSummary
from mandacaru_win.store import ExcludeList, History, IgnoradosProjeto, TrustList


def test_trust_add_remove_persists(tmp_path):
    t = TrustList(tmp_path / "trust.json")
    t.add("ab" * 32, Path("C:/x/a.ps1"))
    assert TrustList(tmp_path / "trust.json").hashes() == {"ab" * 32}
    t.add("ab" * 32, Path("C:/x/a.ps1"))                    # repetido não duplica
    assert len(t.entries()) == 1
    t.remove("ab" * 32)
    assert TrustList(tmp_path / "trust.json").hashes() == set()


def test_corrupt_trust_starts_empty_and_keeps_file(tmp_path):
    p = tmp_path / "trust.json"
    p.write_text("{quebrado")
    assert TrustList(p).hashes() == set()
    assert (tmp_path / "trust.json.corrompido").read_text() == "{quebrado"


def test_history_recent_order_limit_and_bad_line(tmp_path):
    h = History(tmp_path / "history.jsonl")
    for i in range(3):
        h.append(ScanSummary(started=float(i), paths=["C:/d"], files=i, findings=0, duration=1.0, completed=True))
    with open(tmp_path / "history.jsonl", "a") as fh:
        fh.write("lixo\n")
    assert [r["started"] for r in h.recent(2)] == [2.0, 1.0]


def test_trust_io_error_does_not_move_file(tmp_path, monkeypatch):
    import pytest
    p = tmp_path / "trust.json"
    t = TrustList(p)
    t.add("ab" * 32, Path("C:/x/a.ps1"))
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
    p.write_text("{um")
    TrustList(p)
    p.write_text("{dois")
    TrustList(p)
    backups = sorted(f.read_text() for f in tmp_path.glob("trust.json.corrompido*"))
    assert backups == ["{dois", "{um"]


def test_valid_json_that_is_not_a_list_goes_to_corrompido(tmp_path):
    p = tmp_path / "trust.json"
    p.write_text('{"a": 1}')
    assert TrustList(p).hashes() == set()
    assert (tmp_path / "trust.json.corrompido").read_text() == '{"a": 1}'


def test_failed_save_keeps_memory_and_disk_and_removes_tmp(tmp_path, monkeypatch):
    import os

    import pytest
    p = tmp_path / "trust.json"
    t = TrustList(p)
    t.add("ab" * 32, Path("C:/x/a.ps1"))
    monkeypatch.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("cheio")))
    with pytest.raises(OSError):
        t.add("cd" * 32, Path("C:/x/b.ps1"))
    with pytest.raises(OSError):
        t.remove("ab" * 32)
    monkeypatch.undo()
    assert t.hashes() == {"ab" * 32}
    assert TrustList(p).hashes() == {"ab" * 32}
    assert not (tmp_path / "trust.json.tmp").exists()


def test_save_retries_replace_on_permission_error(tmp_path, monkeypatch):
    import os
    p = tmp_path / "trust.json"
    t = TrustList(p)
    real, calls = os.replace, []

    def flaky(a, b):
        calls.append(1)
        if len(calls) < 3:
            raise PermissionError("em uso")
        real(a, b)

    monkeypatch.setattr(os, "replace", flaky)
    monkeypatch.setattr("mandacaru_win.store.time.sleep", lambda s: None)
    t.add("ab" * 32, Path("C:/x/a.ps1"))
    assert len(calls) == 3 and TrustList(p).hashes() == {"ab" * 32}


def test_failed_corruption_backup_raises_instead_of_starting_empty(tmp_path, monkeypatch):
    import os

    import pytest
    p = tmp_path / "trust.json"
    p.write_text("{quebrado")
    monkeypatch.setattr(os, "replace", lambda *_: (_ for _ in ()).throw(PermissionError("x")))
    with pytest.raises(OSError):
        TrustList(p)
    assert p.read_text() == "{quebrado"


def test_history_skips_rows_with_wrong_types(tmp_path):
    p = tmp_path / "history.jsonl"
    good = {"started": 1.0, "paths": ["C:/d"], "files": 1, "findings": 0,
            "duration": 1.0, "completed": True}
    bad = [{**good, "duration": "abc"}, {**good, "paths": [1]}, {**good, "files": None},
           {**good, "started": [1]}, [1, 2], "x"]
    p.write_text("\n".join(json.dumps(r) for r in [good, *bad]) + "\n")
    assert History(p).recent() == [good]


def test_history_keeps_update_rounds_next_to_scans(tmp_path):
    h = History(tmp_path / "history.jsonl")
    h.append(ScanSummary(started=1.0, paths=["C:/d"], files=1, findings=0, duration=1.0, completed=True))
    h.append_update(2.0, 3.5, [{"id": "7zip.7zip", "nome": "7-Zip", "de": "22.01", "para": "24.08",
                                "resultado": "ok"}])
    with open(tmp_path / "history.jsonl", "a") as fh:
        fh.write(json.dumps({"tipo": "atualizacao", "started": 3.0, "programas": [{"id": 1}]}) + "\n")
    rows = h.recent()
    assert [r.get("tipo") for r in rows] == ["atualizacao", None]
    assert rows[0]["programas"][0]["resultado"] == "ok" and rows[0]["duration"] == 3.5


def test_exclude_list_add_remove_persists_and_deduplicates(tmp_path):
    p = tmp_path / "excludes.json"
    alvo = tmp_path / "jogos"
    ex = ExcludeList(p)
    ex.add(alvo)
    ex.add(alvo)  # repetido não duplica
    assert len(ex.entries()) == 1
    assert ExcludeList(p).paths() == [str(alvo.resolve())]
    ex.remove(alvo)
    assert ExcludeList(p).paths() == []


def test_corrupt_excludes_starts_empty_and_keeps_backup(tmp_path):
    p = tmp_path / "excludes.json"
    p.write_text("{quebrado")
    assert ExcludeList(p).paths() == []
    assert (tmp_path / "excludes.json.corrompido").read_text() == "{quebrado"


def test_ignorados_projeto_persiste_por_regra_e_sha(tmp_path):
    p = tmp_path / "ignorados_projeto.json"
    ig = IgnoradosProjeto(p)
    ig.adicionar("r", "abc", Path("C:/proj/AGENTS.md"))
    ig.adicionar("r", "abc", Path("C:/proj/AGENTS.md"))  # repetido não duplica
    outra = IgnoradosProjeto(p)
    assert outra.contem("r", "abc") is True
    assert outra.contem("r", "outro") is False
    assert outra.contem("s", "abc") is False
    assert len(outra.entries()) == 1
    assert outra.entries()[0]["caminho"] == str(Path("C:/proj/AGENTS.md"))


def test_ignorados_projeto_corrompido_gera_backup_e_comeca_vazio(tmp_path):
    p = tmp_path / "ignorados_projeto.json"
    p.write_text("{quebrado")
    ig = IgnoradosProjeto(p)
    assert ig.entries() == [] and ig.contem("r", "abc") is False
    assert (tmp_path / "ignorados_projeto.json.corrompido").read_text() == "{quebrado"


def test_ignorados_projeto_pula_entradas_com_tipo_errado(tmp_path):
    p = tmp_path / "ignorados_projeto.json"
    p.write_text(json.dumps([{"regra": "r", "sha256": "abc"}, {"regra": ["x"], "sha256": "abc"},
                             {"regra": "r", "sha256": {"a": 1}}, 3, "x"]))
    ig = IgnoradosProjeto(p)
    assert len(ig.entries()) == 1 and ig.contem("r", "abc")
