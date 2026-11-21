# Classificador local de malware por IA — Plano 2: treino, prova de qualidade e liberação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produzir o primeiro modelo real (ELF e scripts), treinado com segurança num ambiente isolado e com **0% de uso de GPU**, aprovado ou reprovado por tipo num portão de qualidade medido, publicado no pacote em modo sombra e, depois de 2 a 4 semanas revisadas no SUPRA, liberado para isolar.

**Architecture:** Pipeline em `tools/treino/` (fora do pacote), com etapas pequenas, incrementais e testáveis: corpus em zips AES (`ZIP_DEFLATED` nível 1 ou `ZIP_STORED`, nunca extraídos no disco) → coleta (catálogo histórico `full.csv.zip` + MalwareBazaar + legítimos em streaming com metadado de pacote) → higiene e divisões (temporal, por família sem `"sem_familia"`, e benignos por pacote) → extração incremental em memória para cache SQLite (`~/cache/features.sqlite`, usando o **mesmo** `mandacaru.ml.features` + `StaticScanner` com extensão sintética do `kind`) → treino de gradient boosting em CPU (`float32`, `OMP_NUM_THREADS=4`, `sample_weight` maior nos legítimos difíceis) → calibração em split separado (`cal_fit`/`cal_limiar`) e escolha de limiares → avaliação vetorizada e portão → exportação para o JSON compacto estrito do Plano 1 + `tests/fixtures/ml_golden.json` + relatório + manifesto. A Parte A (código) é toda testada na `Ubuntu-Dev` com dados sintéticos inofensivos em `tests/treino/`. A Parte B (operação) baixa na `UbuntuPentest` e roda extração (`libyara`), treino, avaliação e exportação **sem rede** dentro de `bubblewrap` (`bwrap --unshare-net`, sem `/dev/dxg`).

**Tech Stack:** Python ≥ 3.10; dependências **só de treino**, no extra `[project.optional-dependencies] treino` em `pyproject.toml` e num venv próprio na `UbuntuPentest`: `scikit-learn`, `numpy`, `pyzipper` (zip AES), `zstandard` só se o Python for `< 3.14` (o 3.14 tem `compression.zstd`), além de `yara-python` (ou `python3-yara` do `apt` para o `StaticScanner`). Runtime do Mandacaru continua sem dependência nova e o treino usa **100% CPU** (GTX 1650 intacta, zero CUDA/GPU).

**Spec:** `docs/superpowers/specs/2026-11-20-classificador-ia-malware-design.md` (seções 10, 14, 15, 16)

**Depende de:** Plano 1 (`docs/superpowers/plans/2026-11-20-classificador-ia-runtime.md`), já na branch `feat/classificador-ia` (PR VandyckLN/mandacaru#7). Esta branch, `feat/classificador-ia-treino`, sai dela.

## Global Constraints

- **Uso zero de GPU:** `HistGradientBoostingClassifier` roda 100% em CPU (`OMP_NUM_THREADS=4`, `nice -n 15`, matrizes `float32` no treino e `float64` só nos vetores do `golden.json`); o ambiente isolado de treino não monta `/dev/dxg` nem exige CUDA.
- **Regras de ouro (spec 10.2), impostas por teste AST em `tests/treino/test_politica_treino.py`:**
  - em `tools/treino/` nada de `subprocess`, `pty`, `ctypes`, `cffi`, `importlib`, `pickle`, `marshal`, `shelve`, `webbrowser`;
  - proibidos os atributos e chamadas `system`, `popen`, `posix_spawn`, `posix_spawnp`, qualquer `exec*`/`spawn*`, `extract`, `extractall`, `unpack_archive`, `chmod`, `fchmod`;
  - proibido importar esses nomes com `from os import ...`, `from posix import ...`, `from shutil import ...`, `from zipfile import ...`, `from tarfile import ...` ou mascarar com alias (`import os as o`);
  - proibidos builtins dinâmicos (`eval`, `exec`, `compile`, `__import__`);
  - nenhum byte de amostra escrito em disco fora do zip AES original; nenhuma ferramenta externa toca em amostra.
- **Limites de leitura e arquivo:** amostra lida só em memória com limite estrito `< MAX_BYTES` (`8 * 1024 * 1024`, idêntico ao `static.py` e ao `cli.py` do runtime), conferido antes no tamanho do arquivo `.zip` (`<= MAX_ZIP_BYTES`, isto é, `MAX_BYTES + 1 MB`), depois em `ZipInfo.file_size` **antes** de ler e novamente na leitura; rejeitar diretórios e symlinks (tanto em disco quanto dentro de `.zip`/`.tar`).
- **Zip das amostras:** AES (`WZ_AES`), senha `infected` (padrão do MalwareBazaar). Legítimos são gravados com `ZIP_DEFLATED` (`compresslevel=1`) ou `ZIP_STORED` (nunca `ZIP_LZMA`, para não queimar CPU) e a mesma senha/criptografia AES, para um só leitor e para o Mandacaru/antivírus não reagirem.
- **Orçamento de disco e localização do corpus:** corpus fora de qualquer repositório git, fora das pastas vigiadas e fora de `/mnt`: padrão `~/corpus` (`0700`) no usuário `treino` da `UbuntuPentest`, com teto configurável (`--max-corpus-gb`, padrão `20`). Nunca na `Ubuntu-Dev`.
- **Segredos:** chave do MalwareBazaar só na variável de ambiente `MB_AUTH_KEY`; nunca em arquivo, log, commit ou cabeçalho repassado em redirecionamento HTTP.
- **Logs e relatórios:** só hashes, contagens e números; nunca bytes de amostra.
- **Testes e empacotamento separados:** todos os testes do pipeline ficam em `tests/treino/` e são ignorados no build do `.deb` (`debian/rules`: `--ignore=tests/test_packaging.py --ignore=tests/treino`); dependências de treino ficam no extra `[project.optional-dependencies] treino` de `pyproject.toml` (o CI instala `.[dev,treino]`).
- **`golden.json` fora do pacote instalado:** fica em `tests/fixtures/ml_golden.json` (nunca dentro de `src/mandacaru/ml/models/`), mantendo `src/mandacaru/ml/models/` apenas com `elf.json` e `script.json` (compatível com `tests/test_politica.py` e sem inflar `.deb`/wheel).
- **Sandbox sem rede na Parte B:** extração (incluindo `libyara`), treino, avaliação e exportação rodam dentro de `bubblewrap` (`bwrap --unshare-net`, `~/corpus` em `--ro-bind`, `~/cache` e `~/saida` em `--bind`, `--tmpfs /tmp`, `--cap-drop ALL`, `--new-session`, sem `/dev/dxg`, `ulimit -v`).
- **Metas do portão (spec 10.4), por tipo:** FP ≤ 0,05 % com ≥ 6.000 legítimos no teste; FP por categoria de legítimo difícil ≤ 0,5 %; detecção ≥ 80 % nos malwares que as regras atuais deixam passar; ≥ 500 maliciosos no teste; JSON compacto (`separators=(",", ":")`) ≤ 3 MB; strings em `metrics` ≤ 64 caracteres (exigência de `tests/test_politica.py`); mediana ≤ 30 ms e p99 ≤ 150 ms no SUPRA (já garantidos pelo Plano 1).
- **Modelo:** `HistGradientBoostingClassifier` (`max_iter ≤ 300`, `max_depth = 8`, `max_leaf_nodes = 31`, `min_samples_leaf = 30`, `l2_regularization = 1.0`, `float32` no treino, `sample_weight` maior nos legítimos difíceis), um por família (`elf`, `script`).
- **Saída do ambiente de treino:** pasta dedicada `~/saida/<model_id>/` contendo exatamente `elf.json`, `script.json`, `golden.json`, `relatorio-<model_id>.md` e `manifesto-<model_id>.txt` (hashes). Tudo texto, validado na chegada (sem symlinks e sem sequências de escape ANSI).
- **Estilo e commits:** ruff `line-length = 120`, regras `E, F, W, I, B`. Mensagens em código e CLI em português sem acento (documentação `.md` em português brasileiro). Commits como `VandyckLN <183553227+VandyckLN@users.noreply.github.com>`, sem `Co-Authored-By`.

## Review Focus

- AST checker pega violações disfarçadas (`from os import system`, `import os as o; o.posix_spawn(...)`, `z.extract('x')`, `import importlib`, `eval('1')`) (teste na Task 1).
- `Entry` rejeita `sha256` fora de `^[0-9a-f]{64}$` (anti path-traversal); zip bomba, `>= MAX_BYTES`, symlink interno, arquivo corrompido, senha errada, mais de um membro ou estouro de `--max-corpus-gb` são rejeitados/pulados sem extrair nada (teste na Task 2).
- `baixar.py` recusa redirecionamentos HTTP 30x (não vaza `MB_AUTH_KEY`), respeita teto diário/disco sem repetir downloads e suporta catálogo histórico `full.csv.zip` (teste na Task 3).
- `benignos.py` lê `.deb` em streaming tratando padding de 1 byte em membro `ar` de tamanho ímpar, ignora symlinks e membros `>= MAX_BYTES` e registra `Entry.package` (teste na Task 4).
- O mesmo hash nos dois lados (malicioso e legítimo) sai dos dois; `"sem_familia"` não entra no sorteio de `frac_familias_teste`; legítimos são divididos pelo pacote de origem (teste na Task 5).
- `extrair.py` usa `StaticScanner` instanciado uma vez com extensão sintética (dispara `heur.obfuscated_script`), cacheia vetores `float32` em SQLite WAL e salva/carrega em `.npz` (`allow_pickle=False`) (teste na Task 6).
- Calibração em `cal_fit` separada da escolha de limiares em `cal_limiar`, `len(calib_x) >= 2` com `calib_x` estritamente crescente mesmo em caso extremo, e ordem `medio <= reforco <= alto <= alto_tmp` (teste na Task 7).
- Tipo com poucos dados gera `gate_passed = false` e motivo no relatório; regressão de FP contra `Model` anterior (JSON, sem pickle) reprova o portão (teste na Task 8).
- Exportador extrai `float(clf._baseline_prediction.item())`, recalcula nós internos ponderados por `count`, gera JSON compacto ≤ 3 MB e `golden.json` em `float64` validado com `1e-9` (teste na Task 9).
- `instalar_modelo.py` valida os 5 artefatos (recusa symlinks, estranhos e escapes ANSI), instala `golden.json` em `tests/fixtures/ml_golden.json` e atualiza `MODEL_SHA256`; `mandacaru ml avaliar --stdin --jsonl` processa lista via stdin numa única execução (teste na Task 10).

---

# Parte A — Código (Ubuntu-Dev, dados sintéticos)

### Task 1: Esqueleto de `tools/treino/`, extra `treino`, ajuste do `.deb`/CI e teste de política

**Files:**
- Create: `tools/treino/__init__.py` (docstring), `tools/treino/requirements.in` (`scikit-learn`, `numpy`, `pyzipper`, `zstandard; python_version < "3.14"` — e nota sobre `yara-python` / `python3-yara` do `apt`), `tools/treino/requirements.txt` (gerado a partir do `.in` com `pip-compile --generate-hashes` numa venv temporária com `pip-tools`, sem nenhuma amostra envolvida), `tools/treino/README.md` (resumo das regras de ouro, uso zero de GPU e link para a Parte B deste plano)
- Create: `tests/treino/__init__.py`, `tests/treino/test_politica_treino.py`
- Modify: `pyproject.toml` (adicionar extra `treino = ["scikit-learn>=1.4", "numpy>=1.26", "pyzipper>=0.3", "zstandard>=0.22; python_version < '3.14'"]` sem tocar em `dependencies` nem inflar `dev`)
- Modify: `debian/rules` (`export PYBUILD_TEST_ARGS = --ignore=tests/test_packaging.py --ignore=tests/treino` — preserva a substring exigida por `tests/test_packaging.py`)
- Modify: `.github/workflows/ci.yml` (`pip install -e ".[dev,treino]"`)

**Interfaces:**
- Produces: a pasta `tools/treino/` como pacote importável (`import tools.treino.corpus` com `cwd` na raiz do repo; os testes põem a raiz e `tests/treino` no `sys.path`).

- [ ] **Step 1: Write the failing test** (`tests/treino/test_politica_treino.py`)

```python
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TREINO = ROOT / "tools" / "treino"
PROIBIDOS_IMPORT = {
    "subprocess", "pty", "ctypes", "cffi", "importlib",
    "pickle", "marshal", "shelve", "webbrowser",
}
PROIBIDOS_MOD_ATRIB = {"os", "posix", "shutil", "zipfile", "tarfile"}
PROIBIDOS_ATRIB = {
    "system", "popen", "posix_spawn", "posix_spawnp",
    "extract", "extractall", "unpack_archive", "chmod", "fchmod",
}
PROIBIDOS_PREFIXOS = ("exec", "spawn", "posix_spawn")
PROIBIDOS_BUILTINS = {"eval", "exec", "compile", "__import__"}


def violacoes(arquivos):
    achados = []
    for p in arquivos:
        tree = ast.parse(p.read_text(), filename=str(p))
        aliases_mod = set(PROIBIDOS_MOD_ATRIB)
        nomes_proibidos = set(PROIBIDOS_BUILTINS)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    base = a.name.split(".")[0]
                    if base in PROIBIDOS_IMPORT:
                        achados.append(f"{p.name}: import {a.name}")
                    if base in PROIBIDOS_MOD_ATRIB:
                        aliases_mod.add(a.asname or base)
            elif isinstance(node, ast.ImportFrom):
                base = (node.module or "").split(".")[0]
                if base in PROIBIDOS_IMPORT:
                    achados.append(f"{p.name}: from {node.module}")
                if base in PROIBIDOS_MOD_ATRIB:
                    for a in node.names:
                        if a.name == "*" or a.name in PROIBIDOS_ATRIB or a.name.startswith(PROIBIDOS_PREFIXOS):
                            achados.append(f"{p.name}:{node.lineno}: from {node.module} import {a.name}")
                            nomes_proibidos.add(a.asname or a.name)
            elif isinstance(node, ast.Attribute):
                if node.attr in PROIBIDOS_ATRIB:
                    achados.append(f"{p.name}:{node.lineno}: .{node.attr}")
                elif node.attr.startswith(PROIBIDOS_PREFIXOS) and isinstance(node.value, ast.Name) \
                        and node.value.id in aliases_mod:
                    achados.append(f"{p.name}:{node.lineno}: {node.value.id}.{node.attr}")
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in nomes_proibidos:
                achados.append(f"{p.name}:{node.lineno}: {node.func.id}()")
    return achados


def test_existe_e_tem_codigo():
    assert (TREINO / "__init__.py").is_file()


def test_nenhum_import_ou_chamada_proibida():
    assert violacoes(sorted(TREINO.rglob("*.py"))) == []


def test_politica_pega_violacao(tmp_path):
    casos_ruins = (
        "import subprocess\n",
        "import os\nos.system('x')\n",
        "from os import system\nsystem('x')\n",
        "import os as o\no.posix_spawn('/bin/sh', ['sh'], {})\n",
        "from shutil import unpack_archive\n",
        "z.extractall('d')\n",
        "z.extract('x', 'd')\n",
        "import os\nos.execv('a', [])\n",
        "from ctypes import CDLL\n",
        "import importlib\n",
        "import pickle\n",
        "eval('1 + 1')\n",
    )
    for codigo in casos_ruins:
        (tmp_path / "ruim.py").write_text(codigo)
        assert violacoes([tmp_path / "ruim.py"]), codigo


def test_treino_fora_do_pacote():
    toml = (ROOT / "pyproject.toml").read_text()
    assert 'where = ["src"]' in toml.split("[tool.setuptools.packages.find]")[1].split("[")[0]
    assert "treino =" in toml.split("[project.optional-dependencies]")[1].split("[")[0]
    assert "--ignore=tests/treino" in (ROOT / "debian" / "rules").read_text()
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/treino/test_politica_treino.py -q`
Expected: FAIL em `test_existe_e_tem_codigo`

- [ ] **Step 3: Create and update the files listed above**

Garantir que `debian/rules` mantenha `--ignore=tests/test_packaging.py --ignore=tests/treino` na mesma linha `export PYBUILD_TEST_ARGS = ...` para continuar passando em `tests/test_packaging.py`. No `tools/treino/README.md`, registrar explicitamente que o pipeline roda **100% em CPU** (0% GPU) e explicar a extração do `yara-python` / `python3-yara` no Python 3.14.

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/treino/test_politica_treino.py tests/test_packaging.py -q && .venv/bin/ruff check .`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add tools/treino tests/treino/__init__.py tests/treino/test_politica_treino.py pyproject.toml debian/rules .github/workflows/ci.yml
git commit -m "Treino: esqueleto de tools/treino, extra treino, ignore no deb e teste de politica endurecido"
```

---

### Task 2: Corpus em zips AES, lido só em memória, com manifesto em append e orçamento de disco

**Files:**
- Create: `tools/treino/corpus.py`
- Create: `tests/treino/helpers.py`
- Create: `tests/treino/test_corpus.py`

**Interfaces:**
- Produces (`tools/treino/corpus.py`):
  - `SENHA = b"infected"`; `MAX_BYTES = 8 * 1024 * 1024`; `MAX_ZIP_BYTES = MAX_BYTES + 1024 * 1024`
  - `_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")`
  - `@dataclass(frozen=True) class Entry: sha256: str; label: int; source: str; family: str; first_seen: str; reporter: str; categoria: str; package: str = ""`
    - `__post_init__` valida `_SHA256_RE.fullmatch(self.sha256)` (anti path-traversal; levanta `ValueError` se inválido) e `self.label in (0, 1)`.
  - `class Corpus: __init__(self, root: Path, *, max_disk_bytes: int | None = 20 * 1024**3)` com pastas `root/malicioso/<sha>.zip`, `root/legitimo/<sha>.zip` e manifesto `root/manifesto.jsonl` (uma `Entry` JSON por linha); `root` criada `0700`.
    - Carrega as entradas existentes do `manifesto.jsonl` no `__init__`, mantendo um índice `_hashes: set[str]` e `_disk_bytes: int` em memória; se a última linha estiver truncada por queda anterior, ignora apenas essa linha com aviso em `stderr`.
  - `Corpus.has(sha256: str) -> bool`, `Corpus.disk_usage_bytes() -> int`
  - `Corpus.add_zip(entry: Entry, zip_bytes: bytes) -> bool`: valida tamanho do zip `<= MAX_ZIP_BYTES`, confere se o hash já existe ou se passaria `max_disk_bytes`, valida dentro do zip AES (1 membro, não diretório, não symlink Unix, `info.file_size < MAX_BYTES`, leitura `< MAX_BYTES` e SHA-256 igual a `entry.sha256`) **em memória**; grava o zip atomicamente (temp + `os.replace`) e faz **append** de uma linha no `manifesto.jsonl` (`O_APPEND`, sem reescrever o arquivo inteiro).
  - `Corpus.add_bytes(entry: Entry, data: bytes) -> bool` (legítimos): exige `len(data) < MAX_BYTES`, confere SHA-256 e orçamento de disco; cria o zip AES em memória com `pyzipper.ZIP_DEFLATED` (`compresslevel=1`) e `encryption=pyzipper.WZ_AES` (rápido na CPU e leve em RAM; nunca `ZIP_LZMA`) e grava atomicamente + append no manifesto.
  - `Corpus.entries() -> list[Entry]`
  - `Corpus.read(entry: Entry) -> bytes | None`: verifica se o `.zip` não é symlink (`is_symlink()`) e tem tamanho `<= MAX_ZIP_BYTES`; abre com `pyzipper.AESZipFile`, exige exatamente 1 membro que não seja diretório (`info.is_dir()`) nem symlink (`stat.S_ISLNK(info.external_attr >> 16)`), confere `info.file_size < MAX_BYTES` **antes** de ler e lê `zf.open(info).read(MAX_BYTES)`. Retorna `None` e imprime `"aviso: ..."` em `stderr` se `len(data) >= MAX_BYTES` ou ocorrer erro de zip/senha/tamanho.

- [ ] **Step 1: Write the failing tests** (`tests/treino/helpers.py` e `tests/treino/test_corpus.py`)

```python
import hashlib, io, stat, sys
from pathlib import Path
import pytest

pyzipper = pytest.importorskip("pyzipper")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import zip_aes
from tools.treino.corpus import MAX_BYTES, SENHA, Corpus, Entry


def _e(sha, label=1, package=""):
    return Entry(sha, label, "teste", "Fam", "2026-11-01", "r", "geral", package=package)


def test_ida_e_volta_sem_extrair(tmp_path):
    c = Corpus(tmp_path / "c")
    data = b"#!/bin/sh\necho inofensivo\n"
    sha = hashlib.sha256(data).hexdigest()
    assert c.add_zip(_e(sha), zip_aes(sha, data))
    assert c.read(c.entries()[0]) == data
    arquivos = {p.name for p in (tmp_path / "c").rglob("*") if p.is_file()}
    assert arquivos == {f"{sha}.zip", "manifesto.jsonl"}          # nada extraido no disco
    assert (tmp_path / "c").stat().st_mode & 0o777 == 0o700


def test_entry_rejeita_path_traversal():
    with pytest.raises(ValueError):
        _e("../../etc/passwd")
    with pytest.raises(ValueError):
        _e("z" * 64)


def test_hash_errado_duplicado_e_legitimo(tmp_path):
    c = Corpus(tmp_path / "c")
    assert c.add_zip(_e("0" * 64), zip_aes("x", b"outro")) is False
    data = b"legitimo"
    sha = hashlib.sha256(data).hexdigest()
    assert c.add_bytes(_e(sha, label=0, package="pkg"), data)
    assert c.add_bytes(_e(sha, label=0, package="pkg"), data) is False
    assert c.read(c.entries()[0]) == data and c.entries()[0].package == "pkg"


@pytest.mark.parametrize("zip_ruim", [
    lambda: b"nao e zip",
    lambda: zip_aes("x", b"a", senha=b"outra"),
    lambda: zip_aes("x", b"a", membros=2),
    lambda: zip_aes("x", b"/etc/passwd", symlink=True),
])
def test_zip_ruim_e_pulado(tmp_path, zip_ruim, capsys):
    c = Corpus(tmp_path / "c")
    sha = hashlib.sha256(b"a").hexdigest()
    (tmp_path / "c" / "malicioso").mkdir(parents=True, exist_ok=True)
    (tmp_path / "c" / "malicioso" / f"{sha}.zip").write_bytes(zip_ruim())
    assert c.read(_e(sha)) is None and "aviso" in capsys.readouterr().err


def test_limite_estrito_max_bytes_e_orcamento_disco(tmp_path):
    c = Corpus(tmp_path / "c")
    igual = b"\0" * MAX_BYTES
    sha = hashlib.sha256(igual).hexdigest()
    assert c.add_zip(_e(sha), zip_aes(sha, igual)) is False        # < MAX_BYTES (igual ao runtime)
    c_peq = Corpus(tmp_path / "c2", max_disk_bytes=600)
    d1 = b"A" * 200
    assert c_peq.add_bytes(_e(hashlib.sha256(d1).hexdigest(), label=0), d1)
    d2 = b"B" * 500
    assert c_peq.add_bytes(_e(hashlib.sha256(d2).hexdigest(), label=0), d2) is False
```

*(Em `tests/treino/helpers.py`, `zip_aes(nome, data, *, senha=SENHA, membros=1, symlink=False)` usa `pyzipper.ZIP_DEFLATED` com `compresslevel=1`, `encryption=pyzipper.WZ_AES`; quando `symlink=True`, cria `ZipInfo(nome)` com `external_attr = (stat.S_IFLNK | 0o777) << 16` e `z.writestr(zi, data)`.)*

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/pip install pyzipper && .venv/bin/python -m pytest tests/treino/test_corpus.py -q`
Expected: FAIL (`ModuleNotFoundError: tools.treino.corpus`)

- [ ] **Step 3: Implement `tools/treino/corpus.py` and `tests/treino/helpers.py`**

*(O `pyzipper` entra no extra `treino` em `pyproject.toml`, nunca em `[project.dependencies]`.)*
Implementar append seguro no `manifesto.jsonl` (`os.open(..., os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)` + `os.write` completo) e gravação atômica para cada `.zip` via arquivo temporário + `os.replace`. Garantir que `Corpus.read` faça `stat` sem seguir symlinks antes de abrir.

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/treino/test_corpus.py tests/treino/test_politica_treino.py -q && .venv/bin/ruff check .`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add tools/treino/corpus.py tests/treino/helpers.py tests/treino/test_corpus.py pyproject.toml
git commit -m "Treino: corpus em zips AES deflate, append no manifesto, validacao estrita e teto de disco"
```

---

### Task 3: Coleta no MalwareBazaar (catálogo histórico + incremental seguro)

**Files:**
- Create: `tools/treino/baixar.py`
- Create: `tests/treino/test_baixar.py`

**Interfaces:**
- Consumes: `Corpus`, `Entry`, `MAX_ZIP_BYTES` (Task 2).
- Produces:
  - `API = "https://mb-api.abuse.ch/api/v1/"`; `TIPOS_MB = ("elf", "sh", "py", "pl", "js", "php")`
  - `HttpPost = Callable[[str, dict[str, str], dict[str, str]], tuple[int, bytes]]` (url, cabeçalhos, campos do formulário → status, corpo)
  - `selecionar_catalogo(catalogo_zip: Path, corpus: Corpus, *, tipos=TIPOS_MB, desde: str | None = None, cota: int = 500, max_por_familia: int = 300, max_por_remetente: int = 1000) -> list[dict]`: lê o CSV histórico do MalwareBazaar (`full.csv.zip`) em streaming dentro do zip, filtra apenas entradas fora do `corpus` com `file_type in tipos` e `first_seen >= desde`, aplicando tetos por família (`signature` ou `"sem_familia"`) e remetente (`reporter`) já somados ao que existe no `corpus`, devolvendo lista ordenada/estratificada até `cota`. Isso resolve o limite de `get_file_type` (que só retorna os 1.000 mais recentes) e garante janela temporal longa para treino vs. teste.
  - `listar(tipo: str, *, chave: str, http: HttpPost, limite: int = 1000) -> list[dict]` (`query=get_file_type`, `file_type=tipo`, `limit=limite`)
  - `@dataclass class Resultado: baixados: int; pulados: int; parou: str | None`
  - `coletar(corpus: Corpus, *, chave: str, http: HttpPost, tipos=TIPOS_MB, cota: int = 500, max_por_familia: int = 300, max_por_remetente: int = 1000, catalogo: Path | None = None, desde: str | None = None) -> Resultado`: se `catalogo` for passado, usa `selecionar_catalogo`; caso contrário, lista cada tipo via `listar`. Ignora hashes já no `corpus`, baixa com `query=get_file` + `sha256_hash` até `cota` (ou até atingir `max_disk_bytes` do corpus) e grava com `Corpus.add_zip`. Distingue resposta ZIP (`PK\x03\x04`) de JSON (`{`): `query_status` diferente de `ok` (inclusive limite diário) → para imediatamente com `parou = status`, sem perder o que já gravou.
  - `_http_padrao`: usa `urllib.request` com `HTTPRedirectHandler` customizado que **bloqueia redirecionamentos 30x** (evita vazar `Auth-Key` para outro host), valida `url.startswith("https://")`, timeout de 60 s, backoff exponencial em HTTP `429`/`5xx` (até 3 tentativas) e leitura limitada a `MAX_ZIP_BYTES + 1`.
  - `main(argv=None) -> int`: lê `MB_AUTH_KEY` do ambiente (ausente → mensagem e saída 1), `--corpus`, `--cota`, `[--catalogo ARQUIVO]`, `[--desde AAAA-MM-DD]`, `[--max-corpus-gb N]`; imprime só contagens.
- O cabeçalho é `Auth-Key: <chave>`. A chave nunca é impressa nem gravada.

- [ ] **Step 1: Write the failing tests** (`tests/treino/test_baixar.py`)

```python
import hashlib, io, json, sys, urllib.error, zipfile
from pathlib import Path
import pytest

pytest.importorskip("pyzipper")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import zip_aes
from tools.treino import baixar
from tools.treino.baixar import coletar
from tools.treino.corpus import Corpus

AMOSTRAS = {hashlib.sha256(f"amostra {i}".encode()).hexdigest(): f"amostra {i}".encode() for i in range(6)}


def http_falso(limite_depois=None):
    chamadas = []
    def http(url, cab, campos):
        chamadas.append(campos)
        assert cab["Auth-Key"] == "segredo"
        if campos["query"] == "get_file_type":
            data = [{"sha256_hash": s, "signature": "FamA" if i < 4 else None, "reporter": "r1",
                     "first_seen": f"2026-11-0{i + 1} 00:00:00", "file_type": campos["file_type"]}
                    for i, s in enumerate(AMOSTRAS)] if campos["file_type"] == "elf" else []
            return 200, json.dumps({"query_status": "ok" if data else "no_results", "data": data}).encode()
        n = sum(1 for c in chamadas if c["query"] == "get_file")
        if limite_depois is not None and n > limite_depois:
            return 200, json.dumps({"query_status": "daily_limit_reached"}).encode()
        s = campos["sha256_hash"]
        return 200, zip_aes(s, AMOSTRAS[s])
    return http, chamadas


def test_coleta_com_tetos_e_sem_repetir(tmp_path):
    c = Corpus(tmp_path / "c")
    http, _ = http_falso()
    r = coletar(c, chave="segredo", http=http, cota=10, max_por_familia=3)
    assert r.baixados == 5 and r.parou is None                    # 3 da FamA + 2 sem familia
    http2, chamadas2 = http_falso()
    assert coletar(c, chave="segredo", http=http2, cota=10, max_por_familia=3).baixados == 0
    assert not [x for x in chamadas2 if x["query"] == "get_file"]  # nada baixado de novo


def test_catalogo_historico_filtra_por_data_e_familia(tmp_path):
    cat = tmp_path / "full.csv.zip"
    linhas = ['# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"\n']
    shas = list(AMOSTRAS)
    linhas.append(f'"2025-01-01 00:00:00","{shas[0]}","","","r1","a","elf","","FamA","","","","",""\n')
    linhas.append(f'"2026-06-01 00:00:00","{shas[1]}","","","r1","b","elf","","FamA","","","","",""\n')
    linhas.append(f'"2026-07-01 00:00:00","{shas[2]}","","","r2","c","sh","","n/a","","","","",""\n')
    with zipfile.ZipFile(cat, "w") as z:
        z.writestr("full.csv", "".join(linhas))
    c = Corpus(tmp_path / "c")
    http, chamadas = http_falso()
    r = coletar(c, chave="segredo", http=http, catalogo=cat, desde="2026-01-01", cota=10)
    baixados = [x["sha256_hash"] for x in chamadas if x["query"] == "get_file"]
    assert r.baixados == 2 and set(baixados) == {shas[1], shas[2]}


def test_limite_diario_para_e_guarda_o_progresso(tmp_path):
    c = Corpus(tmp_path / "c")
    http, _ = http_falso(limite_depois=2)
    r = coletar(c, chave="segredo", http=http, cota=10)
    assert r.baixados == 2 and r.parou == "daily_limit_reached" and len(c.entries()) == 2


def test_http_padrao_recusa_redirect_para_nao_vazar_chave():
    handler = baixar._NoRedirectHandler()
    with pytest.raises(urllib.error.HTTPError):
        handler.redirect_request(None, None, 302, "Found", {}, "https://evil.invalid/")


def test_chave_nunca_aparece(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("MB_AUTH_KEY", raising=False)
    assert baixar.main(["--corpus", str(tmp_path / "c")]) == 1
    monkeypatch.setenv("MB_AUTH_KEY", "segredo")
    monkeypatch.setattr(baixar, "_http_padrao", http_falso()[0])
    baixar.main(["--corpus", str(tmp_path / "c"), "--cota", "1"])
    saida = capsys.readouterr()
    assert "segredo" not in saida.out + saida.err
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/treino/test_baixar.py -q`
Expected: FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: Implement `tools/treino/baixar.py`**

Normalizar `first_seen` para `AAAA-MM-DD`; família vazia ou `"n/a"` → `"sem_familia"`. No catálogo `full.csv.zip`, ignorar linhas de comentário (`#`) e ler via `csv.reader` em `io.TextIOWrapper(..., encoding="utf-8", errors="replace")` (sem carregar o CSV inteiro na RAM).

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/treino/test_baixar.py tests/treino/test_politica_treino.py -q && .venv/bin/ruff check .`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add tools/treino/baixar.py tests/treino/test_baixar.py
git commit -m "Treino: coleta do MalwareBazaar com catalogo historico, sem redirects e tetos por familia"
```

---

### Task 4: Ingestão de legítimos em streaming a partir de pacotes

**Files:**
- Create: `tools/treino/benignos.py`
- Create: `tests/treino/test_benignos.py`

**Interfaces:**
- Consumes: `Corpus`, `Entry`, `MAX_BYTES` (Task 2); `mandacaru.ml.kind.detect_kind`.
- Produces:
  - `membros_deb_stream(fh: BinaryIO) -> Iterator[tuple[str, bytes]]` e `membros_deb(deb: bytes) -> Iterator[tuple[str, bytes]]`: lê o formato `ar` em **streaming** (`!<arch>\n`, cabeçalhos de 60 bytes, `seek` para pular membros ignorados **somando `+ 1` byte de padding quando o tamanho do membro `ar` for ímpar**) e abre `data.tar.{xz,zst,gz}` via stream (`lzma.LZMAFile`, `compression.zstd` no 3.14 ou `zstandard.ZstdDecompressor.stream_reader`, `gzip.GzipFile`) + `tarfile.open(fileobj=..., mode="r|*")`, sem descomprimir o pacote inteiro na RAM. Devolve `(caminho, bytes)` apenas para membros regulares (`m.isreg()`) com `0 < m.size < MAX_BYTES` (ignora symlinks, hardlinks, diretórios e arquivos `>= MAX_BYTES` antes de ler).
  - `membros_arquivo(nome: str, data: bytes) -> Iterator[tuple[str, bytes]]` e `membros_caminho(path: Path) -> Iterator[tuple[str, bytes]]`: `.deb` em streaming do disco; `.whl`/`.zip` via `zipfile` checando `not info.is_dir()`, não symlink Unix e `info.file_size < MAX_BYTES`; `.tar.gz`/`.tgz` via `tarfile` streaming (`mode="r|gz"`) checando `m.isreg()` e `m.size < MAX_BYTES`; qualquer outro arquivo regular `< MAX_BYTES` → o próprio arquivo como um membro.
  - `nome_pacote(path: Path) -> str`: extrai o identificador do pacote (ex.: `ola` de `ola_1.0_all.deb`, `pkg` de `pkg-1.0.0.tgz` ou `pkg-1.0-py3-none-any.whl`) para gravar em `Entry.package`.
  - `ingerir(corpus: Corpus, pasta: Path, *, source: str, categoria: str = "geral", first_seen: str) -> int`: percorre `pasta` sem seguir symlinks (`os.walk(..., followlinks=False)` e pula `p.is_symlink()`), lê membros em streaming, guarda como legítimo (`label=0`, `package=nome_pacote(p)`) só os que `detect_kind` reconhece, e devolve quantos entraram. Nada é extraído no disco.
  - `main(argv=None) -> int`: `python -m tools.treino.benignos --corpus DIR --pasta DIR --source NOME [--categoria NOME] [--data AAAA-MM-DD]`; imprime só a contagem.
- Os downloads ficam fora do código (Parte B): `apt-get download`, PyPI JSON API com conferência de SHA-256 (ou `pip download --no-deps --no-binary :all:`), `npm pack --ignore-scripts`.

- [ ] **Step 1: Write the failing tests** (`tests/treino/test_benignos.py`)

```python
import io, lzma, os, sys, tarfile
from pathlib import Path
import pytest

pytest.importorskip("pyzipper")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from tools.treino.benignos import ingerir, membros_arquivo
from tools.treino.corpus import Corpus


def _ar(membros: list[tuple[str, bytes]]) -> bytes:
    buf = bytearray(b"!<arch>\n")
    for nome, data in membros:
        hdr = f"{nome:<16}0           0     0     100644  {len(data):<10}`\n".encode("ascii")
        buf += hdr + data
        if len(data) % 2 == 1:
            buf += b"\n"                                   # padding de 1 byte em membro impar
    return bytes(buf)


def _tar_xz(arquivos: dict[str, bytes], symlink_nome: str | None = None) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:xz") as tf:
        for nome, data in arquivos.items():
            ti = tarfile.TarInfo(nome)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        if symlink_nome:
            si = tarfile.TarInfo(symlink_nome)
            si.type = tarfile.SYMTYPE
            si.linkname = "/etc/passwd"
            tf.addfile(si)
    return raw.getvalue()


def test_deb_em_streaming_com_membro_impar_e_symlink(tmp_path):
    pasta = tmp_path / "debs"; pasta.mkdir()
    deb = _ar([
        ("debian-binary", b"2.0\n"),
        ("control.tar.xz", _tar_xz({}) + b"X"),             # membro anterior com tamanho impar
        ("data.tar.xz", _tar_xz({"usr/bin/ola": b"#!/bin/sh\necho ola\n",
                                 "usr/share/doc/x.txt": b"texto"}, symlink_nome="usr/bin/link")),
    ])
    (pasta / "ola_1.0_all.deb").write_bytes(deb)
    c = Corpus(tmp_path / "c")
    assert ingerir(c, pasta, source="ubuntu", first_seen="2026-11-20") == 1
    [e] = c.entries()
    assert e.label == 0 and e.categoria == "geral" and e.package == "ola"
    assert c.read(e) == b"#!/bin/sh\necho ola\n"
    assert not list((tmp_path / "c").rglob("ola"))


def test_npm_tgz_e_symlink_em_disco_ignorado(tmp_path):
    pasta = tmp_path / "npm"; pasta.mkdir()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tf:
        data = b"const a = require('x');\nmodule.exports = a;\n"
        ti = tarfile.TarInfo("package/index.js"); ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    (pasta / "pkg-1.0.0.tgz").write_bytes(raw.getvalue())
    os.symlink("/etc/passwd", pasta / "link.sh")
    c = Corpus(tmp_path / "c")
    assert ingerir(c, pasta, source="npm", categoria="geral", first_seen="2026-11-20") == 1
    assert c.entries()[0].package == "pkg"


def test_membro_grande_e_ignorado():
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tf:
        data = b"var a=1;\n" * 1_000_000
        ti = tarfile.TarInfo("package/g.js"); ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    assert dict(membros_arquivo("x.tgz", raw.getvalue())) == {}
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/treino/test_benignos.py -q`
Expected: FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: Implement `tools/treino/benignos.py`**

Usar streaming direto sobre o descritor de arquivo em `membros_caminho` (e `io.BytesIO` só para o helper em memória `membros_arquivo`). Sempre conferir `0 < size < MAX_BYTES` antes de alocar buffer para ler o conteúdo do membro.

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/treino/test_benignos.py tests/treino/test_politica_treino.py -q && .venv/bin/ruff check .`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add tools/treino/benignos.py tests/treino/test_benignos.py
git commit -m "Treino: ingestao de legitimos em streaming (.deb, wheels, sdists, npm) com nome de pacote"
```

---

### Task 5: Higiene e divisões (temporal, por família sem `"sem_familia"`, e benignos por pacote)

**Files:**
- Create: `tools/treino/higiene.py`
- Create: `tests/treino/test_higiene.py`

**Interfaces:**
- Consumes: `Entry` (Task 2).
- Produces:
  - `remover_conflitos(entries: list[Entry]) -> list[Entry]`: hash com os dois rótulos sai **dos dois** lados.
  - `remover_conhecidos(entries, conhecidos: set[str]) -> list[Entry]`: tira do lado malicioso os hashes que o CIRCL conhece como legítimos (o conjunto vem da Parte B; só hashes de amostras saem).
  - `@dataclass(frozen=True) class Divisao: treino: tuple[str, ...]; calibracao: tuple[str, ...]; teste: tuple[str, ...]; familias_teste: tuple[str, ...]; corte_temporal_teste: tuple[str, ...]` (hashes)
  - `dividir(entries, *, corte_teste: str, corte_calibracao: str, frac_familias_teste: float = 0.1, semente: int = 7) -> Divisao`:
    - Maliciosos: `first_seen >= corte_teste` → teste (também registrados em `corte_temporal_teste`); entre `corte_calibracao` e `corte_teste` → calibração; antes → treino. Além disso, sorteia `frac_familias_teste` das famílias nomeadas (**excluindo `""` e `"sem_familia"`**) pela semente determinística para irem inteiras **só** para o teste (corte por família).
    - Legítimos: divisão determinística pelo **pacote de origem** (`hashlib.sha256(e.package.encode()).hexdigest()[:8]` quando `e.package` não vazio, senão `e.sha256[:8]`, mod 100 → 70/15/15), estratificada por `categoria`, evitando que arquivos irmãos do mesmo pacote vazem entre treino e teste.
  - `HttpJson = Callable[[str, bytes], tuple[int, bytes]]` (url, corpo JSON → status, corpo)
  - `conhecidos_circl(hashes: list[str], *, http: HttpJson, lote: int = 1000) -> set[str]`: `POST https://hashlookup.circl.lu/bulk/sha256` com `{"hashes": [...]}` em lotes; devolve os hashes que o CIRCL reconhece. Só hashes de **amostras maliciosas** saem (nenhum dado do usuário).
  - `main(argv=None) -> int`: `python -m tools.treino.higiene --corpus DIR --saida ARQUIVO` grava os hashes conhecidos, um por linha.
- `first_seen` dos legítimos é a data de coleta: o corte temporal vale para os maliciosos.

- [ ] **Step 1: Write the failing tests** (`tests/treino/test_higiene.py`)

```python
import json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from tools.treino.corpus import Entry
from tools.treino.higiene import conhecidos_circl, dividir, remover_conflitos, remover_conhecidos


def E(sha, label, family="Fam", first_seen="2026-01-01", categoria="geral", package=""):
    return Entry(sha, label, "teste", family, first_seen, "r", categoria, package=package)


def test_conflito_sai_dos_dois_lados():
    e = [E("a" * 64, 1), E("a" * 64, 0), E("b" * 64, 1)]
    assert [x.sha256 for x in remover_conflitos(e)] == ["b" * 64]


def test_conhecidos_saem_so_do_lado_malicioso():
    e = [E("a" * 64, 1), E("c" * 64, 0)]
    assert {x.sha256 for x in remover_conhecidos(e, {"a" * 64, "c" * 64})} == {"c" * 64}


def test_circl_em_lotes_so_com_hashes():
    enviados = []
    def http(url, corpo):
        enviados.append(json.loads(corpo))
        return 200, json.dumps([{"SHA-256": h.upper()} for h in enviados[-1]["hashes"][:1]]).encode()
    hs = [f"{i:064x}" for i in range(2500)]
    assert conhecidos_circl(hs, http=http, lote=1000) == {hs[0], hs[1000], hs[2000]}
    assert [len(e["hashes"]) for e in enviados] == [1000, 1000, 500]


def test_divisao_temporal_sem_familia_fora_do_sorteio_e_benigno_por_pacote():
    mal = [E(f"{i:064x}", 1, family="sem_familia" if i % 4 == 0 else f"F{i % 20}",
             first_seen=f"2026-{1 + i % 12:02d}-01") for i in range(400)]
    leg = [E(f"{i + 10_000:064x}", 0, categoria="go_rust_estatico" if i % 5 == 0 else "geral",
             package=f"pacote_{i % 100}") for i in range(1000)]
    d1 = dividir(mal + leg, corte_teste="2026-10-01", corte_calibracao="2026-08-01")
    d2 = dividir(mal + leg, corte_teste="2026-10-01", corte_calibracao="2026-08-01")
    assert d1 == d2
    assert "sem_familia" not in d1.familias_teste
    assert any(e.family == "sem_familia" and e.sha256 in d1.treino for e in mal)
    todos = set(d1.treino) | set(d1.calibracao) | set(d1.teste)
    assert len(todos) == 1400 and not (set(d1.treino) & set(d1.teste))
    fam_treino = {e.family for e in mal if e.sha256 in d1.treino}
    assert d1.familias_teste and not (set(d1.familias_teste) & fam_treino)
    # arquivos do mesmo pacote ficam na mesma particao
    partes_por_pkg = {}
    for parte_nome, hs in (("treino", d1.treino), ("calibracao", d1.calibracao), ("teste", d1.teste)):
        hs_set = set(hs)
        for e in leg:
            if e.sha256 in hs_set:
                partes_por_pkg.setdefault(e.package, set()).add(parte_nome)
    assert all(len(v) == 1 for v in partes_por_pkg.values())
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/treino/test_higiene.py -q`
Expected: FAIL

- [ ] **Step 3: Implement `tools/treino/higiene.py`**

Para estratificação por categoria com `package`, manter o hash de partição `int(sha256(f"{e.categoria}:{e.package or e.sha256}".encode()).hexdigest()[:8], 16) % 100` (`< 70` treino, `70..84` calibração, `>= 85` teste).

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/treino/test_higiene.py -q && .venv/bin/ruff check .`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add tools/treino/higiene.py tests/treino/test_higiene.py
git commit -m "Treino: higiene, divisao temporal, familias sem sem_familia e benignos por pacote"
```

---

### Task 6: Extração incremental em SQLite (`float32`), marca correta das regras e `.npz`

**Files:**
- Create: `tools/treino/extrair.py`
- Create: `tests/treino/test_extrair.py`

**Interfaces:**
- Consumes: `Corpus`, `Entry` (Task 2), `Divisao` (Task 5), `mandacaru.ml.kind.detect_kind`, `mandacaru.ml.features.extract`/`FAMILY`/`FEATURE_VERSION`, `mandacaru.detectors.static.StaticScanner`.
- Produces:
  - `EXTENSOES = {"elf": ".elf", "sh": ".sh", "python": ".py", "perl": ".pl", "js": ".js", "php": ".php"}`
  - `feature_code_sha() -> str` e `yara_rules_sha() -> str`: SHA-256 dos arquivos de `features.py` e `rules/yara/*.yar` (para invalidar o cache se mudarem).
  - `extrair_cache(corpus: Corpus, cache_db: Path, *, budget_s: float = 2.0, shard: tuple[int, int] | None = None) -> dict[str, int]`:
    - abre `cache_db` em SQLite (`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`, `timeout=30.0`) com tabela `features(sha256 TEXT, version INT, code_sha TEXT, yara_sha TEXT, family TEXT, kind TEXT, regra_alta INT, regra_media INT, vec BLOB, PRIMARY KEY(sha256, version, code_sha, yara_sha))`;
    - instancia `StaticScanner()` **uma única vez** fora do loop;
    - se `shard = (idx, total)`, processa apenas entradas com `int(sha[:8], 16) % total == idx` (permite rodar os 4 núcleos físicos do i5-9300H em processos paralelos via `bwrap` sem duplicar código de `multiprocessing`);
    - pula hashes já presentes no cache para a versão atual;
    - para cada amostra: `corpus.read` → `detect_kind` (`None` → pulado e contado) → `extract` → `scanner.scan_bytes(Path(f"{sha}{EXTENSOES[kind]}"), data)` (extensão sintética para `script_heuristics` disparar igual ao runtime!) → grava `vec = struct.pack(f"<{len(x)}f", *x)` (`float32`), `regra_alta`, `regra_media`; estouro de orçamento → pulada e contada.
  - `@dataclass class Tabela: X: np.ndarray; y: np.ndarray; kind: tuple[str, ...]; sha: tuple[str, ...]; parte: tuple[str, ...]; categoria: tuple[str, ...]; regra_alta: np.ndarray; regra_media: np.ndarray; temporal_teste: np.ndarray` (`X` com `dtype=np.float32`).
  - `montar_tabelas(corpus: Corpus, divisao: Divisao, cache_db: Path) -> dict[str, Tabela]` (chaves `"elf"` e `"script"`).
  - `extrair(corpus: Corpus, divisao: Divisao, *, cache_db: Path | None = None, budget_s: float = 2.0) -> dict[str, Tabela]` (atalho conveniente: atualiza cache — temporário se `cache_db is None` — e retorna `montar_tabelas`).
  - `salvar(tabelas, pasta: Path) -> None` / `carregar(pasta: Path) -> dict[str, Tabela]` usando `np.savez_compressed` + JSON pequeno para tuplas de metadados e `np.load(..., allow_pickle=False)` (evita JSON de ~100 MB e mantém zero pickle).
  - `main(argv=None) -> int`: permite rodar a etapa de cache isolada (`python -m tools.treino.extrair --corpus DIR --cache ARQ [--shard 0/4]`).

- [ ] **Step 1: Write the failing tests** (`tests/treino/test_extrair.py`)

Corpus sintético: 3 scripts inofensivos (`curl | sh` → `Shell_Pipe_To_Interpreter` `MEDIUM`; script Python com payload base64 + `b64decode` + `exec` → `heur.obfuscated_script` e/ou `Py_Exec_Decoded_Payload`; script simples) e 1 ELF montado com `tests/ml_elf.make_elf`.

```python
import sys
from pathlib import Path
import numpy as np
import pytest

pytest.importorskip("pyzipper")
pytest.importorskip("numpy")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from mandacaru.ml.features import ELF_FEATURE_NAMES, SCRIPT_FEATURE_NAMES, extract
from tools.treino.extrair import carregar, extrair, extrair_cache, salvar


def test_extrai_por_familia_com_extensao_sintetica_e_cache(tmp_path):
    c, d, dados, sha_curl, sha_heur = _corpus_e_divisao(tmp_path)
    db = tmp_path / "cache.sqlite"
    r1 = extrair_cache(c, db)
    assert r1["extraidos"] == 4 and r1["cacheados"] == 0
    r2 = extrair_cache(c, db)
    assert r2["extraidos"] == 0 and r2["cacheados"] == 4         # incremental
    t = extrair(c, d, cache_db=db)
    assert set(t) == {"elf", "script"}
    assert t["script"].X.dtype == np.float32
    assert t["script"].X.shape[1] == len(SCRIPT_FEATURE_NAMES)
    assert t["elf"].X.shape[1] == len(ELF_FEATURE_NAMES)
    i = t["script"].sha.index(sha_curl)
    assert bool(t["script"].regra_media[i]) is True and bool(t["script"].regra_alta[i]) is False
    j = t["script"].sha.index(sha_heur)
    assert bool(t["script"].regra_media[j]) is True             # heur.obfuscated_script disparou pela extensao .py
    assert np.allclose(t["script"].X[i], np.asarray(extract("sh", dados[sha_curl]), dtype=np.float32))


def test_salvar_e_carregar_npz(tmp_path):
    c, d, *_ = _corpus_e_divisao(tmp_path)
    t = extrair(c, d)
    salvar(t, tmp_path / "tab")
    assert (tmp_path / "tab" / "script.npz").is_file()
    assert carregar(tmp_path / "tab")["script"].sha == t["script"].sha
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/treino/test_extrair.py -q`
Expected: FAIL

- [ ] **Step 3: Implement `tools/treino/extrair.py`**

*(Instalar `[treino]` para testes locais, se ainda não instalado: `.venv/bin/pip install -e ".[dev,treino]"` ou via extras separados.)*

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/treino/test_extrair.py -q && .venv/bin/ruff check .`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add tools/treino/extrair.py tests/treino/test_extrair.py
git commit -m "Treino: cache incremental em SQLite WAL, extensao sintetica para heuristicas e npz sem pickle"
```

---

### Task 7: Treino (`float32`, `sample_weight`), calibração em split separado e limiares

**Files:**
- Create: `tools/treino/treinar.py`
- Create: `tests/treino/test_treinar.py`

**Interfaces:**
- Consumes: `Tabela` (Task 6).
- Produces:
  - `FP_ALTO = 0.0005`, `FP_ALTO_TMP = 0.00025`, `FP_MEDIO = 0.01`, `MIN_REFORCO = 300`, `PESO_DIFICIL = 4.0`
  - `CATEGORIAS_TMP = ("build_tmp", "pip_tmp", "instalador_curl_sh", "instalador_run")`
  - `@dataclass class Treinado: clf; calib_x: list[float]; calib_y: list[float]; limiares: dict[str, dict[str, float]]` (tipo → `alto`, `alto_tmp`, `reforco`, `medio`)
  - `treinar(t: Tabela, *, semente: int = 7, max_iter: int = 300) -> Treinado`:
    1. Treina `HistGradientBoostingClassifier(max_iter=max_iter, max_depth=8, max_leaf_nodes=31, min_samples_leaf=30, l2_regularization=1.0, learning_rate=0.1, early_stopping=True, validation_fraction=0.1, n_iter_no_change=20, random_state=semente)` sobre `X` (`np.float32`), aplicando `sample_weight = PESO_DIFICIL` aos legítimos de categorias difíceis (`y == 0` e `categoria != "geral"`).
    2. Divide determinísticamente a parte `calibracao` (50/50 estratificada por `y` quando há dados suficientes; com fallback seguro para conjuntos pequenos sintéticos) em `cal_fit` e `cal_limiar`:
       - em `cal_fit`: ajusta `IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1)` sobre `sigmoide(decision_function)` (protegida: `raw < -700 -> 0.0`) — ou Platt scaling amostrada em 200 pontos quando isotônica colapsar — e garante **sempre** `len(calib_x) >= 2`, `calib_x` estritamente crescente em `[0, 1]` e `calib_y` não decrescente em `[0, 1]` (exigido por `parse_model` em `model.py`);
       - em `cal_limiar`: escolhe os limiares por tipo sobre a probabilidade calibrada dos legítimos do tipo:
         - `alto`: menor limiar com FP ≤ `FP_ALTO`;
         - `alto_tmp`: o mesmo sobre `CATEGORIAS_TMP` com meta `FP_ALTO_TMP` (nunca abaixo de `alto`);
         - `medio`: menor limiar com FP ≤ `FP_MEDIO` (nunca acima de `alto`);
         - `reforco`: só com legítimos que têm `regra_media`; com menos de `MIN_REFORCO`, `reforco = alto`.
- Garantia ao final: `0.0 <= medio <= reforco <= alto <= alto_tmp <= 1.0`.

- [ ] **Step 1: Write the failing tests** (`tests/treino/test_treinar.py`)

```python
import sys
from pathlib import Path
import pytest

pytest.importorskip("sklearn")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import probs_calibracao_legitimos, sintetico_script
from tools.treino.treinar import PESO_DIFICIL, pesos_amostra, treinar


def test_limiares_respeitam_o_orcamento_e_a_ordem():
    t = sintetico_script(n=4000, semente=1)
    tr = treinar(t, max_iter=50)
    lim = tr.limiares["sh"]
    assert 0.0 <= lim["medio"] <= lim["reforco"] <= lim["alto"] <= lim["alto_tmp"] <= 1.0
    assert len(tr.calib_x) >= 2 and all(a < b for a, b in zip(tr.calib_x, tr.calib_x[1:]))
    probs = probs_calibracao_legitimos(tr, t)
    assert sum(p >= lim["alto"] for p in probs) / len(probs) <= 0.0005 + 1e-12


def test_reforco_sem_dados_vira_alto():
    t = sintetico_script(n=3000, semente=2, regra_media=False)
    tr = treinar(t, max_iter=30)
    assert tr.limiares["sh"]["reforco"] == tr.limiares["sh"]["alto"]


def test_calibracao_colapsada_mantem_dois_pontos_e_peso_dificil():
    t = sintetico_script(n=1000, semente=4, separavel=True, categoria_dificil="go_rust_estatico")
    tr = treinar(t, max_iter=10)
    assert len(tr.calib_x) >= 2 and tr.calib_x[0] < tr.calib_x[-1]
    w = pesos_amostra(t, t.parte == "treino")
    assert float(w.max()) == pytest.approx(PESO_DIFICIL)


def test_deterministico():
    t = sintetico_script(n=2000, semente=3)
    assert treinar(t, max_iter=20).limiares == treinar(t, max_iter=20).limiares
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/treino/test_treinar.py -q`
Expected: FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: Implement `tools/treino/treinar.py` and helpers in `tests/treino/helpers.py`**

*(O `scikit-learn` e `numpy` já estão no extra `treino` de `pyproject.toml`, fora das dependências de runtime.)*

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/treino/test_treinar.py -q && .venv/bin/ruff check .`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add tools/treino/treinar.py tests/treino/test_treinar.py tests/treino/helpers.py
git commit -m "Treino: gradient boosting float32 com pesos nos dificeis, calibracao isolada e limiares"
```

---

### Task 8: Avaliação vetorizada, regressão contra `Model` JSON e relatório completo

**Files:**
- Create: `tools/treino/avaliar.py`
- Create: `tests/treino/test_avaliar.py`

**Interfaces:**
- Consumes: `Treinado` (Task 7), `Tabela` (Task 6), `mandacaru.ml.model.Model`.
- Produces:
  - `MIN_LEGITIMOS_TESTE = 6000`, `MIN_MALICIOSOS_TESTE = 500`, `META_FP = 0.0005`, `META_FP_CATEGORIA = 0.005`, `META_DETECCAO = 0.80`
  - `@dataclass class Portao: kind: str; aprovado: bool; motivos: list[str]; fp: float; fp_categorias: dict[str, float]; deteccao_regras_perdem: float; deteccao_geral: float; deteccao_temporal: float; deteccao_familias_ineditas: float; duplicatas_treino_teste: int; n_legitimos: int; n_maliciosos: int`
  - `avaliar(tr: Treinado, t: Tabela, *, anterior: Model | None = None, legitimos_anteriores: Tabela | None = None) -> dict[str, Portao]`:
    - calcula probabilidades na parte `teste` de forma **vetorizada** (`clf.decision_function` + interpolação em `(calib_x, calib_y)`) para terminar em milissegundos na CPU;
    - "regras perdem" = maliciosos com `regra_alta == False`; separa detecção em `temporal_teste` e nas famílias inéditas (`not temporal_teste`);
    - conta quantos vetores exatos de `X_teste` aparecem em `X_treino` (`duplicatas_treino_teste`);
    - reprova por qualquer meta não cumprida, por amostra mínima não atingida, ou (com `anterior: Model` carregado de JSON) por FP maior que o de `anterior.probability(x)` nos `legitimos_anteriores`; cada motivo em português sem acento em `motivos`.
  - `relatorio(portoes: dict[str, Portao], *, model_id: str, contagens: dict) -> str` (Markdown, só números e hashes, relatando também corte temporal, famílias inéditas e duplicatas).

- [ ] **Step 1: Write the failing tests** (`tests/treino/test_avaliar.py`)

```python
import json, sys
from pathlib import Path
import pytest

pytest.importorskip("sklearn")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import sintetico_script
from mandacaru.ml.features import SCRIPT_FEATURE_NAMES
from mandacaru.ml.model import parse_model
from ml_model import model_dict, stump
from tools.treino import avaliar as av
from tools.treino.avaliar import avaliar, relatorio
from tools.treino.treinar import treinar


def test_tipo_com_poucos_dados_reprova_com_motivo():
    t = sintetico_script(n=2000, semente=4)
    p = avaliar(treinar(t, max_iter=30), t)["sh"]
    assert p.aprovado is False and any("6000" in m for m in p.motivos)


def test_aprova_quando_todas_as_metas_batem(monkeypatch):
    monkeypatch.setattr(av, "MIN_LEGITIMOS_TESTE", 100)
    monkeypatch.setattr(av, "MIN_MALICIOSOS_TESTE", 50)
    t = sintetico_script(n=6000, semente=5, separavel=True)
    p = av.avaliar(treinar(t, max_iter=60), t)["sh"]
    assert p.aprovado, p.motivos


def test_regressao_contra_modelo_json_anterior(monkeypatch):
    monkeypatch.setattr(av, "MIN_LEGITIMOS_TESTE", 100)
    monkeypatch.setattr(av, "MIN_MALICIOSOS_TESTE", 50)
    t = sintetico_script(n=6000, semente=7, separavel=False)
    tr = treinar(t, max_iter=30)
    tr.limiares["sh"]["alto"] = 0.0                          # forca FP=100% no novo
    d = model_dict(family="script", kinds={"sh": {"gate_passed": True, "alto": 0.99, "alto_tmp": 0.99,
                                                  "reforco": 0.99, "medio": 0.9}},
                   trees=[stump(SCRIPT_FEATURE_NAMES.index("baixa_e_executa"), 0.5, -5.0, -5.0)])
    anterior = parse_model(json.dumps(d).encode())
    p = av.avaliar(tr, t, anterior=anterior, legitimos_anteriores=t)["sh"]
    assert p.aprovado is False and any("anterior" in m for m in p.motivos)


def test_relatorio_so_com_numeros():
    t = sintetico_script(n=2000, semente=6)
    md = relatorio(avaliar(treinar(t, max_iter=20), t), model_id="script-teste", contagens={"script": 2000})
    assert "script-teste" in md and "| sh |" in md and "exemplo.invalid" not in md
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/treino/test_avaliar.py -q`
Expected: FAIL

- [ ] **Step 3: Implement `tools/treino/avaliar.py`**

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/treino/test_avaliar.py -q && .venv/bin/ruff check .`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add tools/treino/avaliar.py tests/treino/test_avaliar.py
git commit -m "Treino: avaliacao vetorizada, regressao contra Model JSON e metricas temporal vs familia"
```

---

### Task 9: Exportação para JSON compacto estrito e `tests/fixtures/ml_golden.json`

**Files:**
- Create: `tools/treino/exportar.py`
- Create: `tests/test_ml_golden.py` (no **pacote**: confere o modelo instalado contra `tests/fixtures/ml_golden.json`; pula se não houver)
- Create: `tests/treino/test_exportar.py`

**Interfaces:**
- Consumes: `Treinado` (Task 7), `Portao` (Task 8), `mandacaru.ml.model.parse_model`, `mandacaru.ml.features.FEATURE_VERSION`/nomes.
- Produces:
  - `exportar(tr: Treinado, portoes: dict[str, Portao], *, family: str, model_id: str, feature_code_sha: str, manifesto_sha256: str, metricas: dict) -> dict` no formato exato de `mandacaru.ml.model`:
    - `base_score = float(clf._baseline_prediction.item())` (no scikit-learn, `_baseline_prediction` é array 2D `(1, 1)`);
    - árvores vêm de `clf._predictors[i][0].nodes`: folha (`is_leaf`) → `feature = -1`; nó interno → `feature = feature_idx`, `threshold = num_threshold`, `left`/`right`; renumera em pré-ordem se algum filho não tiver índice maior que o pai;
    - **consistência da explicação (Saabas):** recalcular `value` de cada nó interno de baixo para cima como média ponderada por `count` dos nós filhos (`(count[l]*val[l] + count[r]*val[r]) / (count[l] + count[r])`), garantindo que `base_score + sum(root_values) + sum(contributions) == raw_score`;
    - `kinds[k] = {"gate_passed": portoes[k].aprovado, **tr.limiares[k]}`;
    - garantir que todos os valores em `metrics` sejam números (`int`/`float`) ou textos curtos (`<= 64` chars, exigido por `tests/test_politica.py`).
  - `golden(tr: Treinado, X, n: int = 200, semente: int = 7) -> dict`: `{"family", "model_id", "vetores": [...], "raw": [...], "prob": [...]}` com `raw` calculado via `clf.decision_function(np.asarray(amostra, dtype=np.float64))` (`float64` para bater a tolerância de `1e-9` com o Python puro).
  - `conferir(json_modelo: dict, json_golden: dict) -> None`: `parse_model` + compara `raw_score`/`probability` com tolerância de `1e-9` e confere também `base_score + sum(root_values) + sum(contributions) == raw_score`; levanta `AssertionError` com o índice divergente.
  - `serializar_json(obj: dict) -> bytes`: `json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode()` (JSON compacto, respeitando o teto de 3 MB).
  - `main(argv=None) -> int`: escreve `elf.json`, `script.json`, `golden.json` (as duas famílias), relatório e manifesto numa pasta de saída, chamando `conferir` antes de gravar.
- `tests/test_ml_golden.py` (roda no CI quando o modelo estiver instalado): lê `ROOT / "tests" / "fixtures" / "ml_golden.json"` (fora de `src/mandacaru/ml/models/`, para não quebrar `tests/test_politica.py` nem inflar o `.deb`/wheel) e confere cada família instalada em `src/mandacaru/ml/models/` com `1e-9`.

- [ ] **Step 1: Write the failing tests** (`tests/treino/test_exportar.py` e `tests/test_ml_golden.py`)

```python
import json, sys
from pathlib import Path
import pytest

pytest.importorskip("sklearn")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import sintetico_script
from mandacaru.ml.model import parse_model
from tools.treino.avaliar import avaliar
from tools.treino.exportar import conferir, exportar, golden, serializar_json
from tools.treino.treinar import treinar


def test_exportado_carrega_reproduz_sklearn_e_soma_contribuicoes():
    t = sintetico_script(n=3000, semente=8)
    tr = treinar(t, max_iter=40)
    port = avaliar(tr, t)
    m = exportar(tr, port, family="script", model_id="script-teste", feature_code_sha="0" * 40,
                 manifesto_sha256="0" * 64, metricas={"fp": 0.0})
    g = golden(tr, t.X)
    conferir(m, g)
    raw_bytes = serializar_json(m)
    modelo = parse_model(raw_bytes)
    assert modelo.kinds["sh"].gate_passed is False
    assert len(raw_bytes) <= 3 * 1024 * 1024
    x0 = g["vetores"][0]
    soma_raizes = sum(ar.value[0] for ar in modelo.trees)
    assert modelo.base_score + soma_raizes + sum(modelo.contributions(x0)) == pytest.approx(modelo.raw_score(x0))


def test_conferir_pega_divergencia():
    t = sintetico_script(n=2000, semente=9)
    tr = treinar(t, max_iter=20)
    m = exportar(tr, avaliar(tr, t), family="script", model_id="x", feature_code_sha="0" * 40,
                 manifesto_sha256="0" * 64, metricas={})
    g = golden(tr, t.X)
    g["raw"][0] += 1e-3
    with pytest.raises(AssertionError):
        conferir(m, g)
```

E `tests/test_ml_golden.py`:

```python
import json
from pathlib import Path
import pytest
from mandacaru.ml import MODEL_SHA256
from mandacaru.ml.model import load_model

ROOT = Path(__file__).resolve().parent.parent


def test_golden_do_modelo_instalado():
    golden_path = ROOT / "tests" / "fixtures" / "ml_golden.json"
    if not golden_path.is_file():
        pytest.skip("nenhum modelo instalado")
    pasta = ROOT / "src" / "mandacaru" / "ml" / "models"
    g = json.loads(golden_path.read_text())
    for fam, dados in g.items():
        m = load_model(pasta / f"{fam}.json", expected_sha256=MODEL_SHA256[fam])
        for x, raw, prob in zip(dados["vetores"], dados["raw"], dados["prob"], strict=True):
            assert m.raw_score(x) == pytest.approx(raw, abs=1e-9)
            assert m.probability(x) == pytest.approx(prob, abs=1e-9)
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/treino/test_exportar.py tests/test_ml_golden.py -q`
Expected: FAIL em `test_exportar.py` (`ModuleNotFoundError`); `test_ml_golden.py` pula

- [ ] **Step 3: Implement `tools/treino/exportar.py` and `tests/test_ml_golden.py`**

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/treino/test_exportar.py tests/test_ml_golden.py tests/test_politica.py -q && .venv/bin/ruff check .`
Expected: passam (golden pula)

- [ ] **Step 5: Commit**

```bash
git add tools/treino/exportar.py tests/treino/test_exportar.py tests/test_ml_golden.py
git commit -m "Treino: exportacao compacta com nos internos ponderados, golden.json e conferencia 1e-9"
```

---

### Task 10: Comando único do pipeline, instalação validada e `--stdin --jsonl` no CLI

**Files:**
- Create: `tools/treino/pipeline.py`
- Create: `tools/instalar_modelo.py`
- Modify: `src/mandacaru/ml/cli.py` e `tests/test_ml_cli.py` (adicionar `--stdin` e `--jsonl` em `mandacaru ml avaliar`)
- Create: `tests/treino/test_pipeline.py`, `tests/treino/test_instalar_modelo.py`

**Interfaces:**
- Consumes: Tasks 2 a 9.
- Produces (`tools/treino/pipeline.py`):
  - `python -m tools.treino.pipeline --corpus ~/corpus --cache ~/cache/features.sqlite --saida ~/saida/<model_id> --corte-teste AAAA-MM-DD --corte-calibracao AAAA-MM-DD [--conhecidos arquivo] [--anterior pasta] [--model-id ID]`:
    - higiene → divisão → `extrair_cache` incremental → `montar_tabelas` → treino → avaliação (carregando `anterior/elf.json` e `anterior/script.json` via `load_model(..., expected_sha256=None)` quando `--anterior` for passado) → exportação dos 5 artefatos (`elf.json`, `script.json`, `golden.json`, `relatorio-<model_id>.md`, `manifesto-<model_id>.txt`) na pasta de saída;
    - `pipeline.main(argv) -> int` (0 = rodou; portão reprovado não é erro; imprime só contagens e o resumo do portão).
- Produces (`tools/instalar_modelo.py`):
  - roda na `Ubuntu-Dev`: lê uma pasta com exatamente os 5 artefatos (`elf.json`, `script.json`, `golden.json`, um `relatorio-*.md` e um `manifesto-*.txt`).
  - **recusa** qualquer arquivo estranho, qualquer symlink (`p.is_symlink()`, abertura com `os.O_NOFOLLOW`), JSON > `MAX_MODEL_BYTES` ou markdown/texto > 2 MB.
  - valida `elf.json` e `script.json` com `parse_model` + `<= 3 MB` + strings `<= 64` chars, valida `golden.json` com `conferir`, e valida `relatorio-*.md` e `manifesto-*.txt` como UTF-8 estrito sem caracteres de controle/escapes ANSI (`\x1b`, `\x00`..`\x08`, `\x0b`..`\x1f`, `\x7f`) para impedir terminal escape injection.
  - instala `elf.json`/`script.json` em `src/mandacaru/ml/models/`, `golden.json` em `tests/fixtures/ml_golden.json`, relatório e manifesto em `docs/ml/`, e reescreve o dicionário `MODEL_SHA256` em `src/mandacaru/ml/__init__.py`. Retorna `1` sem copiar nada se qualquer validação falhar.
- Modify (`src/mandacaru/ml/cli.py`):
  - `mandacaru ml avaliar` aceita `--stdin` (lê caminhos separados por `\0` ou `\n` de `sys.stdin.buffer`, tornando `arquivos` opcional quando `--stdin` for usado) e `--jsonl` (emite um objeto JSON por linha, sem recarregar modelos ou os MD5 do `dpkg` em múltiplos processos).

- [ ] **Step 1: Write the failing tests** (`tests/treino/test_pipeline.py`, `tests/treino/test_instalar_modelo.py`, e novo caso em `tests/test_ml_cli.py`)

```python
# tests/treino/test_pipeline.py + test_instalar_modelo.py
def test_pipeline_ponta_a_ponta_sintetico(tmp_path):
    corpus = _corpus_sintetico(tmp_path, n_scripts=300, n_elf=60)
    out = tmp_path / "out" / "2026.11"
    assert pipeline.main(["--corpus", str(corpus), "--cache", str(tmp_path / "cache.sqlite"),
                          "--saida", str(out), "--corte-teste", "2026-10-01",
                          "--corte-calibracao", "2026-08-01", "--model-id", "2026.11"]) == 0
    assert {p.name for p in out.iterdir()} == {
        "elf.json", "script.json", "golden.json", "relatorio-2026.11.md", "manifesto-2026.11.txt",
    }


def test_instalar_modelo_valida_e_fixa_o_hash(tmp_path):
    origem = _artefatos_validos(tmp_path)
    repo = _repo_falso(tmp_path)
    assert instalar_modelo.main([str(origem), "--repo", str(repo)]) == 0
    assert (repo / "tests/fixtures/ml_golden.json").is_file()
    assert list((repo / "docs/ml").glob("relatorio-*.md"))
    texto = (repo / "src/mandacaru/ml/__init__.py").read_text()
    for fam in ("elf", "script"):
        h = hashlib.sha256((repo / f"src/mandacaru/ml/models/{fam}.json").read_bytes()).hexdigest()
        assert f'"{fam}": "{h}"' in texto


def test_instalar_modelo_recusa_estranho_symlink_e_ansi(tmp_path):
    origem = _artefatos_validos(tmp_path)
    (origem / "amostra.bin").write_bytes(b"\x7fELF")
    assert instalar_modelo.main([str(origem), "--repo", str(_repo_falso(tmp_path))]) == 1
    (origem / "amostra.bin").unlink()
    (origem / "relatorio-teste.md").write_text("\x1b[31minjection\x1b[0m\n")
    assert instalar_modelo.main([str(origem), "--repo", str(_repo_falso(tmp_path))]) == 1
    (origem / "relatorio-teste.md").write_text("# ok\n")
    (origem / "elf.json").unlink()
    os.symlink("/etc/passwd", origem / "elf.json")
    assert instalar_modelo.main([str(origem), "--repo", str(_repo_falso(tmp_path))]) == 1
```

*(E em `tests/test_ml_cli.py`, testar `mandacaru ml avaliar --stdin --jsonl` com caminhos separados por `\0` via `monkeypatch.setattr(sys, "stdin", ...)`.)*

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/treino/test_pipeline.py tests/treino/test_instalar_modelo.py tests/test_ml_cli.py -q`
Expected: FAIL

- [ ] **Step 3: Implement `pipeline.py`, `instalar_modelo.py` and update `src/mandacaru/ml/cli.py`**

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check .`
Expected: suíte inteira passa

- [ ] **Step 5: Commit**

```bash
git add tools/treino/pipeline.py tools/instalar_modelo.py src/mandacaru/ml/cli.py tests/test_ml_cli.py tests/treino/test_pipeline.py tests/treino/test_instalar_modelo.py
git commit -m "Treino: pipeline com cache, instalacao validada dos 5 artefatos e avaliar --stdin --jsonl"
```

---

# Parte B — Operação (ambiente isolado e máquina real)

As tarefas abaixo **não** são TDD: são procedimentos com verificação. Cada uma tem um **ponto de parada** quando depende do usuário. Nenhuma roda na `Ubuntu-Dev` com amostras reais.

### Task 11: Endurecer a `UbuntuPentest` e preparar `bubblewrap` (F0) — **PARADA: precisa do usuário (root nessa distro)**

- [ ] **Step 1:** O usuário, no PowerShell do Windows, abre um shell root na distro:
  `wsl.exe -d UbuntuPentest -u root`
- [ ] **Step 2:** Dentro dela, como root (instala `bubblewrap`, cria usuário `treino` sem sudo e pastas `0700`):

```bash
apt-get update && apt-get install -y bubblewrap python3-venv python3-yara
cat > /etc/wsl.conf <<'EOF'
[automount]
enabled = false
mountFsTab = false

[interop]
enabled = false
appendWindowsPath = false
EOF
adduser --disabled-password --gecos "" treino
chmod 0700 /home/treino
install -d -m 0700 -o treino -g treino /home/treino/corpus /home/treino/cache /home/treino/saida
```

*(Nota para Python 3.14: se o Python da `UbuntuPentest` for 3.14 e o venv não enxergar o `python3-yara` do sistema, extrair os headers com `apt-get download libpython3.14-dev` e compilar `yara-python` no venv via `CFLAGS`, como documentado na `Ubuntu-Dev`, ou criar o venv com `--system-site-packages` exclusivamente para usar `python3-yara` empacotado.)*

- [ ] **Step 3:** No PowerShell: `wsl --terminate UbuntuPentest`
- [ ] **Step 4: Verificar** (`wsl.exe -d UbuntuPentest -u treino`), configurar `umask 077` no `~/.bashrc` do usuário `treino` e guardar a evidência em `~/saida/verificacao-ambiente.txt`:

```bash
grep -qxF 'umask 077' ~/.bashrc || echo 'umask 077' >> ~/.bashrc
umask 077
{
  ls -A /mnt/c 2>&1 || true
  mount | grep -E '9p|drvfs|wsl' || echo "sem mounts host"
  ls -la /proc/sys/fs/binfmt_misc 2>&1 || true
  command -v cmd.exe || echo "cmd.exe indisponivel"
  command -v bwrap
  sudo -n true 2>&1 | head -1 || true
  stat -c '%a %U %n' ~ ~/corpus ~/cache ~/saida
} | tee ~/saida/verificacao-ambiente.txt
```

Expected: `/mnt/c` vazio ou inexistente; `"sem mounts host"`; `WSLInterop` ausente; `cmd.exe indisponivel`; `/usr/bin/bwrap` presente; `sudo` pede senha ou não existe; `700 treino` nas 4 pastas.

- [ ] **Step 5:** Clonar o repositório **público** só para leitura (sem credenciais), na branch deste plano, e criar o venv de treino:

```bash
git clone --branch feat/classificador-ia-treino https://github.com/VandyckLN/mandacaru ~/mandacaru
python3 -m venv --system-site-packages ~/venv
~/venv/bin/pip install --require-hashes -r ~/mandacaru/tools/treino/requirements.txt
~/venv/bin/pip install --no-deps -e ~/mandacaru
```

*(O `requirements.txt` com hashes já foi gerado e commitado na Task 1; o `--no-deps -e ~/mandacaru` disponibiliza `mandacaru.ml` e `StaticScanner` sem baixar extras.)*

### Task 12: Coleta de dados (F2) — **PARADA: chave do MalwareBazaar e alguns dias**

- [ ] **Step 1:** O usuário cria a conta gratuita no abuse.ch e exporta a chave **só na sessão**:
  `read -rs MB_AUTH_KEY && export MB_AUTH_KEY`
- [ ] **Step 2:** Baixar o catálogo histórico `full.csv.zip` do MalwareBazaar e coletar até os alvos do spec (10–30 mil ELF; alguns milhares de scripts), garantindo amostra temporal ampla (ex.: últimos 12 meses) e respeito ao teto de disco:

```bash
cd ~/mandacaru
curl -fL -o ~/full.csv.zip https://bazaar.abuse.ch/export/csv/full/
~/venv/bin/python -m tools.treino.baixar --corpus ~/corpus --catalogo ~/full.csv.zip --desde <AAAA-MM-DD> --cota 2000 --max-corpus-gb 20
```

Expected: uma linha com `baixados=N pulados=M`; se `parou=daily_limit_reached`, repetir nos dias seguintes (sem baixar de novo o que já entrou no corpus).

- [ ] **Step 3:** Legítimos (ainda na `UbuntuPentest`, como `treino`, com rede):
  - pacotes Ubuntu/Debian (~2.000 pacotes populares de `main`/`universe`, incluindo Go/Rust estáticos, excluindo pacotes grandes sem executáveis como `*-doc`, `*-data`, `fonts-*` e `linux-firmware`): `apt-get download $(cat ~/mandacaru/tools/treino/pacotes.txt)` em `~/benignos/deb` (lista commitada depois);
  - PyPI: baixar os tarballs `sdist` dos top ~1.000 pacotes populares diretamente pela JSON API do PyPI com conferência de SHA-256 (eliminando risco de `setup.py` executar código durante coleta) para `~/benignos/pypi`;
  - npm: `npm pack --ignore-scripts <top 1000 versoes fixadas>` em `~/benignos/npm`;
  - difíceis: `upx` sobre cópias de binários legítimos (`~/benignos/upx_legitimo`), AppImages, instaladores `.run`, `rustup-init.sh` e `install.sh` do nvm (`~/benignos/instalador_curl_sh`), artefatos de build e temporários do pip (`~/benignos/build_tmp`, `~/benignos/pip_tmp`).
  - Ingestão em streaming, uma vez por pasta, com a `categoria` da pasta:
    `~/venv/bin/python -m tools.treino.benignos --corpus ~/corpus --pasta ~/benignos/deb --source ubuntu`
- [ ] **Step 4:** Hashes legítimos conhecidos (só hashes de amostras maliciosas saem):
  `~/venv/bin/python -m tools.treino.higiene --corpus ~/corpus --saida ~/saida/conhecidos.txt`
- [ ] **Step 5: Verificar** contagens: `jq -r '.label' ~/corpus/manifesto.jsonl | sort | uniq -c`

### Task 13: Extração incremental e treino sem rede via `bubblewrap` (F3)

Esta etapa roda **100% offline e sem GPU** (`bwrap --unshare-net`, `~/corpus` montado somente leitura, sem `/dev/dxg`).

- [ ] **Step 1:** Escolher os cortes: `--corte-teste` = data que deixe ~15 % dos maliciosos mais recentes no teste; `--corte-calibracao` = ~15 % antes disso; definir `--model-id` (ex.: `2026.12.0`).
- [ ] **Step 2:** Extrair características e marcas do `StaticScanner` (com `libyara`) para o cache incremental em `~/cache/features.sqlite`, usando os 4 núcleos físicos em paralelo com baixa prioridade (`nice -n 15`):

```bash
for s in 0/4 1/4 2/4 3/4; do
  nice -n 15 bwrap --unshare-net --ro-bind / / --ro-bind ~/corpus ~/corpus \
    --bind ~/cache ~/cache --tmpfs /tmp --dev /dev --proc /proc \
    --cap-drop ALL --new-session --die-with-parent \
    bash -c 'ulimit -v 4194304 && exec ~/venv/bin/python -m tools.treino.extrair --corpus ~/corpus --cache ~/cache/features.sqlite --shard "$1"' _ "$s" &
done
wait
```

- [ ] **Step 3:** Rodar treino, calibração, avaliação, portão e exportação dentro de `bwrap --unshare-net` (`OMP_NUM_THREADS=4`, 0% GPU):

```bash
OMP_NUM_THREADS=4 nice -n 15 bwrap --unshare-net --ro-bind / / --ro-bind ~/corpus ~/corpus \
  --bind ~/cache ~/cache --bind ~/saida ~/saida --tmpfs /tmp --dev /dev --proc /proc \
  --cap-drop ALL --new-session --die-with-parent \
  bash -c 'ulimit -v 6291456 && exec ~/venv/bin/python -m tools.treino.pipeline --corpus ~/corpus --cache ~/cache/features.sqlite --saida ~/saida/<model_id> --model-id <model_id> --corte-teste <data> --corte-calibracao <data> --conhecidos ~/saida/conhecidos.txt'
```

Expected: resumo do portão por tipo; pasta `~/saida/<model_id>/` com exatamente os 5 artefatos: `elf.json`, `script.json`, `golden.json`, `relatorio-<model_id>.md` e `manifesto-<model_id>.txt`.

- [ ] **Step 4:** Ler o relatório com o usuário (incluindo FP por categoria difícil, corte temporal vs. famílias inéditas e `duplicatas_treino_teste`). Tipo reprovado vai para o pacote em `alert` (é o próprio `gate_passed`). Se ELF e scripts reprovarem, investigar antes de seguir (mais dados, características).

### Task 14: Trazer o modelo para a `Ubuntu-Dev` e conferir nos arquivos do usuário

- [ ] **Step 1:** Cópia unidirecional (da `Ubuntu-Dev`, que lê a pasta exata `~/saida/<model_id>` na outra distro, sem concatenar arquivos antigos):

```bash
MID="<model_id>"
mkdir -p ~/modelo-novo
for f in elf.json script.json golden.json "relatorio-${MID}.md" "manifesto-${MID}.txt"; do
  wsl.exe -d UbuntuPentest -u treino cat "~/saida/${MID}/${f}" > ~/modelo-novo/"$f"
done
```

- [ ] **Step 2:** `.venv/bin/python tools/instalar_modelo.py ~/modelo-novo` → Expected: saída 0, modelos em `src/mandacaru/ml/models/`, `golden.json` em `tests/fixtures/ml_golden.json`, relatório e manifesto em `docs/ml/`, e `MODEL_SHA256` atualizado.
- [ ] **Step 3:** `.venv/bin/python -m pytest -q && .venv/bin/ruff check .` → Expected: suíte inteira passa, inclusive `tests/test_ml_golden.py` e `tests/test_politica.py`.
- [ ] **Step 4:** Falsos positivos nos arquivos do próprio usuário numa única invocação via `--stdin --jsonl` (nada sai da máquina, nada é commitado):

```bash
find /usr/bin ~/.local ~/projetos ~/Downloads -type f -size -8M -print0 \
  | .venv/bin/mandacaru ml avaliar --stdin --jsonl > ~/fp-local.jsonl
```

Expected: nenhum `"band": "alto"` ou `"reforco"` indevido (ou cada caso explicado com o usuário).

- [ ] **Step 5:** Commit dos modelos, `tests/fixtures/ml_golden.json`, `src/mandacaru/ml/__init__.py`, `docs/ml/relatorio-<model_id>.md` e `docs/ml/manifesto-<model_id>.txt` somente após `pytest -q` verde e como `VandyckLN` (sem `Co-Authored-By`).

### Task 15: Release 0.6.0 em modo sombra (F4/F5 em produção) — **PARADA: sudo e 2 a 4 semanas**

- [ ] **Step 1:** Versão `0.6.0` em `src/mandacaru/__init__.py`, `debian/changelog` e `CHANGELOG.md` (sai o "(em desenvolvimento)"); `docs/novidades-0.6.md` atualizado com o modelo real (tipos aprovados, métricas do relatório). Suíte verde.
- [ ] **Step 2:** O usuário monta e instala o `.deb` (`sudo apt install ./mandacaru_0.6.0_all.deb`) e confere `mandacaru ml status` (modelos e tipos aprovados) e `systemctl status mandacaru`.
- [ ] **Step 3:** **Esperar 2 a 4 semanas** de uso normal.
- [ ] **Step 4:** Revisar com o usuário: `sudo mandacaru ml sombra`. Expected: FP real dentro da meta (no máximo ~1 isolamento indevido por mês); cada caso explicado.

### Task 16: Liberar o isolamento (F6)

- [ ] **Step 1: Write the failing test** — `Config().ml_mode == "isolate"` em `tests/test_ml_wiring.py` (troca o teste que hoje espera `"shadow"`) e `tests/test_packaging.py` continua exigindo o `mode` comentado.
- [ ] **Step 2:** Rodar e ver falhar.
- [ ] **Step 3:** `ml_mode: str = "isolate"` em `config.py`; README e `docs/novidades-0.6.md` atualizados ("modo padrão: isolate"); CHANGELOG `0.6.1`.
- [ ] **Step 4:** Suíte verde.
- [ ] **Step 5:** Commit e release 0.6.1.
