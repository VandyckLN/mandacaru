# Mandacaru instalável (v0.2) — Plano de implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Qualquer pessoa instala o Mandacaru no Ubuntu/Debian com um comando (`sudo apt install ./mandacaru_0.2.0_all.deb` ou `pipx install mandacaru-edr`) e ele passa a rodar como serviço, configurado por um arquivo em `/etc/mandacaru`.

**Architecture:** Um módulo `config.py` lê um TOML e devolve um `Config` imutável; a CLI sobrepõe as flags a ele e entrega o resultado aos coletores e ao scanner. O pacote Debian é montado com `debhelper` + `pybuild` a partir do mesmo `pyproject.toml`, usando as bibliotecas do sistema (`python3-yara` etc.), e instala a unit systemd, o config e o logrotate. Um workflow de release publica o `.deb` no GitHub Releases e o wheel no PyPI quando uma tag `v*` é criada.

**Tech Stack:** Python ≥ 3.10, `tomllib`/`tomli`, setuptools, debhelper 13 + dh-python (pybuild), systemd, GitHub Actions, PyPI Trusted Publishing.

**Spec:** não há documento de spec. Este plano implementa a etapa 2 da ordem aprovada na conversa de 2026-11-14 ("arquivo de configuração em `/etc/mandacaru`, serviço systemd, pacote `.deb` e publicação no PyPI para uso via `pipx`; fecha com a release v0.2"). As decisões de design abaixo são do autor do plano e estão marcadas como tal.

## Global Constraints

- Alvos de instalação: Ubuntu 24.04+, Debian 13+. Nada de suporte a RPM nesta etapa.
- `requires-python = ">=3.10"` continua valendo; o CI já roda 3.10 a 3.14.
- Pisos de dependência baixam para o que o Ubuntu 24.04 empacota: `yara-python>=4.3`, `psutil>=5.9`, `watchdog>=3.0`.
- Nome no PyPI: **`mandacaru-edr`** (o nome `mandacaru` já pertence a outro projeto). O pacote Debian, o comando e o módulo importável continuam `mandacaru`.
- A versão existe em um só lugar: `mandacaru.__version__`. `pyproject.toml` lê dali; `debian/changelog` é conferido por teste.
- Códigos de saída: `0` sem alerta HIGH+, `2` com alerta HIGH/CRITICAL (inalterado), `1` para erro de configuração ou de E/S.
- Mensagens ao usuário em português sem acento nos textos emitidos pelo código (padrão atual do projeto); documentação em português com acento.
- `ruff check .` e `pytest -q` passam ao fim de cada task.
- Nenhuma ação de resposta (quarentena, matar processo) nesta etapa: o serviço só detecta e registra.
- Commits terminam com `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`.

## Decisões de design (do autor do plano)

1. **Formato do config: TOML com seções** (`[monitor]`, `[alerts]`, `[rules]`, `[exclude]`), porque a etapa 3 vai acrescentar `[response]` sem quebrar o formato. Chave desconhecida é erro, não é ignorada: um erro de digitação em um antivírus não pode desligar proteção em silêncio.
2. **Precedência:** flag da CLI > arquivo > padrão.
3. **O serviço roda como root** (eBPF exige) com `ProtectSystem=full`, `ProtectHome=read-only` e `NoNewPrivileges=yes`. Sem `PrivateTmp`, porque `/tmp` é uma das pastas vigiadas.
4. **`.deb` nativo com `debian/` no repositório** em vez de `fpm`/`nfpm`: é o caminho que permite entrar no Debian/PPA depois e resolve as dependências pelo apt.
5. **O serviço é habilitado e iniciado na instalação** (comportamento padrão do `dh_installsystemd`).

## Review Focus

Entradas que a etapa implica e que mais provavelmente quebram na mão de quem instala. Cada uma tem teste na task dona do código.

1. **Config com chave errada ou tipo errado** (`min_severty = "LOW"`, `paths = "/tmp"`): mensagem de uma linha citando a chave, saída `1`, sem traceback. → Task 1 e Task 3.
2. **Serviço rodando como root:** as pastas padrão precisam ser as de cada usuário em `/home/*`, não `/root/Downloads`. → Task 3.
3. **eBPF presente mas quebrado** (sem headers do kernel, WSL, contêiner): cai para psutil com aviso, em vez de derrubar o serviço em loop de restart. → Task 4.
4. **Arquivo de alertas dentro de pasta vigiada** (`--json /tmp/a.jsonl`): cada alerta gravado geraria novo evento de arquivo; o caminho do JSONL é excluído automaticamente. → Task 2 e Task 3.
5. **Arquivo de alertas não gravável** (diretório inexistente, sem permissão): mensagem de uma linha e saída `1`. → Task 3.

## Estrutura de arquivos

| Arquivo | Responsabilidade |
|---|---|
| `src/mandacaru/config.py` (novo) | `Config`, `ConfigError`, `load_config` |
| `src/mandacaru/detectors/static.py` | ganha exclusões por glob |
| `src/mandacaru/cli.py` | `--config`, precedência, pastas padrão de root, fallback do eBPF, erros com saída `1` |
| `packaging/config.toml` (novo) | config de exemplo instalado em `/etc/mandacaru/` |
| `debian/` (novo) | `control`, `rules`, `changelog`, `copyright`, `source/format`, `py3dist-overrides`, `mandacaru.service`, `mandacaru.logrotate`, `mandacaru.install`, `mandacaru.dirs` |
| `.github/workflows/deb.yml` (novo) | workflow reutilizável: monta o `.deb`, instala, testa o serviço |
| `.github/workflows/ci.yml` | passa a chamar `deb.yml` |
| `.github/workflows/release.yml` (novo) | tag `v*` → PyPI + GitHub Release |
| `tests/test_config.py`, `tests/test_cli.py`, `tests/test_packaging.py` (novos) | testes das tasks 1, 3–4 e 5–6 |
| `CHANGELOG.md` (novo), `README.md` | notas da v0.2 e instruções de instalação |

---

### Task 1: Carregador de configuração

**Files:**
- Create: `src/mandacaru/config.py`
- Modify: `pyproject.toml` (dependências)
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: `mandacaru.events.Severity`
- Produces:
  - `class ConfigError(ValueError)`
  - `DEFAULT_PATH = "/etc/mandacaru/config.toml"`
  - `@dataclass(frozen=True) class Config` com campos e padrões: `watch_paths: tuple[str, ...] = ()`, `ebpf: bool = True`, `min_severity: Severity = Severity.LOW`, `json_path: str | None = None`, `rule_dirs: tuple[str, ...] = ()`, `exclude: tuple[str, ...] = ()`
  - `load_config(path: str | os.PathLike | None = None) -> Config`

Mapeamento TOML → campo: `[monitor] paths` → `watch_paths`, `[monitor] ebpf` → `ebpf`, `[alerts] min_severity` → `min_severity`, `[alerts] json` → `json_path`, `[rules] dirs` → `rule_dirs`, `[exclude] paths` → `exclude`.

- [ ] **Step 1: Escrever os testes que falham**

```python
import pytest
from mandacaru.config import Config, ConfigError, load_config
from mandacaru.events import Severity

def write(tmp_path, text):
    p = tmp_path / "config.toml"
    p.write_text(text, encoding="utf-8")
    return p

def test_sem_arquivo_padrao_devolve_defaults(monkeypatch, tmp_path):
    monkeypatch.setattr("mandacaru.config.DEFAULT_PATH", str(tmp_path / "nao-existe.toml"))
    assert load_config() == Config()

def test_caminho_explicito_inexistente_e_erro(tmp_path):
    with pytest.raises(ConfigError, match="nao-existe.toml"):
        load_config(tmp_path / "nao-existe.toml")

def test_le_todas_as_chaves(tmp_path):
    cfg = load_config(write(tmp_path, '''
[monitor]
paths = ["/srv/uploads"]
ebpf = false
[alerts]
min_severity = "high"
json = "/var/log/mandacaru/alerts.jsonl"
[rules]
dirs = ["/etc/mandacaru/rules.d"]
[exclude]
paths = ["/home/*/.cache/*"]
'''))
    assert cfg == Config(watch_paths=("/srv/uploads",), ebpf=False, min_severity=Severity.HIGH,
                         json_path="/var/log/mandacaru/alerts.jsonl",
                         rule_dirs=("/etc/mandacaru/rules.d",), exclude=("/home/*/.cache/*",))

def test_arquivo_vazio_devolve_defaults(tmp_path):
    assert load_config(write(tmp_path, "")) == Config()

@pytest.mark.parametrize("text, trecho", [
    ('[alerts]\nmin_severty = "LOW"\n', "alerts.min_severty"),      # chave desconhecida
    ('[resposta]\nx = 1\n', "resposta"),                             # secao desconhecida
    ('[monitor]\npaths = "/tmp"\n', "monitor.paths"),                # tipo errado: str em vez de lista
    ('[monitor]\nebpf = "sim"\n', "monitor.ebpf"),                   # tipo errado: str em vez de bool
    ('[alerts]\nmin_severity = "URGENTE"\n', "alerts.min_severity"), # valor fora do enum
    ('[monitor\npaths = []\n', "TOML"),                              # sintaxe invalida
])
def test_config_invalido_cita_a_chave(tmp_path, text, trecho):
    with pytest.raises(ConfigError, match=trecho):
        load_config(write(tmp_path, text))
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `.venv/bin/python -m pytest tests/test_config.py -q`
Expected: FAIL com `ModuleNotFoundError: No module named 'mandacaru.config'`

- [ ] **Step 3: Adicionar `tomli` para Python 3.10 e baixar os pisos**

Em `pyproject.toml`, `dependencies` passa a ser exatamente:

```toml
dependencies = [
  "yara-python>=4.3",
  "psutil>=5.9",
  "watchdog>=3.0",
  "tomli>=2.0; python_version < '3.11'",
]
```

- [ ] **Step 4: Implementar `src/mandacaru/config.py`**

Importar `tomllib` com fallback para `tomli` em 3.10. Toda `ConfigError` leva o caminho do arquivo e a chave pontuada (`alerts.min_severity`) na mensagem; erro de sintaxe leva a palavra `TOML`. `min_severity` aceita qualquer caixa. Listas viram tuplas.

- [ ] **Step 5: Rodar e ver passar**

Run: `.venv/bin/pip install -q -e ".[dev]" && .venv/bin/python -m pytest -q && .venv/bin/ruff check .`
Expected: todos passam (19 antigos + 10 novos), `All checks passed!`

- [ ] **Step 6: Commit**

```bash
git add src/mandacaru/config.py tests/test_config.py pyproject.toml
git commit -m "Adiciona carregador de configuracao TOML"
```

---

### Task 2: Exclusões no scanner

**Files:**
- Modify: `src/mandacaru/detectors/static.py` (classe `StaticScanner`)
- Test: `tests/test_detectors.py`

**Interfaces:**
- Produces:
  - `StaticScanner.__init__(self, extra_rule_dirs: Iterable[str] = (), exclude: Iterable[str] = ())`
  - `StaticScanner.is_excluded(self, path: str | os.PathLike) -> bool` — `fnmatch.fnmatchcase` do caminho **absoluto** contra cada padrão (`*` atravessa `/`).
  - `scan_file` devolve `[]` para caminho excluído; `scan_tree` não desce em diretório excluído.

- [ ] **Step 1: Escrever os testes que falham** (acrescentar ao fim de `tests/test_detectors.py`)

```python
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

def test_exclusao_ignora_arquivo(tmp_path):
    f = tmp_path / "eicar.txt"
    f.write_text(EICAR)
    assert StaticScanner(exclude=[str(tmp_path / "*.txt")]).scan_file(f) == []
    assert StaticScanner(exclude=["/outro/lugar/*"]).scan_file(f) != []

def test_exclusao_usa_caminho_absoluto(tmp_path, monkeypatch):
    (tmp_path / "eicar.txt").write_text(EICAR)
    monkeypatch.chdir(tmp_path)
    assert StaticScanner(exclude=[str(tmp_path / "eicar.txt")]).scan_file("eicar.txt") == []

def test_scan_tree_nao_desce_em_pasta_excluida(tmp_path):
    (tmp_path / "cache").mkdir()
    (tmp_path / "cache" / "eicar.txt").write_text(EICAR)
    (tmp_path / "ok.txt").write_text(EICAR)
    alerts = list(StaticScanner(exclude=[str(tmp_path / "cache")]).scan_tree(tmp_path))
    assert [a.evidence["path"] for a in alerts] == [str(tmp_path / "ok.txt")]
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `.venv/bin/python -m pytest tests/test_detectors.py -q -k "exclus or pasta_excluida"`
Expected: FAIL com `TypeError: ... unexpected keyword argument 'exclude'`

- [ ] **Step 3: Implementar** conforme as assinaturas acima.

- [ ] **Step 4: Rodar e ver passar**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check .`
Expected: todos passam.

- [ ] **Step 5: Commit**

```bash
git add src/mandacaru/detectors/static.py tests/test_detectors.py
git commit -m "Scanner aceita exclusoes por glob"
```

---

### Task 3: CLI lê o config

**Files:**
- Modify: `src/mandacaru/cli.py`
- Test: `tests/test_cli.py` (novo)

**Interfaces:**
- Consumes: `Config`, `ConfigError`, `load_config` (Task 1); `StaticScanner(extra_rule_dirs, exclude)` (Task 2).
- Produces:
  - Flag global `--config CAMINHO`.
  - `--min-severity` passa a ter `default=None` (ausente = usa o config).
  - `effective_config(args: argparse.Namespace) -> Config` — carrega o config e sobrepõe as flags: `--rules` é **acrescentado** a `rule_dirs`; `--json` substitui `json_path`; `--min-severity` substitui `min_severity`; no `monitor`, caminhos posicionais substituem `watch_paths` e `--no-ebpf` força `ebpf=False`. Se `json_path` não for `None`, seu caminho absoluto é acrescentado a `exclude`.
  - `default_watch_paths(euid: int | None = None, home_root: Path = Path("/home")) -> list[str]` — `euid=None` usa `os.geteuid()` em posix. Com `euid == 0`: `Downloads`, `Documents`, `Documentos`, `Desktop`, `Área de Trabalho` de cada subdiretório de `home_root`, mais `/tmp` e `/dev/shm`; só os que existem. Caso contrário, o comportamento atual.
  - `main()` captura `ConfigError` e `OSError` ao abrir o JSONL, imprime `mandacaru: erro: <mensagem>` em stderr e devolve `1`.
  - `cmd_scan` e `cmd_monitor` usam `effective_config(args)` em vez de ler `args.rules/json/min_severity` direto.

- [ ] **Step 1: Escrever os testes que falham**

```python
import os
from mandacaru import cli
from mandacaru.events import Severity

EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

def parse(argv):
    return cli.build_parser().parse_args(argv)

def cfgfile(tmp_path, text):
    p = tmp_path / "c.toml"
    p.write_text(text, encoding="utf-8")
    return str(p)

def test_flag_vence_o_arquivo(tmp_path):
    c = cfgfile(tmp_path, '[alerts]\nmin_severity = "HIGH"\njson = "/a.jsonl"\n[rules]\ndirs = ["/r1"]\n')
    cfg = cli.effective_config(parse(["--config", c, "--min-severity", "LOW", "--json", "/b.jsonl",
                                      "--rules", "/r2", "scan", "."]))
    assert cfg.min_severity == Severity.LOW
    assert cfg.json_path == "/b.jsonl"
    assert cfg.rule_dirs == ("/r1", "/r2")

def test_arquivo_vale_quando_nao_ha_flag(tmp_path):
    c = cfgfile(tmp_path, '[alerts]\nmin_severity = "HIGH"\n[monitor]\npaths = ["/srv"]\nebpf = true\n')
    cfg = cli.effective_config(parse(["--config", c, "monitor"]))
    assert (cfg.min_severity, cfg.watch_paths, cfg.ebpf) == (Severity.HIGH, ("/srv",), True)
    cfg = cli.effective_config(parse(["--config", c, "monitor", "--no-ebpf", "/outro"]))
    assert (cfg.watch_paths, cfg.ebpf) == (("/outro",), False)

def test_json_e_excluido_automaticamente(tmp_path):
    out = tmp_path / "alerts.jsonl"
    cfg = cli.effective_config(parse(["--json", str(out), "scan", "."]))
    assert os.path.abspath(out) in cfg.exclude

def test_scan_nao_escaneia_o_proprio_jsonl(tmp_path):
    out = tmp_path / "alerts.jsonl"
    out.write_text(EICAR)          # um JSONL antigo cujo conteudo casaria com uma regra
    assert cli.main(["--json", str(out), "scan", str(tmp_path)]) == 0
    assert out.read_text() == EICAR   # nenhum alerta gravado: o proprio arquivo foi pulado

def test_root_vigia_home_de_cada_usuario(tmp_path):
    (tmp_path / "ana" / "Downloads").mkdir(parents=True)
    (tmp_path / "bia" / "Documentos").mkdir(parents=True)
    got = cli.default_watch_paths(euid=0, home_root=tmp_path)
    assert str(tmp_path / "ana" / "Downloads") in got
    assert str(tmp_path / "bia" / "Documentos") in got
    assert not any(p.startswith("/root") for p in got)

def test_config_invalido_sai_com_1_sem_traceback(tmp_path, capsys):
    c = cfgfile(tmp_path, '[alerts]\nmin_severty = "LOW"\n')
    assert cli.main(["--config", c, "scan", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "mandacaru: erro:" in err and "alerts.min_severty" in err and "Traceback" not in err

def test_json_nao_gravavel_sai_com_1(tmp_path, capsys):
    assert cli.main(["--json", str(tmp_path / "nao" / "existe" / "a.jsonl"), "scan", str(tmp_path)]) == 1
    assert "mandacaru: erro:" in capsys.readouterr().err
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `.venv/bin/python -m pytest tests/test_cli.py -q`
Expected: FAIL com `AttributeError: module 'mandacaru.cli' has no attribute 'build_parser'`

- [ ] **Step 3: Implementar em `cli.py`**

Extrair a montagem do `argparse` de `main` para `build_parser() -> argparse.ArgumentParser`. O resto conforme as Interfaces. `cmd_monitor` usa `list(cfg.watch_paths) or default_watch_paths()`.

- [ ] **Step 4: Rodar e ver passar**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check .`
Expected: todos passam.

- [ ] **Step 5: Commit**

```bash
git add src/mandacaru/cli.py tests/test_cli.py
git commit -m "CLI le /etc/mandacaru/config.toml; flags sobrepoem o arquivo"
```

---

### Task 4: eBPF quebrado cai para psutil

**Files:**
- Modify: `src/mandacaru/cli.py` (`cmd_monitor`)
- Test: `tests/test_cli.py`

**Interfaces:**
- Produces: `start_process_collector(q: queue.Queue, use_ebpf: bool) -> tuple[str, Callable[[], None]]` — devolve `("ebpf", stop)` ou `("psutil", stop)`. Tenta eBPF só se `use_ebpf and ebpf.available()`; qualquer exceção ao criar ou iniciar o `ExecTracer` imprime `[mandacaru] eBPF indisponivel (<exc>); usando psutil` em stderr e segue com `ProcessMonitor`. `cmd_monitor` passa a chamá-la com `cfg.ebpf`.

- [ ] **Step 1: Escrever os testes que falham** (acrescentar a `tests/test_cli.py`)

```python
import queue

class FakeCollector:
    def __init__(self, q): self.started = False
    def start(self): self.started = True
    def stop(self): pass

def test_ebpf_quebrado_cai_para_psutil(monkeypatch, capsys):
    def boom(q):
        raise RuntimeError("sem headers do kernel")
    monkeypatch.setattr(cli.ebpf, "available", lambda: True)
    monkeypatch.setattr(cli.ebpf, "ExecTracer", boom)
    monkeypatch.setattr(cli, "ProcessMonitor", FakeCollector)
    kind, stop = cli.start_process_collector(queue.Queue(), use_ebpf=True)
    assert kind == "psutil" and callable(stop)
    assert "eBPF indisponivel (sem headers do kernel)" in capsys.readouterr().err

def test_ebpf_desligado_nem_tenta(monkeypatch):
    monkeypatch.setattr(cli.ebpf, "available", lambda: True)
    monkeypatch.setattr(cli.ebpf, "ExecTracer", lambda q: (_ for _ in ()).throw(AssertionError("nao devia tentar")))
    monkeypatch.setattr(cli, "ProcessMonitor", FakeCollector)
    assert cli.start_process_collector(queue.Queue(), use_ebpf=False)[0] == "psutil"

def test_ebpf_funcionando_e_usado(monkeypatch):
    monkeypatch.setattr(cli.ebpf, "available", lambda: True)
    monkeypatch.setattr(cli.ebpf, "ExecTracer", FakeCollector)
    assert cli.start_process_collector(queue.Queue(), use_ebpf=True)[0] == "ebpf"
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `.venv/bin/python -m pytest tests/test_cli.py -q -k ebpf`
Expected: FAIL com `AttributeError: ... has no attribute 'start_process_collector'`

- [ ] **Step 3: Implementar** conforme a Interface.

- [ ] **Step 4: Rodar e ver passar**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check .`
Expected: todos passam.

- [ ] **Step 5: Teste manual do monitor de ponta a ponta**

```bash
.venv/bin/mandacaru --json /tmp/mdc-test.jsonl monitor /tmp/mdc-watch --no-ebpf &   # criar /tmp/mdc-watch antes
sleep 2; printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/mdc-watch/e.txt
sleep 2; kill %1; grep -c EICAR_Test_File /tmp/mdc-test.jsonl
```
Expected: `1`

- [ ] **Step 6: Commit**

```bash
git add src/mandacaru/cli.py tests/test_cli.py
git commit -m "Monitor cai para psutil quando o eBPF falha ao iniciar"
```

---

### Task 5: Pacote Debian com serviço systemd

**Files:**
- Create: `packaging/config.toml`, `debian/control`, `debian/rules` (modo 755), `debian/changelog`, `debian/copyright`, `debian/source/format`, `debian/py3dist-overrides`, `debian/mandacaru.service`, `debian/mandacaru.logrotate`, `debian/mandacaru.install`, `debian/mandacaru.dirs`
- Create: `.github/workflows/deb.yml`
- Modify: `.github/workflows/ci.yml`, `pyproject.toml`, `.gitignore`
- Test: `tests/test_packaging.py`

**Interfaces:**
- Consumes: `load_config` (Task 1); o comando `mandacaru --config ... monitor` (Task 3).
- Produces: artefato `mandacaru_<versão>_all.deb`; workflow reutilizável `deb.yml` (`on: workflow_call`) que publica o artefato de Actions chamado `deb`.

- [ ] **Step 1: Escrever os testes que falham** (`tests/test_packaging.py`)

```python
import re
from pathlib import Path
import pytest
import mandacaru
from mandacaru.config import Config, load_config
from mandacaru.events import Severity

ROOT = Path(__file__).resolve().parent.parent
# o pybuild copia tests/ para um diretorio de build sem debian/ nem packaging/
pytestmark = pytest.mark.skipif(not (ROOT / "debian").is_dir(), reason="fora da arvore de fontes")

def test_config_de_exemplo_e_valido():
    cfg = load_config(ROOT / "packaging" / "config.toml")
    assert cfg == Config(ebpf=True, min_severity=Severity.LOW,
                         json_path="/var/log/mandacaru/alerts.jsonl",
                         rule_dirs=("/etc/mandacaru/rules.d",))

def test_versao_do_changelog_debian_bate_com_o_pacote():
    first = (ROOT / "debian" / "changelog").read_text().splitlines()[0]
    assert re.match(r"mandacaru \(([^)]+)\)", first).group(1) == mandacaru.__version__

def test_unit_aponta_para_o_config_instalado():
    unit = (ROOT / "debian" / "mandacaru.service").read_text()
    assert "ExecStart=/usr/bin/mandacaru --config /etc/mandacaru/config.toml monitor" in unit
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `.venv/bin/python -m pytest tests/test_packaging.py -q`
Expected: 3 FAIL (`FileNotFoundError` / `ConfigError`)

- [ ] **Step 3: Versão em um só lugar**

Em `pyproject.toml`: remover `version = "0.1.0"`, adicionar `dynamic = ["version"]` em `[project]` e:

```toml
[tool.setuptools.dynamic]
version = { attr = "mandacaru.__version__" }
```

Verificar: `.venv/bin/pip install -q -e . && .venv/bin/mandacaru --version` → `0.1.0`.

- [ ] **Step 4: Criar `packaging/config.toml`** (conteúdo exato)

```toml
# Mandacaru - configuracao do servico. Depois de editar: sudo systemctl restart mandacaru

[monitor]
# Pastas vigiadas. Sem esta chave: Downloads, Documentos e Desktop de cada usuario, mais /tmp e /dev/shm.
# paths = ["/home/ana/Downloads", "/srv/uploads"]
ebpf = true          # ve todo execve pelo kernel; se nao funcionar, cai para psutil sozinho

[alerts]
min_severity = "LOW" # INFO | LOW | MEDIUM | HIGH | CRITICAL
json = "/var/log/mandacaru/alerts.jsonl"

[rules]
dirs = ["/etc/mandacaru/rules.d"]   # suas regras .yar

[exclude]
paths = []           # globs de caminho absoluto, ex.: "/home/*/.cache/*"
```

- [ ] **Step 5: Criar os arquivos de `debian/`** (conteúdo exato; `Maintainer` usa o e-mail do `git log -1 --format=%ae`)

`debian/control`:
```
Source: mandacaru
Section: admin
Priority: optional
Maintainer: Vandyck Diniz <E-MAIL DO GIT LOG>
Build-Depends: debhelper-compat (= 13), dh-python, pybuild-plugin-pyproject,
 python3-all, python3-setuptools, python3-pytest, python3-yara, python3-psutil, python3-watchdog
Standards-Version: 4.7.0
Homepage: https://github.com/VandyckLN/mandacaru
Rules-Requires-Root: no

Package: mandacaru
Architecture: all
Depends: ${python3:Depends}, ${misc:Depends}, python3-yara, python3-psutil, python3-watchdog
Recommends: python3-bpfcc, logrotate
Description: antivirus/EDR de codigo aberto contra ataques conduzidos por IA
 Detecta tecnicas (ofuscacao + execucao, criptografia em massa, shell aberto
 por servico, agente de IA lendo credenciais) em vez de assinaturas de bytes.
 Roda como servico systemd e grava alertas em JSON Lines.
```

`debian/rules`:
```make
#!/usr/bin/make -f
export PYBUILD_TEST_PYTEST = 1
%:
	dh $@ --with python3 --buildsystem=pybuild
```

`debian/changelog` (data no formato de `date -R`):
```
mandacaru (0.1.0) unstable; urgency=medium

  * Primeiro pacote Debian.

 -- Vandyck Diniz <E-MAIL DO GIT LOG>  Sat, 14 Nov 2026 12:00:00 -0300
```

`debian/source/format`: `3.0 (native)`

`debian/py3dist-overrides`:
```
yara-python python3-yara
```

`debian/copyright`: formato DEP-5, `Files: *`, `Copyright: 2026 Vandyck Diniz`, `License: GPL-3+` com o parágrafo padrão apontando para `/usr/share/common-licenses/GPL-3`.

`debian/mandacaru.install`: `packaging/config.toml etc/mandacaru`

`debian/mandacaru.dirs`: `etc/mandacaru/rules.d`

`debian/mandacaru.service`:
```ini
[Unit]
Description=Mandacaru - antivirus/EDR
Documentation=https://github.com/VandyckLN/mandacaru
After=local-fs.target

[Service]
Type=simple
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/mandacaru --config /etc/mandacaru/config.toml monitor
Restart=on-failure
RestartSec=5
LogsDirectory=mandacaru
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
```

`debian/mandacaru.logrotate` (`copytruncate` porque o serviço mantém o arquivo aberto em modo append):
```
/var/log/mandacaru/*.jsonl {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    copytruncate
}
```

Acrescentar a `.gitignore`: `debian/.debhelper/`, `debian/mandacaru/`, `debian/files`, `debian/*.substvars`, `debian/*.debhelper*`, `.pybuild/`, `dist/`, `build/`.

- [ ] **Step 6: Rodar os testes locais e ver passar**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check .`
Expected: todos passam.

- [ ] **Step 7: Criar `.github/workflows/deb.yml`**

`on: workflow_call`, `permissions: contents: read`. Dois jobs:

`build` (`runs-on: ubuntu-24.04`):
1. `actions/checkout@v4`
2. `sudo apt-get update && sudo apt-get install -y debhelper dh-python pybuild-plugin-pyproject python3-all python3-setuptools python3-pytest python3-yara python3-psutil python3-watchdog`
3. `dpkg-buildpackage -us -uc -b && mkdir dist && mv ../mandacaru_*_all.deb dist/`
4. Conferir o conteúdo — o passo falha se faltar algum:
   ```bash
   dpkg-deb -c dist/*.deb | tee contents.txt
   for f in usr/bin/mandacaru dist-packages/mandacaru/rules/yara/base.yar etc/mandacaru/config.toml \
            etc/mandacaru/rules.d/ systemd/system/mandacaru.service etc/logrotate.d/mandacaru; do
     grep -q "$f" contents.txt || { echo "faltou $f"; exit 1; }
   done
   dpkg-deb -f dist/*.deb Depends | grep -q python3-yara
   ```
5. Instalar e testar o serviço de verdade (o runner tem systemd):
   ```bash
   sudo apt-get install -y ./dist/*.deb
   systemd-analyze verify /usr/lib/systemd/system/mandacaru.service
   sleep 3 && systemctl is-active mandacaru
   printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar-ci.txt
   sleep 5 && sudo grep -q EICAR_Test_File /var/log/mandacaru/alerts.jsonl
   sudo journalctl -u mandacaru --no-pager | tail -20
   sudo apt-get remove -y mandacaru && ! systemctl is-active mandacaru
   ```
6. `actions/upload-artifact@v4` com `name: deb`, `path: dist/*.deb`.

`install` (`needs: build`, `runs-on: ubuntu-latest`, `strategy.matrix.image: ["ubuntu:24.04", "ubuntu:26.04", "debian:13"]`, `container: ${{ matrix.image }}`):
1. `actions/download-artifact@v4` com `name: deb`
2. `apt-get update && apt-get install -y ./mandacaru_*_all.deb`
3. `mandacaru --version`
4. Varredura real com as bibliotecas da distro:
   ```bash
   printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/e.txt
   mandacaru --config /etc/mandacaru/config.toml --json /tmp/a.jsonl scan /tmp/e.txt
   grep -q EICAR_Test_File /tmp/a.jsonl
   ```

Em `ci.yml`, acrescentar o job:
```yaml
  deb:
    uses: ./.github/workflows/deb.yml
```

- [ ] **Step 8: Commit, push e ver o CI passar**

```bash
git add debian packaging .github tests/test_packaging.py pyproject.toml .gitignore
git commit -m "Pacote Debian com servico systemd, config e logrotate"
git push && gh run watch --exit-status
```
Expected: jobs `test` (5), `deb / build` e `deb / install` (3) verdes. O build do `.deb` só é verificável aqui: a máquina de desenvolvimento não tem `debhelper` nem Docker no WSL. Se `dpkg-buildpackage` falhar no `dh_python3` por causa do nome da dependência do YARA, o ajuste é em `debian/py3dist-overrides`; se falhar no `dh_auto_test`, é em `PYBUILD_TEST_ARGS`.

---

### Task 6: Release v0.2.0 (PyPI + GitHub Release)

**Files:**
- Create: `.github/workflows/release.yml`, `CHANGELOG.md`
- Modify: `pyproject.toml` (`name`), `src/mandacaru/__init__.py`, `debian/changelog`, `README.md`, `CONTRIBUTING.md`
- Test: `tests/test_packaging.py`

**Interfaces:**
- Consumes: workflow `deb.yml` e seu artefato `deb` (Task 5).
- Produces: tag `v0.2.0` → `mandacaru-edr 0.2.0` no PyPI e `mandacaru_0.2.0_all.deb` anexado ao GitHub Release.

**Pré-requisito humano (uma vez, antes do Step 6):** criar conta no PyPI e cadastrar um *pending trusted publisher*: projeto `mandacaru-edr`, owner `VandyckLN`, repositório `mandacaru`, workflow `release.yml`, environment `pypi`. No GitHub, criar o environment `pypi` no repositório.

- [ ] **Step 1: Escrever o teste que falha** (acrescentar a `tests/test_packaging.py`)

```python
def test_nome_no_pypi_e_changelog_da_versao():
    import tomllib
    proj = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert proj["name"] == "mandacaru-edr"
    assert f"## {mandacaru.__version__}" in (ROOT / "CHANGELOG.md").read_text()
```
(Em 3.10 o `tomllib` não existe: usar `pytest.importorskip("tomllib")` no lugar do `import`.)

- [ ] **Step 2: Rodar e ver falhar**

Run: `.venv/bin/python -m pytest tests/test_packaging.py -q`
Expected: FAIL em `proj["name"] == "mandacaru-edr"`

- [ ] **Step 3: Renomear a distribuição e subir a versão**

- `pyproject.toml`: `name = "mandacaru-edr"`.
- `src/mandacaru/__init__.py`: `__version__ = "0.2.0"`.
- `debian/changelog`: nova entrada `mandacaru (0.2.0)` no topo (config, serviço systemd, exclusões, fallback do eBPF).
- `CHANGELOG.md`: seções `## 0.2.0` (config em `/etc/mandacaru/config.toml`; serviço systemd; pacote `.deb`; `pipx install mandacaru-edr`; exclusões por glob; como root vigia `/home/*`; eBPF com fallback; saída `1` para erro de config) e `## 0.1.0` (protótipo inicial).

- [ ] **Step 4: Atualizar a documentação**

`README.md`, seção **Instalação**, nesta ordem:
1. **Ubuntu/Debian (recomendado, instala o serviço):** baixar o `.deb` da página de Releases e `sudo apt install ./mandacaru_0.2.0_all.deb`; depois `systemctl status mandacaru` e `sudo tail -f /var/log/mandacaru/alerts.jsonl`.
2. **Só a ferramenta de varredura:** `pipx install mandacaru-edr` (com a nota de `python3-dev libssl-dev` caso o pip precise compilar o YARA).
3. **Desenvolvimento:** o bloco atual de `git clone` + venv.

Nova seção **Configuração** com o conteúdo de `packaging/config.toml` e a regra de precedência (flag > arquivo > padrão). Atualizar o status para `v0.2`, o número de testes e marcar `[x] Serviço systemd + pacote .deb` no Roadmap. Em `CONTRIBUTING.md`, acrescentar como montar o `.deb` localmente (`sudo apt install` das Build-Depends + `dpkg-buildpackage -us -uc -b`).

- [ ] **Step 5: Criar `.github/workflows/release.yml`**

`on: push: tags: ["v*"]`. Jobs:
- `deb`: `uses: ./.github/workflows/deb.yml`.
- `wheel` (`ubuntu-latest`): checkout; `actions/setup-python@v5` 3.13; `pip install build && python -m build`; falhar se `v$(python -c 'import sys; sys.path.insert(0,"src"); import mandacaru; print(mandacaru.__version__)')` for diferente de `$GITHUB_REF_NAME`; `upload-artifact` `name: wheel`, `path: dist/*`.
- `pypi` (`needs: [wheel, deb]`, `environment: pypi`, `permissions: id-token: write`): baixar `wheel` em `dist/`; `pypa/gh-action-pypi-publish@release/v1`.
- `github-release` (`needs: [pypi]`, `permissions: contents: write`): baixar `wheel` e `deb` em `dist/`; `gh release create "$GITHUB_REF_NAME" dist/* --generate-notes` com `GH_TOKEN: ${{ github.token }}`.

- [ ] **Step 6: Rodar tudo, commit, merge e tag**

```bash
.venv/bin/pip install -q -e ".[dev]" && .venv/bin/python -m pytest -q && .venv/bin/ruff check .
.venv/bin/pip install -q build && .venv/bin/python -m build && ls dist/   # mandacaru_edr-0.2.0-py3-none-any.whl e .tar.gz
git add -A && git commit -m "Release v0.2.0: instalavel via .deb e pipx"
git push && gh run watch --exit-status
```
Depois do merge em `main` **e com o pré-requisito humano feito**: `git tag v0.2.0 && git push origin v0.2.0 && gh run watch --exit-status`.

- [ ] **Step 7: Verificação final em máquina limpa**

```bash
pipx install mandacaru-edr && mandacaru --version          # 0.2.0
gh release view v0.2.0 --json assets -q '.assets[].name'   # inclui mandacaru_0.2.0_all.deb
```
Expected: os dois comandos mostram a versão `0.2.0`.
