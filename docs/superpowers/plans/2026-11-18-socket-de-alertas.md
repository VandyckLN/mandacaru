# Socket de alertas (v0.3.0) — plano de implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** o `mandacaru monitor` publica cada alerta, em tempo real, como uma linha JSON v1 num socket Unix restrito ao grupo `mandacaru`, e o pacote sobe para 0.3.0.

**Architecture:** o módulo novo `alert_socket.py` tem um servidor `AF_UNIX`, que só transmite, e uma thread que aceita clientes. O sink é chamado na thread do motor e envia em modo não bloqueante, derrubando quem não acompanha. O `cli.py` monta os sinks numa função testável (`build_sinks`), e a unit, o `postinst` e o config empacotado entregam o diretório, o grupo e o caminho.

**Tech Stack:** Python 3.10+ só com a biblioteca padrão (`socket`, `threading`, `grp`, `json`), pytest e ruff. Empacotamento com debhelper 13 e systemd.

**Spec:** `docs/superpowers/specs/2026-11-17-socket-de-alertas-design.md`

## Global Constraints

- Caminho padrão do socket: `/run/mandacaru/alerts.sock`. Modo `0660`, dono `root:mandacaru`. Sem o grupo, ou sem permissão de `chown`, o modo é `0600`.
- A linha é exatamente `{"v":1,"ts":…,"severity":…,"rule":…,"summary":…,"mitre":[…]}` + `"\n"`, em UTF-8 com `ensure_ascii=False`. **Nunca** inclui a `evidence`.
- O sink nunca levanta exceção para o motor e nunca bloqueia: o envio é não bloqueante, e qualquer erro derruba só aquele cliente.
- O socket só transmite: nada do que o cliente envia é lido.
- Mensagens no stderr em ASCII sem acento, com o prefixo `[mandacaru] `, como no resto do código.
- Versão `0.3.0` em `src/mandacaru/__init__.py`, `CHANGELOG.md` e `debian/changelog`.
- Só biblioteca padrão. O `ruff check .` (line-length 120) e o `pytest -q` precisam passar, porque são o que o CI roda.
- **O caminho do `AF_UNIX` tem limite de 108 bytes.** O `tmp_path` do pytest, somado a nomes de teste longos, passa disso. Os testes de socket usam a fixture `short_dir`, em `tests/conftest.py` (crie o arquivo), com `tempfile.mkdtemp(prefix="mc", dir="/tmp")` e remoção no teardown. A fixture vale para os testes da Task 1 e da Task 2.
- Trabalho no branch `feat/socket-alertas`. Push, PR, merge e tag `v0.3.0` são só do autor.

## Review Focus

1. **Corrida entre o accept e o emit:** a thread que aceita clientes e a thread do motor mexem na mesma lista. Todo acesso tem que passar pelo lock, e um cliente aceito no meio de um envio não pode causar `RuntimeError: list changed size`.
2. **Parada com o `accept` bloqueado:** o `stop()` tem que encerrar a thread em menos de 1 s, mesmo sem nenhum cliente. Fechar o socket de outra thread não acorda o `accept` no Linux, por isso o socket de escuta usa timeout.
3. **Envio parcial:** um `sendall` não bloqueante pode escrever meia linha e depois levantar `BlockingIOError`. O cliente precisa ser derrubado ali, para nunca receber a segunda metade colada à linha seguinte.
4. **Clientes mortos acumulando:** um cliente que conecta e desconecta sem que nenhum alerta saia fica na lista até o próximo envio. Isso é aceitável, desde que o próximo envio o remova sem exceção.
5. **`chown` sem root:** rodando como usuário comum (teste, `mandacaru monitor` à mão), o `chown` para um grupo do qual o usuário não faz parte falha. Nesse caso o socket fica `0600` e o monitor segue. Isso fica preso pelo teste `test_chown_negado_cai_para_0600`, na Task 1.

---

### Task 1: `socket_sink` em `alert_socket.py`

**Files:**
- Create: `src/mandacaru/alert_socket.py`
- Create: `tests/conftest.py` (fixture `short_dir`)
- Test: `tests/test_socket_sink.py`

**Interfaces:**
- Consumes: `Alert` e `Severity` de `mandacaru.events`, e `AlertSink` de `mandacaru.engine`.
- Produces:
  - `socket_sink(path: str, min_sev: Severity) -> tuple[AlertSink, Callable[[], None]]`, que levanta `OSError` se o caminho estiver ocupado por algo que não é um socket ou se o diretório pai não existir;
  - `alert_line(alert: Alert) -> bytes`, a linha v1 já com `\n`;
  - `GROUP = "mandacaru"`;
  - `_group_gid(name: str) -> int | None`, o ponto de troca dos testes, que faz `grp.getgrnam` e devolve `None` com `KeyError`.

- [ ] **Step 1: Escrever os testes que falham**

Os helpers do arquivo são:
- `mk(sev=Severity.HIGH, summary="Shell bash com conexao de rede ativa")`, que monta um `Alert(rule="behavior.revshell", severity=sev, summary=summary, evidence={"cmdline": ["bash", "-i"], "pid": 42}, mitre=["T1059"], ts=1794872689.2)`;
- `connect(path)`, que devolve um socket cliente conectado com `settimeout(2)` e depois dá `time.sleep(0.1)`, para a thread de accept registrar o cliente;
- `readline(sock) -> dict`, que lê até o `\n` e faz `json.loads`;
- a fixture `short_dir`, que veio do Global Constraints (o limite de 108 bytes do `AF_UNIX`).

Todos os testes usam `path = os.path.join(short_dir, "a.sock")` e chamam `stop()` no fim.

```python
def test_cliente_recebe_json_v1_sem_evidence(short_dir):
    sink, stop = socket_sink(path, Severity.LOW); c = connect(path); time.sleep(0.1)
    sink(mk())
    assert readline(c) == {"v": 1, "ts": 1794872689.2, "severity": "HIGH", "rule": "behavior.revshell",
                           "summary": "Shell bash com conexao de rede ativa", "mitre": ["T1059"]}

def test_resumo_com_acento_sai_em_utf8(short_dir):
    # alert_line(mk(summary="Ação suspeita: relatório.sh")) contém "Ação".encode() e não contém b"\\u00e7"

def test_abaixo_do_min_sev_nao_sai(short_dir):
    # min_sev=HIGH; sink(mk(Severity.MEDIUM)); sink(mk(Severity.HIGH)) -> a primeira linha lida é HIGH

def test_dois_clientes_recebem_o_mesmo_alerta(short_dir):
    # dois connect(); um sink(mk()); readline dos dois devolve o mesmo dict

def test_cliente_que_nao_le_e_derrubado_sem_travar(short_dir):
    # lento = connect(path) que nunca lê; rapido = connect(path) lido por uma thread que conta as linhas
    # t0 = time.monotonic(); 200 x sink(mk(summary="x" * 65536)); assert time.monotonic() - t0 < 1.0
    # o rapido recebeu as 200 linhas; lento.recv() termina com b"" ou ConnectionResetError (foi fechado)

def test_cliente_que_fecha_e_removido_sem_excecao(short_dir):
    # c = connect(path); c.close(); time.sleep(0.1); sink(mk()); sink(mk())  # nenhuma exceção

def test_socket_velho_e_recriado(short_dir):
    # cria um socket AF_UNIX em path com bind e fecha (fica o arquivo); socket_sink(path, ...) funciona

def test_arquivo_comum_no_caminho_nao_e_apagado(short_dir):
    # path com write_text("x"); pytest.raises(OSError): socket_sink(path, ...); o conteúdo continua "x"

def test_pai_inexistente_levanta_oserror(short_dir):
    # pytest.raises(OSError): socket_sink(os.path.join(short_dir, "nao", "a.sock"), Severity.LOW)

def test_sem_grupo_fica_0600_e_avisa(short_dir, monkeypatch, capsys):
    # monkeypatch _group_gid -> None; stat.S_IMODE(os.stat(path).st_mode) == 0o600
    # "[mandacaru] grupo mandacaru ausente: socket so para root" no stderr

def test_com_grupo_fica_0660_no_grupo(short_dir, monkeypatch):
    # monkeypatch _group_gid -> os.getgid(); modo 0o660 e st_gid == os.getgid()

def test_chown_negado_cai_para_0600(short_dir, monkeypatch, capsys):
    # pytest.skip se os.geteuid() == 0; monkeypatch _group_gid -> 0 (grupo root, ao qual o usuário comum não pertence)
    # modo 0o600; "[mandacaru] sem permissao para dar o socket ao grupo mandacaru: socket so para root" no stderr

def test_stop_apaga_o_socket_e_encerra_rapido(short_dir):
    # t0; stop(); time.monotonic() - t0 < 1.0; not os.path.exists(path); sink(mk()) depois do stop não levanta
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `.venv/bin/python -m pytest tests/test_socket_sink.py -q`
Expected: erro de coleta `ModuleNotFoundError: No module named 'mandacaru.alert_socket'`.

- [ ] **Step 3: Implementar `src/mandacaru/alert_socket.py`**

- `alert_line` faz `json.dumps({...}, ensure_ascii=False, separators=(",", ":"))`, com as chaves na ordem `v, ts, severity, rule, summary, mitre`, e devolve `.encode() + b"\n"`.
- **Preparar o caminho:** se o caminho existe e é socket (`stat.S_ISSOCK`), faz `os.unlink`. Se existe e é outra coisa, levanta `FileExistsError`, que é subclasse de `OSError`. O pai inexistente faz o próprio `bind` levantar `FileNotFoundError`.
- **Permissão, depois do `bind`:**
  1. `gid = _group_gid(GROUP)`;
  2. se `gid is None`, faz `chmod 0o600` e imprime o aviso de grupo ausente;
  3. se não, tenta `os.chown(path, -1, gid)` e depois `chmod 0o660`. Com `PermissionError`, faz `chmod 0o600` e imprime o aviso de `chown` negado.
- **Escuta:** `listen(16)` e `settimeout(0.5)`. A thread daemon `mandacaru-alert-socket` roda `accept` em laço até o `threading.Event` de parada. Ignora `TimeoutError`/`socket.timeout`, coloca o cliente em `setblocking(False)` e o adiciona à lista com o lock. Sai do laço com `OSError` depois do stop.
- **`_sink`:**
  1. retorna se `alert.severity < min_sev` ou se já parou;
  2. monta a linha uma vez;
  3. com o lock, tenta `sendall` em cada cliente. Qualquer `OSError`, incluindo `BlockingIOError`, fecha e remove o cliente (Review Focus 3);
  4. envolve tudo num `except Exception`, para nunca propagar.
- **`stop`:** é idempotente. Liga o evento, faz `join(1.0)` na thread, fecha o servidor e os clientes e faz `os.unlink(path)` com `FileNotFoundError` ignorado.

- [ ] **Step 4: Rodar e ver passar**

Run: `.venv/bin/python -m pytest tests/test_socket_sink.py -q && .venv/bin/ruff check .`
Expected: os 13 testes passam e o ruff mostra `All checks passed!`.

- [ ] **Step 5: Commit**

```bash
git add src/mandacaru/alert_socket.py tests/conftest.py tests/test_socket_sink.py
git commit -m "Socket de alertas: transmite cada alerta como JSON v1 sem travar o motor"
```

### Task 2: chave `[alerts] socket` e ligação no `monitor`

**Files:**
- Modify: `src/mandacaru/config.py` (campo `Config.socket_path`, `_SCHEMA["alerts"]`)
- Modify: `src/mandacaru/cli.py` (`cmd_monitor` passa a usar `build_sinks`)
- Test: `tests/test_config.py`, `tests/test_cli.py`

**Interfaces:**
- Consumes: `socket_sink` da Task 1.
- Produces:
  - `Config.socket_path: str | None = None`;
  - `build_sinks(cfg: Config) -> tuple[list[AlertSink], list[Callable[[], None]]]` em `cli.py`, que monta os sinks (console, jsonl se `json_path`, socket se `socket_path`) e as funções de parada.

- [ ] **Step 1: Escrever os testes que falham**

```python
# tests/test_config.py
def test_socket_preenche_socket_path(short_dir):      # [alerts] socket = "/x"  -> cfg.socket_path == "/x"
def test_socket_vazio_desliga(short_dir):              # socket = ""             -> cfg.socket_path == "" e len(cli.build_sinks(cfg)[0]) == 1
def test_socket_com_tipo_errado_e_erro(short_dir):     # socket = 1              -> pytest.raises(ConfigError, match="alerts.socket")

# tests/test_cli.py
def test_build_sinks_com_socket_cria_o_arquivo(short_dir, capsys):
    # cfg = Config(socket_path=os.path.join(short_dir, "a.sock")); sinks, stops = cli.build_sinks(cfg)
    # len(sinks) == 2 (console + socket); os.path.exists(...); f"[mandacaru] alertas em tempo real: {p}" no stderr
    # for s in stops: s()  -> o arquivo some

def test_build_sinks_com_socket_impossivel_avisa_e_segue(short_dir, capsys):
    # cfg = Config(socket_path=os.path.join(short_dir, "nao", "a.sock")); sinks, stops = cli.build_sinks(cfg)
    # len(sinks) == 1; "[mandacaru] socket de alertas desligado:" no stderr; sem exceção

def test_build_sinks_sem_socket(short_dir):
    # Config() -> len(sinks) == 1 e stops == []
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `.venv/bin/python -m pytest tests/test_config.py tests/test_cli.py -q`
Expected: os testes novos falham. O de config falha com `chave desconhecida alerts.socket`, e os de cli com `AttributeError: ... 'build_sinks'`.

- [ ] **Step 3: Implementar**

- No `config.py`, acrescentar `"socket": ("socket_path", _str)` em `_SCHEMA["alerts"]` e o campo no `Config`.
- No `cli.py`:
  - `build_sinks` só cria o socket se `cfg.socket_path` for verdadeiro. Com `OSError`, imprime `[mandacaru] socket de alertas desligado: {exc}` e segue sem ele.
  - Sem erro, imprime `[mandacaru] alertas em tempo real: {cfg.socket_path}`.
  - O `cmd_monitor` usa `sinks, stoppers = build_sinks(cfg)` no lugar da montagem atual e soma depois os stoppers dos coletores. Hoje a lista `stoppers` começa com o coletor de processos, e o socket deve ser parado depois dos coletores.
- **Atenção:** o `test_config_de_exemplo_e_valido` (em `test_packaging.py`) continua passando nesta task, porque o `packaging/config.toml` só muda na Task 3.

- [ ] **Step 4: Rodar e ver passar**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check .`
Expected: a suíte inteira passa, os 54 testes que já existiam mais os novos, e o ruff mostra `All checks passed!`.

- [ ] **Step 5: Commit**

```bash
git add src/mandacaru/config.py src/mandacaru/cli.py tests/test_config.py tests/test_cli.py
git commit -m "Config [alerts] socket e monitor publicando alertas no socket"
```

### Task 3: empacotamento, documentação e versão 0.3.0

**Files:**
- Modify: `debian/mandacaru.service`, `debian/control`, `debian/changelog`, `packaging/config.toml`, `src/mandacaru/__init__.py`, `CHANGELOG.md`, `README.md`
- Create: `debian/mandacaru.postinst`
- Test: `tests/test_packaging.py`

**Interfaces:**
- Consumes: a chave `socket` da Task 2.
- Produces: o pacote 0.3.0 que a distro vai consumir, com o grupo `mandacaru` e o `/run/mandacaru/alerts.sock`.

- [ ] **Step 1: Escrever e ajustar os testes que falham**

```python
def test_config_de_exemplo_e_valido():   # o Config esperado ganha socket_path="/run/mandacaru/alerts.sock"

def test_unit_cria_o_diretorio_do_socket():
    unit = (ROOT / "debian" / "mandacaru.service").read_text()
    assert "RuntimeDirectory=mandacaru" in unit and "RuntimeDirectoryMode=0755" in unit

def test_postinst_cria_o_grupo_antes_do_debhelper():
    post = (ROOT / "debian" / "mandacaru.postinst").read_text()
    assert "addgroup --system --quiet mandacaru" in post
    assert post.index("addgroup") < post.index("#DEBHELPER#")   # grupo existe antes de o serviço subir

def test_control_depende_de_adduser():
    assert "adduser" in (ROOT / "debian" / "control").read_text().split("Package: mandacaru", 1)[1]
```

O `test_versao_do_changelog_debian_bate_com_o_pacote` e o `test_nome_no_pypi_e_changelog_da_versao` já cobrem a versão 0.3.0 depois que o `__version__` mudar.

- [ ] **Step 2: Rodar e ver falhar**

Run: `.venv/bin/python -m pytest tests/test_packaging.py -q`
Expected: 4 falhas: a do config de exemplo, a da unit, a do postinst (arquivo inexistente) e a do control.

- [ ] **Step 3: Implementar**

- `packaging/config.toml`, em `[alerts]`, depois de `json`:
  ```
  socket = "/run/mandacaru/alerts.sock"  # alertas em tempo real p/ o grupo mandacaru; "" desliga
  ```
- `debian/mandacaru.service`: `RuntimeDirectory=mandacaru` e `RuntimeDirectoryMode=0755`, logo depois de `LogsDirectoryMode=0750`.
- `debian/mandacaru.postinst`, executável:
  ```sh
  #!/bin/sh
  set -e
  if [ "$1" = configure ] && ! getent group mandacaru >/dev/null; then
      addgroup --system --quiet mandacaru
  fi
  #DEBHELPER#
  exit 0
  ```
- `debian/control`: `Depends:` ganha `adduser`.
- O `__version__` passa a `"0.3.0"`.
- `debian/changelog`: entrada nova no topo, `mandacaru (0.3.0) unstable; urgency=medium`, com os itens:
  - `* Socket de alertas em tempo real em /run/mandacaru/alerts.sock (grupo mandacaru).`
  - `* Grupo de sistema mandacaru criado na instalacao.`

  A assinatura tem a data de hoje no formato RFC 2822, com o mesmo mantenedor.
- `CHANGELOG.md`: `## 0.3.0` no topo, com dois itens. Um descreve o socket com o contrato v1, sem `evidence`, e o outro diz que os membros do grupo `mandacaru` conectam.
- `README.md`:
  - o bloco TOML de "Configuração" ganha a linha `socket`;
  - entra a seção nova `## Alertas em tempo real`, antes de `## Arquitetura`. Ela traz um parágrafo com o caminho, a permissão e o `sudo usermod -aG mandacaru $USER`, a linha de exemplo da spec §3.5, uma frase dizendo que a `evidence` não sai pelo socket e o exemplo `socat - UNIX-CONNECT:/run/mandacaru/alerts.sock`;
  - o diagrama de "Arquitetura" passa a listar `sinks (console | jsonl | socket)`.

- [ ] **Step 4: Rodar e ver passar**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check . && sh -n debian/mandacaru.postinst && test -x debian/mandacaru.postinst`
Expected: a suíte inteira passa, o ruff mostra `All checks passed!` e o `sh -n` e o `test -x` passam em silêncio.

- [ ] **Step 5: Smoke test sem root**

Run, num diretório temporário curto (`mktemp -d /tmp/mcXXXX`):
- um config com `paths = ["<tmp>/vigiado"]`, `ebpf = false`, `json = "<tmp>/a.jsonl"` e `socket = "<tmp>/a.sock"`;
- `.venv/bin/mandacaru --config <cfg> monitor &`;
- `python3 -c` conectando em `<tmp>/a.sock` e imprimindo a primeira linha;
- num outro shell, copiar uma amostra que gera alerta HIGH para `<tmp>/vigiado` (o arquivo EICAR dos testes do CLI serve);
- `kill %1`.

Expected:
- o cliente imprime uma linha `{"v":1,...,"severity":"HIGH"...}` sem `evidence`;
- o stderr do monitor mostra `alertas em tempo real: <tmp>/a.sock` e o aviso de `chown` negado ou de grupo ausente;
- depois do `kill`, o `<tmp>/a.sock` não existe mais.

- [ ] **Step 6: Commit**

```bash
git add debian/ packaging/config.toml src/mandacaru/__init__.py CHANGELOG.md README.md tests/test_packaging.py
git commit -m "Versao 0.3.0: socket de alertas no pacote, grupo mandacaru e docs"
```

**Depois do plano, a cargo do autor:** push do branch, PR com o CI verde (o `deb.yml` gera o `.deb`), merge e push da tag `v0.3.0`. O SHA256 da `.deb` publicada vai para o `mandacaru.lock` da distro, na spec de aviso sonoro.
