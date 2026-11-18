# Quarentena com decisão do usuário — plano de implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Arquivo detectado com severidade alta vai para uma quarentena segura, o usuário decide (confiar / analisar /
manter) e toda decisão fica num log que usuário comum não forja.

**Architecture:** O serviço (`mandacaru monitor`, root) só isola e avisa: `Engine.process` chama `Quarantine.isolate`
nos eventos de arquivo e o alerta sai com `quarantine_id`. As decisões são subcomandos `mandacaru quarentena ...`
executados via `pkexec` por dois auxiliares em `/usr/libexec/mandacaru/`; a análise por hash roda nesses processos
curtos, nunca no serviço. Um timer diário apaga casos vencidos.

**Tech Stack:** Python ≥ 3.10 só com stdlib (`urllib.request`, `socket`, `fcntl`, `json`, `uuid`, `hashlib`), pytest,
systemd, polkit, debhelper.

**Spec:** `docs/superpowers/specs/2026-11-18-quarentena-design.md` — leia antes de cada tarefa; este plano não repete
o porquê.

## Global Constraints

- Sem dependência nova obrigatória (nada em `dependencies` do `pyproject.toml`, nada em `Depends` além de polkit).
- Python ≥ 3.10; Linux apenas.
- Caminhos fixos: quarentena `/var/lib/mandacaru/quarantine/` (root:mandacaru 0750), lista de confiança
  `/var/lib/mandacaru/trusted.json` (0644), log `/var/log/mandacaru/decisions.jsonl` (root:mandacaru 0640).
  Todos como constantes de módulo e **injetáveis** nos construtores para os testes rodarem sem root.
- `<id>.bin` 0600 root; `<id>.json` 0640 root:mandacaru; XOR com chave de 1 byte `0xA5`.
- Padrões: `min_severity = "HIGH"`, `retention_days = 30`, `max_file_mb = 256`, `max_total_mb = 2048`, `cymru = true`.
- O serviço nunca lê comandos de fora e nunca faz requisição de rede.
- Conteúdo de arquivo só sai da máquina com `--enviar`, chave do VirusTotal, TTY e confirmação `[s/N]`.
- Códigos de saída de `mandacaru quarentena`: `0` ok, `1` uso/config, `3` id inexistente ou já resolvido,
  `4` quarentena adulterada.
- Mensagens ao usuário em português sem acento no código (padrão atual do repo), via `print(..., file=sys.stderr)`.
- Commits: autor `VandyckLN <183553227+VandyckLN@users.noreply.github.com>`, **sem** `Co-Authored-By` nem rodapé do
  Claude; mensagem em português no estilo do repo.
- Testes: `.venv/bin/python -m pytest -q` e `.venv/bin/ruff check .` verdes ao fim de cada tarefa.

## Review Focus

1. **Nome de arquivo com bytes inválidos em UTF-8, espaço ou quebra de linha** → isolar, listar, registrar e
   restaurar funcionam e restauram no caminho exato (metadados com `json.dumps(..., ensure_ascii=True)`, que
   preserva surrogates). Teste na Tarefa 3 e na Tarefa 4.
2. **O mesmo arquivo gera `file_create` e `file_write` em sequência** → um caso só; o segundo evento vira
   `nao_isolado/sumiu` sem exceção e sem alerta duplicado com outro id. Teste na Tarefa 6.
3. **Disco cheio no meio da cópia** → original intacto, nenhum `.tmp` sobrando, registro `nao_isolado`. Teste
   (falha injetada no `write`) na Tarefa 3.
4. **Arquivo trocado por symlink entre a detecção e o isolamento** → `O_NOFOLLOW` recusa, nada fora da pasta
   vigiada é movido. Teste na Tarefa 3.
5. **`mandacaru monitor` rodando sem root ou sem `/var/lib/mandacaru`** → o monitor sobe, avisa uma vez que a
   quarentena está desligada e os alertas continuam saindo. Teste na Tarefa 6.

---

### Task 1: Configuração `[quarantine]` e `[analysis]`

**Files:**
- Modify: `src/mandacaru/config.py`
- Modify: `packaging/config.toml`
- Test: `tests/test_config.py`, `tests/test_packaging.py`

**Interfaces:**
- Produces: campos novos em `Config` (frozen dataclass, com estes padrões):
  `quarantine: bool = True`, `quarantine_min_severity: Severity = Severity.HIGH`, `retention_days: int = 30`,
  `max_file_mb: int = 256`, `max_total_mb: int = 2048`, `cymru: bool = True`,
  `virustotal_key: str | None = None`, `malwarebazaar_key: str | None = None`.
- Mapeamento no `_SCHEMA`: `quarantine.enabled → quarantine`, `quarantine.min_severity`, `quarantine.retention_days`,
  `quarantine.max_file_mb`, `quarantine.max_total_mb`, `analysis.cymru`, `analysis.virustotal_key`,
  `analysis.malwarebazaar_key`.
- Novo conversor `_pos_int(value, key) -> int`: aceita só `int` > 0 (e não `bool`).

- [ ] **Step 1: Testes que falham**

```python
def test_secoes_de_quarentena_e_analise(tmp_path):
    cfg = load_config(write(tmp_path, '''
[quarantine]
enabled = false
min_severity = "critical"
retention_days = 7
max_file_mb = 10
max_total_mb = 100
[analysis]
cymru = false
virustotal_key = "vt"
malwarebazaar_key = "mb"
'''))
    assert (cfg.quarantine, cfg.quarantine_min_severity, cfg.retention_days) == (False, Severity.CRITICAL, 7)
    assert (cfg.max_file_mb, cfg.max_total_mb) == (10, 100)
    assert (cfg.cymru, cfg.virustotal_key, cfg.malwarebazaar_key) == (False, "vt", "mb")

def test_padroes_da_quarentena():
    c = Config()
    assert (c.quarantine, c.quarantine_min_severity, c.retention_days, c.max_file_mb, c.max_total_mb, c.cymru) == \
        (True, Severity.HIGH, 30, 256, 2048, True)

@pytest.mark.parametrize("v", ["0", "-1", "true", '"30"', "1.5"])
def test_retention_days_invalido(tmp_path, v):
    with pytest.raises(ConfigError, match="quarantine.retention_days"):
        load_config(write(tmp_path, f"[quarantine]\nretention_days = {v}\n"))

def test_chave_desconhecida_em_analysis(tmp_path):
    with pytest.raises(ConfigError, match="analysis.vt"):
        load_config(write(tmp_path, '[analysis]\nvt = "x"\n'))
```

Em `tests/test_packaging.py::test_config_de_exemplo_e_valido`, o `Config` esperado continua o mesmo (o exemplo usa
os padrões); acrescente `assert "uso NAO comercial" in (ROOT / "packaging" / "config.toml").read_text()`.

- [ ] **Step 2:** `.venv/bin/python -m pytest -q tests/test_config.py tests/test_packaging.py` → FAIL (campos não existem).
- [ ] **Step 3:** Implementar os campos, `_pos_int` e o `_SCHEMA`; em `packaging/config.toml` acrescentar as seções
  exatamente como na seção 9 do spec (`[quarantine]` com os padrões explícitos; `[analysis]` com `cymru = true`, o
  comentário "Team Cymru MHR e gratuito so para uso NAO comercial; em uso por empresa, desligue (false)" e as chaves
  comentadas).
- [ ] **Step 4:** mesmo comando → PASS; suíte inteira verde.
- [ ] **Step 5:** Commit `Config: secoes [quarantine] e [analysis]`.

### Task 2: Log de decisões

**Files:**
- Create: `src/mandacaru/decisions.py`
- Test: `tests/test_decisions.py`

**Interfaces:**
- Produces:
  - `DEFAULT_LOG = "/var/log/mandacaru/decisions.jsonl"`
  - `ACTIONS = {"isolar", "nao_isolado", "ignorado_confiavel", "analisar", "manter", "confiar", "apagar",
    "desconfiar", "expirado", "restauracao_recusada"}`
  - `class DecisionLog: __init__(self, path: str | os.PathLike = DEFAULT_LOG)`;
    `record(self, action: str, *, case_id: str | None = None, sha256: str | None = None, path: str | None = None,
    by: str = "sistema", uid: int | None = None, detail: dict | None = None) -> None`
  - `actor_from_env(env: Mapping[str, str] = os.environ) -> tuple[str, int | None]`: `PKEXEC_UID`, senão `SUDO_UID`,
    resolvido com `pwd.getpwuid` (nome) — uid sem nome vira `str(uid)`; sem nenhum dos dois, `("sistema", None)`.
- Linha gravada: `{"v": 1, "ts", "id", "sha256", "path", "action", "by", "uid", "detail"}` passada por `safe_text`,
  uma por `record`, escrita com `os.open(O_WRONLY|O_APPEND|O_CREAT, 0o640)` + `fcntl.flock(LOCK_EX)` + um único
  `os.write`. Ação fora de `ACTIONS` → `ValueError`.

- [ ] **Step 1: Testes que falham** — `test_grava_uma_linha_json_por_decisao` (campos e `v == 1`),
  `test_acao_desconhecida_e_erro`, `test_caminho_com_utf8_invalido_nao_perde_a_linha`
  (`path="/tmp/\udcff.py"` → linha válida com `�`), `test_dois_processos_escrevendo_nao_misturam_linhas`
  (2 `multiprocessing.Process` × 200 `record` → 400 linhas, todas `json.loads` válidas),
  `test_actor_from_env` (`{"PKEXEC_UID": str(os.getuid())}` → nome do usuário atual; `{}` → `("sistema", None)`;
  `{"SUDO_UID": "4242424"}` sem usuário → `("4242424", 4242424)`), `test_permissao_do_arquivo_novo_e_0640`.
- [ ] **Step 2:** `pytest tests/test_decisions.py` → FAIL (módulo não existe).
- [ ] **Step 3:** Implementar `decisions.py`.
- [ ] **Step 4:** → PASS.
- [ ] **Step 5:** Commit `Log de decisoes da quarentena (JSON Lines com flock)`.

### Task 3: Isolar um arquivo

**Files:**
- Create: `src/mandacaru/quarantine.py`
- Test: `tests/test_quarantine.py`

**Interfaces:**
- Consumes: `DecisionLog` (Task 2), `Alert` (`events.py`).
- Produces:
  - `DEFAULT_DIR = "/var/lib/mandacaru/quarantine"`, `XOR_KEY = 0xA5`, `GROUP = "mandacaru"`
  - `@dataclass class Case`: `id, sha256, size, original_path, uid, gid, mode, mtime, rule, severity, summary,
    quarantined_at, expires_at, state, original_removido, analysis` — `to_json() -> str`
    (`ensure_ascii=True`, `"v": 1`), `@classmethod from_json(text) -> Case`.
  - `@dataclass class IsolateResult: status: str` (`"isolado" | "nao_isolado" | "confiavel"`),
    `case: Case | None = None`, `reason: str | None = None`.
  - `class Quarantine: __init__(self, root=DEFAULT_DIR, log: DecisionLog | None = None,
    trust: TrustList | None = None, retention_days=30, max_file_bytes=256 MiB, max_total_bytes=2 GiB,
    now: Callable[[], float] = time.time)`; `isolate(self, path: str, alert: Alert) -> IsolateResult`;
    `load(self, case_id: str) -> Case` (levanta `CaseNotFound`); `list(self) -> list[Case]` (por `quarantined_at`);
    `used_bytes(self) -> int`.
  - `class CaseNotFound(LookupError)`, `class Tampered(RuntimeError)`; `validate_id(case_id) -> str` (32 hex
    minúsculos, senão `CaseNotFound`).
  - `xor_stream(src, dst, key=XOR_KEY) -> str` (copia em blocos de 1 MiB, devolve sha256 hex do conteúdo **de
    entrada**) — usado também na Task 4.
- `trust` é `None` nesta tarefa (a Task 4 liga). `isolate` segue a seção 2 do spec, na ordem: `O_RDONLY|O_NOFOLLOW`
  → `fstat` (não regular → `nao_isolado/nao_regular`) → limites de tamanho (`tamanho`, `quarentena_cheia`) → cópia
  XOR para `<id>.bin.tmp` 0600 + `fsync` → `<id>.json` via tmp + `rename` → `rename` do `.bin` → `fsync` do diretório
  → `unlink` do original. `chown(json, -1, gid do grupo mandacaru)` só se o grupo existir e `os.geteuid() == 0`.
  Toda saída grava uma linha no log (`isolar` / `nao_isolado` com `detail.motivo`). Nunca levanta exceção para o
  chamador: erro vira `nao_isolado` com o `strerror`.

- [ ] **Step 1: Testes que falham** (fixture `q = Quarantine(tmp_path/"q", DecisionLog(tmp_path/"d.jsonl"),
  now=lambda: 1000.0)`; alerta de exemplo `Alert("yara.X", Severity.HIGH, "s", {"path": str(f)})`):
  - `test_isola_embaralha_e_remove_o_original`: status `isolado`; original não existe; `.bin` != conteúdo e
    `bytes(b ^ 0xA5 for b in bin) == conteudo`; modo do `.bin` `0o600`; `case.sha256 == sha256(conteudo)`;
    `case.expires_at == 1000.0 + 30*86400`; log tem `action == "isolar"` com o mesmo id.
  - `test_metadados_preservam_nome_com_bytes_invalidos` (arquivo `b"a\xff b\n.py"` via `os.fsdecode`):
    `q.load(id).original_path == caminho`.
  - `test_symlink_nao_e_seguido`: `link → alvo`; status `nao_isolado`; alvo e link intactos.
  - `test_falha_no_meio_da_copia_deixa_o_original` (monkeypatch `os.write` dentro de `quarantine` para levantar
    `OSError(errno.ENOSPC, ...)` na 2ª chamada; arquivo de 3 MiB): status `nao_isolado`, original intacto,
    `list((tmp_path/"q").iterdir()) == []`.
  - `test_arquivo_grande_demais_nao_e_isolado` (`max_file_bytes=10`) → `nao_isolado`, `reason == "tamanho"`.
  - `test_quarentena_cheia` (`max_total_bytes` menor que soma de dois arquivos) → 2º `quarentena_cheia`.
  - `test_arquivo_que_sumiu` → `nao_isolado`, `reason == "sumiu"`.
  - `test_falha_no_unlink_mantem_o_caso` (monkeypatch `os.unlink` do original) → `isolado`,
    `case.original_removido is False`.
  - `test_validate_id` (`"../x"`, `"A"*32`, `"a"*31` → `CaseNotFound`).
- [ ] **Step 2:** `pytest tests/test_quarantine.py` → FAIL.
- [ ] **Step 3:** Implementar.
- [ ] **Step 4:** → PASS.
- [ ] **Step 5:** Commit `Quarentena: isolar arquivo sem risco de perda`.

### Task 4: Lista de confiança e restauração ("Confio")

**Files:**
- Modify: `src/mandacaru/quarantine.py`
- Test: `tests/test_quarantine.py`

**Interfaces:**
- Produces:
  - `DEFAULT_TRUST = "/var/lib/mandacaru/trusted.json"`
  - `class TrustList: __init__(self, path=DEFAULT_TRUST, recheck_seconds=5.0, now=time.monotonic)`;
    `contains(self, sha256: str) -> bool` (relê o arquivo se o mtime mudou, checando no máximo a cada
    `recheck_seconds`; arquivo ausente = lista vazia); `add(self, sha256, original_path, by) -> None`;
    `remove(self, sha256) -> bool`. Escrita atômica (tmp + `rename`, 0644).
  - `Quarantine.isolate`: se `trust.contains(sha)` → `IsolateResult("confiavel")`, nada é movido, log
    `ignorado_confiavel`. O hash é calculado lendo o arquivo antes da cópia (mesmo fd).
  - `Quarantine.restore(self, case_id: str, by: str, uid: int | None) -> str` (devolve o caminho onde o arquivo
    ficou). Segue a seção 6 do spec: hash confere (senão `Tampered` + log `restauracao_recusada`); **primeiro**
    `trust.add`, depois tmp `O_EXCL` no diretório original, `fchmod`/`utime` (e `fchown` só como root),
    `os.link(tmp, destino)`; `FileExistsError` → destino `<nome>.restaurado-<AAAA-MM-DD>`; `unlink(tmp)`; apaga
    `.bin`/`.json`; log `confiar` com `detail.restaurado_em`. Diretório original ausente → `FileNotFoundError` com
    mensagem, caso continua isolado.

- [ ] **Step 1: Testes que falham:**
  - `test_restaurar_devolve_conteudo_modo_e_mtime` (arquivo 0o640 com mtime fixo) — e o caso some de `q.list()`.
  - `test_restaurar_nao_sobrescreve`: cria outro arquivo no caminho original antes → original novo intacto,
    restaurado em `x.py.restaurado-1970-01-01` (use `now`), retorno aponta para ele.
  - `test_restaurar_bin_adulterado_e_recusado`: altera 1 byte do `.bin` → `Tampered`; log `restauracao_recusada`;
    caso continua em `q.list()`.
  - `test_restaurar_poe_hash_na_lista_e_nao_isola_de_novo`: depois de restaurar, `q.isolate(caminho, alerta)`
    → `status == "confiavel"`, arquivo no lugar.
  - `test_restaurar_nome_com_bytes_invalidos` (mesmo nome da Task 3).
  - `test_trustlist_rele_quando_outro_processo_altera` (duas instâncias no mesmo arquivo; `recheck_seconds=0`).
  - `test_restaurar_id_inexistente` → `CaseNotFound`.
- [ ] **Step 2:** → FAIL. **Step 3:** Implementar. **Step 4:** → PASS.
- [ ] **Step 5:** Commit `Quarentena: lista de confianca e restauracao`.

### Task 5: Manter, apagar e expirar

**Files:**
- Modify: `src/mandacaru/quarantine.py`
- Test: `tests/test_quarantine.py`

**Interfaces:**
- Produces: `Quarantine.keep(case_id, by, uid) -> Case` (só registra `manter`; não muda `expires_at`);
  `Quarantine.delete(case_id, by, uid, action="apagar") -> None` (apaga `.bin` e `.json`, registra);
  `Quarantine.purge_expired(self) -> int` (apaga os com `expires_at <= now()`, registra `expirado` com
  `by="sistema"`, devolve quantos); `Quarantine.set_analysis(case_id, analysis: dict) -> Case` (regrava o `.json`
  de forma atômica). Arquivos órfãos (`.bin` sem `.json` ou `*.tmp` com mais de 1 h) também são apagados pelo
  `purge_expired`, sem linha de log.

- [ ] **Step 1: Testes que falham:** `test_manter_registra_e_mantem_prazo`, `test_apagar_remove_os_dois_arquivos`,
  `test_purge_apaga_so_os_vencidos` (dois casos, `now` avançado 30 dias + 1 s só passa um),
  `test_purge_limpa_orfaos`, `test_set_analysis_persiste`, `test_list_ignora_json_corrompido` (um `.json` inválido
  não derruba `list()`; o caso é pulado).
- [ ] **Step 2:** → FAIL. **Step 3:** Implementar. **Step 4:** → PASS.
- [ ] **Step 5:** Commit `Quarentena: manter, apagar e expirar em 30 dias`.

### Task 6: Motor isola e o alerta sempre chega

**Files:**
- Modify: `src/mandacaru/events.py`, `src/mandacaru/engine.py`, `src/mandacaru/alert_socket.py`, `src/mandacaru/cli.py`
- Test: `tests/test_engine_quarantine.py`, `tests/test_socket_sink.py`, `tests/test_cli.py`

**Interfaces:**
- Consumes: `Quarantine`, `TrustList`, `DecisionLog` (Tasks 2–5), campos de `Config` (Task 1).
- Produces:
  - `Alert` ganha `quarantine_id: str | None = None` (entra no `to_json`).
  - `Engine.__init__(..., quarantine: Quarantine | None = None, quarantine_min_severity: Severity = Severity.HIGH,
    watch_paths: Sequence[str] = ())`.
  - Em `Engine.process`, **só no ramo de evento de arquivo** e só para alertas do scanner com
    `severity >= quarantine_min_severity` cujo `evidence["path"]` esteja dentro de algum `watch_paths`
    (comparação por `Path.resolve(strict=False)` + `is_relative_to`): chama `isolate` uma vez por caminho
    (vários alertas do mesmo arquivo compartilham o resultado).
    - `isolado` → `alert.quarantine_id = case.id`, `evidence["quarantine_id"]`; o alerta é emitido **sem** passar
      pelo dedup (`emit(alert, force=True)`).
    - `confiavel` → `alert.severity = Severity.INFO`, `evidence["trusted"] = True`.
    - `nao_isolado` → `evidence["quarantine"] = "nao_isolado: <reason>"` e o `summary` ganha
      `" (NAO isolado: <reason>)"`.
  - `Engine.emit(self, alert, force: bool = False) -> bool`.
  - `console_sink` e `socket_sink` deixam passar alerta com `quarantine_id` mesmo abaixo de `min_sev`.
    `alert_line` inclui `"quarantine_id"` só quando houver.
  - `cli.build_quarantine(cfg) -> Quarantine | None`: `None` se `cfg.quarantine` é falso; se o diretório não existe
    ou não é gravável (`os.access(W_OK)`), avisa uma vez em stderr
    `"[mandacaru] quarentena desligada: <motivo>"` e devolve `None`. `cmd_monitor` passa a quarentena, o
    `quarantine_min_severity` e os `paths` resolvidos para o `Engine`.

- [ ] **Step 1: Testes que falham** (`Engine` com sink que coleta em lista, `Quarantine` em `tmp_path`, pasta
  vigiada `tmp_path/"w"`, um arquivo que bate na regra YARA de teste já usada em `tests/test_detectors.py`):
  - `test_arquivo_malicioso_em_pasta_vigiada_e_isolado` → alerta com `quarantine_id`, arquivo sumiu.
  - `test_create_e_write_seguidos_geram_um_caso` → dois eventos, `len(q.list()) == 1`, um alerta com id,
    nenhuma exceção.
  - `test_arquivo_fora_da_pasta_vigiada_so_alerta`.
  - `test_process_start_nunca_isola` (evento `process_start` com `cmdline=["python", caminho]`).
  - `test_medium_nao_isola_com_padrao`.
  - `test_alerta_de_caso_novo_ignora_dedup` (dois arquivos iguais em sequência no mesmo caminho → dois alertas,
    dois ids).
  - `test_hash_confiavel_vira_info_sem_isolar`.
  - Em `tests/test_socket_sink.py`: `test_alerta_com_quarantine_id_passa_pelo_filtro_de_severidade`
    (`min_sev=CRITICAL`, alerta HIGH com id → chega com `"quarantine_id"`); `test_linha_sem_quarantine_id_nao_tem_o_campo`.
  - Em `tests/test_cli.py`: `test_quarentena_sem_diretorio_desliga_e_avisa` (`build_quarantine` com dir inexistente
    → `None`, aviso uma vez); `test_quarentena_desligada_no_config`.
- [ ] **Step 2:** → FAIL. **Step 3:** Implementar. **Step 4:** suíte inteira → PASS.
- [ ] **Step 5:** Commit `Monitor isola arquivos detectados e avisa com quarantine_id`.

### Task 7: Análise por hash

**Files:**
- Create: `src/mandacaru/analysis.py`
- Test: `tests/test_analysis.py`

**Interfaces:**
- Consumes: `Config` (Task 1).
- Produces:
  - `Resolver = Callable[[str], list[str]]` (nome → IPs v4; padrão via `socket.getaddrinfo(name, None, AF_INET)`;
    `socket.gaierror` = sem registro). `Http = Callable[[urllib.request.Request, float], tuple[int, bytes]]`
    (padrão via `urlopen`, devolvendo `(status, corpo)`; `HTTPError` vira o status dele).
  - `@dataclass SourceResult: status: str` (`"achou" | "nao_achou" | "erro" | "desligada"`), `detail: str = ""`.
  - `@dataclass AnalysisResult: case_id: str, verdict: str, sources: dict[str, SourceResult], summary: str` —
    `to_dict()` no formato do contrato do spec (`{"v": 1, "id", "verdict", "sources", "summary"}`).
  - `analyze(case_id: str, sha256: str, cfg: Config, resolver: Resolver = ..., http: Http = ..., timeout=10.0)
    -> AnalysisResult`.
  - `upload_virustotal(data: bytes, filename: str, key: str, http: Http = ..., timeout=60.0) -> str` (devolve o id
    da análise do VirusTotal). Recusa `len(data) > 32 * 1024 * 1024` com `ValueError`.
- Fontes, nomes fixos das chaves em `sources`: `"cymru"`, `"circl"`, `"malwarebazaar"`, `"virustotal"`.
  - `cymru` (se `cfg.cymru`): nome da consulta conforme `https://hash.cymru.com/docs_dns` (SHA-256 em dois blocos de
    32 hex + `.hash.cymru.com`; confira o formato exato na doc e escreva-o num comentário com o link). Algum IP
    `127.0.0.2` → `achou`.
  - `circl`: `GET https://hashlookup.circl.lu/lookup/sha256/<h>`, `Accept: application/json`; 200 → `achou`
    (detail = `FileName`/`source` do JSON, se houver); 404 → `nao_achou`.
  - `malwarebazaar` (se chave): `POST https://mb-api.abuse.ch/api/v1/`, corpo `query=get_info&hash=<h>`, header
    `Auth-Key`; `query_status == "ok"` → `achou` (detail = `signature`); `"hash_not_found"` → `nao_achou`.
  - `virustotal` (se chave): `GET https://www.virustotal.com/api/v3/files/<h>`, header `x-apikey`; 200 → `achou`
    se `malicious > 0` (detail `"54/70 detectam"` = malicious / soma de `last_analysis_stats`), senão `nao_achou`;
    404 → `nao_achou`.
  - Sem chave / `cymru=false` → `desligada`. Exceção, timeout, status inesperado → `erro` com mensagem curta.
- Veredito: `malicioso` se cymru, malwarebazaar ou virustotal `achou`; senão `legitimo_conhecido` se circl `achou`;
  senão `desconhecido`. `summary`: uma linha em português (ex.: `"Malicioso: VirusTotal 54/70 detectam;
  Team Cymru conhece"`; `"Desconhecido: nenhuma fonte conhece este arquivo"`; com todas em `erro`:
  `"Desconhecido: analise limitada, sem resposta das fontes"`).
- User-Agent genérico: `mandacaru/<versao>`.

- [ ] **Step 1: Testes que falham** (resolver e http falsos; nenhum teste acessa a rede):
  `test_cymru_achou_e_malicioso`, `test_so_circl_achou_e_legitimo_conhecido`, `test_ninguem_achou_e_desconhecido`,
  `test_malware_vence_circl`, `test_cymru_desligado_nem_consulta` (resolver que falha o teste se chamado),
  `test_chaves_ausentes_marcam_desligada`, `test_fonte_com_timeout_nao_impede_as_outras`,
  `test_todas_com_erro_avisa_analise_limitada`, `test_virustotal_resume_deteccoes` (`{"malicious": 54, ...}` somando
  70 → `"54/70 detectam"`), `test_nome_da_consulta_cymru` (o nome que o resolver recebe),
  `test_headers_de_autenticacao` (`Auth-Key`, `x-apikey` nas requisições), `test_upload_recusa_mais_de_32mb`,
  `test_to_dict_segue_o_contrato` (chaves exatas e `v == 1`).
- [ ] **Step 2:** → FAIL. **Step 3:** Implementar. **Step 4:** → PASS.
- [ ] **Step 5:** Commit `Analise por hash: Team Cymru, CIRCL, MalwareBazaar e VirusTotal`.

### Task 8: Subcomandos `mandacaru quarentena`

**Files:**
- Create: `src/mandacaru/quarantine_cli.py`
- Modify: `src/mandacaru/cli.py` (registra o subparser)
- Test: `tests/test_quarantine_cli.py`

**Interfaces:**
- Consumes: Tasks 1–7.
- Produces: `add_parser(sub) -> None` (registra `quarentena` com `listar`, `analisar <id> [--json] [--enviar]`,
  `manter <id>`, `confiar <id>`, `apagar <id>`, `desconfiar <sha256>`, `limpar`);
  `cmd_quarentena(args, *, quarantine: Quarantine | None = None, euid: int | None = None, env=os.environ,
  analyzer=analysis.analyze, stdin_isatty=sys.stdin.isatty, input_fn=input) -> int` (parâmetros com padrão para os
  testes injetarem; produção usa os padrões e `Quarantine` com os caminhos fixos e `cfg` do `--config`).
- Regras:
  - Todos menos `listar` exigem `euid == 0`; senão saída 1 com
    `"mandacaru: erro: este comando precisa de root (use sudo ou o botao do popup)"`.
  - `by, uid = actor_from_env(env)` em toda decisão.
  - `analisar`: lê o caso, `analyze(...)`, `set_analysis`, grava log `analisar` com `detail = result.to_dict()`;
    `--json` imprime `json.dumps(result.to_dict(), ensure_ascii=False)` numa linha em stdout; sem `--json`, texto com
    o summary, uma linha por fonte e, só com TTY, `"Confiar: sudo mandacaru quarentena confiar <id> | Manter:
    sudo mandacaru quarentena manter <id>"`.
    `--enviar`: só se `cfg.virustotal_key`, veredito `desconhecido` e TTY; pergunta exatamente
    `"O arquivo ficara acessivel a pesquisadores e empresas parceiras do VirusTotal. Enviar? [s/N] "`; só `s`/`S`
    envia (desembaralha em memória, `upload_virustotal`) e registra `detail.enviado = True`; qualquer condição
    faltando → saída 1 com o motivo.
  - Exceções → códigos: `CaseNotFound` → 3, `Tampered` → 4, `FileNotFoundError` na restauração → 1.
  - `limpar` imprime `"<n> caso(s) expirado(s) apagado(s)"`.

- [ ] **Step 1: Testes que falham** (`euid=0` injetado, `Quarantine` em `tmp_path`, analisador falso):
  `test_listar_mostra_casos_sem_root` (cada linha tem id, data, caminho original, regra, dias até expirar e o
  veredito da análise ou `-`), `test_decisao_sem_root_sai_com_1`, `test_confiar_restaura_e_registra_quem`
  (`env={"PKEXEC_UID": str(os.getuid())}` → log `by` = usuário atual), `test_id_inexistente_sai_com_3`,
  `test_id_malformado_sai_com_3`, `test_bin_adulterado_sai_com_4`, `test_analisar_json_segue_contrato`
  (stdout = 1 linha JSON com `verdict`), `test_analisar_sem_tty_nao_pergunta` (`input_fn` que falha se chamado),
  `test_enviar_exige_chave_tty_e_confirmacao` (sem chave → 1; com chave e resposta `""` → não envia;
  `"s"` → envia, log `enviado`), `test_limpar_apaga_vencidos`, `test_desconfiar_tira_da_lista`.
- [ ] **Step 2:** → FAIL. **Step 3:** Implementar. **Step 4:** → PASS.
- [ ] **Step 5:** Commit `CLI: mandacaru quarentena (listar, analisar, manter, confiar, apagar, limpar)`.

### Task 9: Empacotamento (systemd, polkit, timer, logrotate) e versão 0.4.0

**Files:**
- Create: `packaging/libexec/quarantine-decide`, `packaging/libexec/quarantine-release` (sh, 0755),
  `packaging/polkit/io.github.vandyckln.mandacaru.policy`, `packaging/polkit/50-mandacaru.rules`,
  `debian/mandacaru.mandacaru-quarantine-clean.service`, `debian/mandacaru.mandacaru-quarantine-clean.timer`
- Modify: `debian/mandacaru.service`, `debian/mandacaru.install`, `debian/mandacaru.logrotate`, `debian/control`,
  `debian/rules` (se preciso para instalar o timer: `dh_installsystemd --name=mandacaru-quarantine-clean`),
  `debian/changelog`, `src/mandacaru/__init__.py`, `CHANGELOG.md`, `README.md`
- Test: `tests/test_packaging.py`

**Interfaces / valores fixos:**
- Auxiliares: `quarantine-decide` aceita só `analisar|manter` (mais `--json` para `analisar`); `quarantine-release`
  só `confiar|apagar`; ambos validam o id com `case "$2" in *[!0-9a-f]*|"") exit 3` e comprimento 32, e fazem
  `exec /usr/bin/mandacaru --config /etc/mandacaru/config.toml quarentena "$@"`. Qualquer outra coisa → saída 1.
- Policy: ações `io.github.vandyckln.mandacaru.decide` e `io.github.vandyckln.mandacaru.release`, com
  `org.freedesktop.policykit.exec.path` apontando para cada auxiliar; `release`: `auth_admin` em
  `allow_any/allow_inactive/allow_active`; `decide`: `auth_admin` (a regra libera o grupo).
- Regra JS: `action.id == "io.github.vandyckln.mandacaru.decide" && subject.active && subject.local &&
  subject.isInGroup("mandacaru")` → `polkit.Result.YES`.
- `mandacaru.service`: `StateDirectory=mandacaru` + `StateDirectoryMode=0750`; `ReadWritePaths=/home` (mantém
  `ProtectHome=read-only` para o resto); `ExecStartPre=+/bin/sh -c 'install -d -m 0750 -g mandacaru
  /var/lib/mandacaru/quarantine'` (ou equivalente que crie o subdiretório com o grupo).
- Timer: `OnCalendar=daily`, `Persistent=true`; service `Type=oneshot`,
  `ExecStart=/usr/bin/mandacaru --config /etc/mandacaru/config.toml quarentena limpar`.
- Logrotate: entrada própria para `/var/log/mandacaru/decisions.jsonl` com `rotate 52`, `weekly`, `compress`,
  `copytruncate`, e a entrada atual troca `*.jsonl` por `alerts.jsonl` (para não pegar o arquivo duas vezes).
- `debian/control`: `Depends` ganha `polkitd | policykit-1`; config instalado como 0640 (`debian/rules` com
  `execute_after_dh_fixperms: chmod 0640 debian/mandacaru/etc/mandacaru/config.toml`).
- Versão `0.4.0` em `__init__.py`, `debian/changelog` e `CHANGELOG.md` (entrada descrevendo a quarentena).
- README: seção "Quarentena" (o que é isolado, as três escolhas, `mandacaru quarentena ...`, aviso de que o Team
  Cymru é só para uso não comercial e `analysis.cymru = false`); a linha de status deixa de dizer "não remove nada".

- [ ] **Step 1: Testes que falham** em `tests/test_packaging.py`: `test_service_tem_state_directory_e_escrita_em_home`,
  `test_timer_de_limpeza_diario_persistente`, `test_policy_release_exige_admin` (parse XML com
  `xml.etree.ElementTree`: os três `allow_*` == `auth_admin` na ação release), `test_regra_libera_so_decide_para_o_grupo`
  (texto contém `isInGroup("mandacaru")` e o id `decide`, não o `release`),
  `test_auxiliares_aceitam_so_seus_subcomandos` (os scripts usam `${MANDACARU_BIN:-/usr/bin/mandacaru}`; o teste
  roda com `MANDACARU_BIN=echo`: `release manter <id>` → 1, `decide confiar <id>` → 1, id inválido → 3,
  `decide analisar <id válido> --json` imprime os argumentos repassados; `pkexec` limpa o ambiente, então a
  variável não vaza em produção), `test_logrotate_guarda_decisoes_um_ano`,
  `test_install_leva_polkit_e_auxiliares`, `test_depende_de_polkit`.
- [ ] **Step 2:** → FAIL. **Step 3:** Criar/alterar os arquivos. **Step 4:** suíte inteira + `ruff` → PASS.
- [ ] **Step 5: Build do .deb** como o CI faz (`.github/workflows/deb.yml`), conferindo com `dpkg -c` que entram
  `/usr/libexec/mandacaru/quarantine-{decide,release}`, `/usr/share/polkit-1/actions/...policy`,
  `/usr/share/polkit-1/rules.d/50-mandacaru.rules` e o timer. Se não houver ambiente para buildar, registre isso e
  deixe para o CI do PR.
- [ ] **Step 6:** Commit `Empacotamento da quarentena: polkit, auxiliares, timer e logrotate (0.4.0)`.

### Task 10: Verificação ponta a ponta (manual, como root, numa VM ou na máquina do usuário)

Sem código novo; roteiro para rodar antes do PR e anotar o resultado no PR:

- [ ] Instalar o `.deb`; `systemctl status mandacaru` ativo; `ls -ld /var/lib/mandacaru/quarantine` → `drwxr-x--- root mandacaru`.
- [ ] Criar em `~/Downloads` um arquivo que bata numa regra HIGH (o mesmo usado nos testes) → some da pasta;
  `nc -U /run/mandacaru/alerts.sock` mostra a linha com `quarantine_id`; `mandacaru quarentena listar` mostra o caso.
- [ ] `pkexec /usr/libexec/mandacaru/quarantine-decide analisar <id> --json` sem senha (usuário no grupo) → JSON com
  `verdict`.
- [ ] `pkexec /usr/libexec/mandacaru/quarantine-release confiar <id>` → pede senha; arquivo volta; criar/alterar de
  novo não gera popup.
- [ ] `tail /var/log/mandacaru/decisions.jsonl` → `isolar`, `analisar`, `confiar` com `by` = seu usuário;
  `echo x >> /var/log/mandacaru/decisions.jsonl` como usuário comum → permissão negada.
- [ ] `systemctl list-timers mandacaru-quarantine-clean.timer` agendado.
