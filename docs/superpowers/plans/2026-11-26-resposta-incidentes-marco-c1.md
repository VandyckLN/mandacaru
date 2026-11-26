# Resposta a incidentes — Marco (c.1): motor de usuário (sem Qt) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Entregar em Python puro o motor que o painel **Resposta a incidente** (c.2, Antigravity) vai usar: registro `incidents/<id>.json`, encerramento de processos do usuário, remoção/restauração de persistência de usuário, checklist de credenciais e exportação de relatório HTML/JSON sanitizada.

**Architecture:** Seis módulos `windows/src/mandacaru_win/incident*.py` sem nenhuma importação de Qt. Cada ação do sistema operacional passa por um *backend* injetável (processos, registro `HKCU`, executor de `schtasks`, pasta Inicializar), com implementação real para Windows e falsos nos testes. A fachada `Resposta` é a única porta para o c.2: toda ação passa por ela e fica registrada no incidente **antes** de mexer no sistema (o backup do Desfazer nunca se perde num travamento).

**Tech Stack:** Python 3.10–3.13 (biblioteca padrão: `ctypes`, `winreg`, `subprocess`, `csv`, `html`, `json`, `base64`), pytest, ruff. Nenhuma dependência nova.

**Spec:** [docs/superpowers/specs/2026-11-26-resposta-a-incidentes-design.md](../specs/2026-11-26-resposta-a-incidentes-design.md) — seções 2 (cadeia de ações, linhas de usuário), 4 (persistência na v1), 5 (checklist), 6 (registro e exportação) e a linha **Marco (c) → c.1** da tabela de divisão de trabalho.

## Global Constraints

- Fronteira de arquivos: só `windows/src/mandacaru_win/incident*.py`, `windows/tests/test_incident*.py` e este plano. **Não tocar** em `app.py`, `theme.py`, `quarantine.py` (marco b, Antigravity) nem em `incident_ui.py` (c.2).
- Nenhum módulo `incident*.py` importa `PySide6`, `mandacaru_win.worker` ou `mandacaru_win.app` (verificado por teste).
- A janela nunca roda elevada: c.1 só faz ações de usuário. Tarefas agendadas de outro usuário/sistema são detectadas, marcadas `exige_servico=True` e nunca removidas aqui.
- Registro: `<dados>/incidents/<id>.json`, `id` = 32 hex (`uuid4().hex`), gravação atômica com `fsync` via `store._atomic_write_json`.
- Persistência só **associada ao incidente** (menciona caminho/pasta do incidente ou tem o SHA-256 dele); nunca lista programas aleatórios do usuário.
- O Mandacaru nunca lê conteúdo de `.env`, chaves privadas ou cookies; a checklist só orienta.
- Links de credenciais: tabela fixa no código, só `https://` e hosts da lista auditada.
- Exportação: sanitização **ligada por padrão** (`ocultar=True`); backups do Desfazer nunca saem no relatório; HTML sem `<script>`, sem recurso externo e com CSP `default-src 'none'; style-src 'unsafe-inline'`.
- Código, comentários, mensagens e docs em pt-BR com acentos.
- Testes sem rede e sem administrador; os que tocam o Windows real usam `@pytest.mark.skipif(sys.platform != "win32", ...)` e rodam no CI `windows.yml`.
- Ao fim de cada tarefa: `cd windows && pytest -q` verde e `ruff check windows` limpo. Ao fim do marco: `mandacaru dev . --sem-rede` sai com `0`.
- Commits sem linha `Co-Authored-By` (regra do dono).

## Review Focus

1. **PID reaproveitado:** o PID do achado agora pertence a outro programa, ou um "filho" listado é mais antigo que o pai (órfão de um processo anterior com o mesmo PID) → nada de outro programa é encerrado (Tarefa 2).
2. **Entrada mudou entre detectar e remover** (valor do `Run` trocado, arquivo da Inicializar regravado) → remoção recusada, nada apagado (Tarefa 3).
3. **Desfazer sobre algo que já voltou ou foi recriado** (valor com o mesmo nome, arquivo com o mesmo nome) → não sobrescreve; mesmo valor idêntico conta como restaurado (Tarefas 3 e 4).
4. **Backup adulterado no JSON** (chave fora de `Run`/`RunOnce`, nome de arquivo com `..\`, nome de tarefa com aspas) → restauração recusada (Tarefas 3 e 4).
5. **Nome de usuário curto ou comum** (`dev`, `agente`) na sanitização → não corrompe nomes de regra, SHA-256 nem técnicas MITRE (Tarefa 6).

## API para o c.2 (resumo)

```python
store = IncidentStore(data_dir() / "incidents")
inc = store.criar(origem="projeto", ameaca="projeto", achados=[...], pasta=r"C:\proj")
r = Resposta(store, inc)                       # backends reais por padrão
r.encerrar_processo(pid, exe, sha256)          # -> Acao
r.detectar_persistencia()                      # -> list[Entrada]
r.remover_persistencia(entrada)                # -> Acao (com backup)
r.desfazer(indice)                             # -> Acao
r.marcar_credencial("ssh", True)
montar_checklist(inc.ameaca)                   # -> list[ItemCredencial]
exportar_html(inc) / exportar_json(inc)        # ocultar=True por padrão
salvar_relatorio(destino, texto)
```

---

### Task 1: Registro de incidentes (`incident.py`)

**Files:** Create `windows/src/mandacaru_win/incident.py`; Test `windows/tests/test_incident.py`.

**Interfaces — Produces:**
- `class IncidentError(Exception)`
- `ORIGENS = ("varredura", "projeto", "atualizacoes")`, `AMEACAS = ("malware", "projeto", "vulnerabilidade")`, `FASES = ("conter", "neutralizar", "recuperar")`, `RESULTADOS = ("em_andamento", "concluida", "parcial", "falhou")`
- `agora() -> str` (ISO local com fuso, segundos); `sha256_arquivo(caminho: Path) -> str | None` (sem seguir link, `None` se ilegível ou não regular).
- `@dataclass class Acao: tipo: str; fase: str; modo: str ("automatica"|"guiada"); resultado: str; detalhe: str; alvo: dict; data: str; backup: dict | None = None; desfeita: bool = False`
- `@dataclass class Incidente: id: str; criado: str; origem: str; ameaca: str; achados: list[dict]; pasta: str | None = None; acoes: list[Acao]; credenciais: dict[str, bool]; versao: int = 1` — cada achado é `{"regra", "severidade", "caminho", "sha256"?, "mitre"?}`.
- `class IncidentStore(base: Path)`: `criar(*, origem, ameaca, achados, pasta=None) -> Incidente`; `carregar(id) -> Incidente`; `salvar(inc) -> None`; `listar() -> list[Incidente]` (mais novo primeiro, pula corrompidos); `registrar(inc, acao) -> int` (acrescenta, salva, devolve o índice).

- [ ] **Step 1: Testes que falham:** `test_criar_grava_json_atomico` (arquivo `base/<id>.json` existe, `id` casa `[0-9a-f]{32}`, sem `.tmp` sobrando, `carregar(id) == inc`); `test_origem_ou_ameaca_invalida` (`IncidentError`); `test_id_invalido_nao_vira_caminho` (`carregar("../x")` → `IncidentError`); `test_registrar_acrescenta_e_persiste` (índice 0 e 1, recarregado tem as duas ações com `backup` preservado); `test_corrompido_nao_derruba_listar` (um JSON quebrado e um com `acoes` de tipo errado: `listar()` devolve só o válido; `carregar` do quebrado → `IncidentError("O registro do incidente está corrompido.")`); `test_sha256_arquivo_nao_segue_link` (pular se `os.symlink` falhar).
- [ ] **Step 2: Run** `cd windows && pytest -q tests/test_incident.py` → FAIL (`ModuleNotFoundError`).
- [ ] **Step 3: Implementar** com validação de tipos ao carregar (`_de_dict`) e `store._atomic_write_json` para gravar.
- [ ] **Step 4: Run** `pytest -q tests/test_incident.py && ruff check .` → PASS.
- [ ] **Step 5: Commit** `feat(windows): registro de incidentes em incidents/<id>.json`.

---

### Task 2: Encerrar processos do usuário (`incident_proc.py`)

**Interfaces — Consumes:** `sha256_arquivo`. **Produces:**
- `@dataclass(frozen=True) class ProcessoInfo: pid: int; ppid: int; exe: str | None; criado: float | None`
- `class Processos(Protocol)`: `listar() -> list[ProcessoInfo]`; `info(pid) -> ProcessoInfo | None`; `encerrar(pid) -> None` (levanta `OSError`).
- `class ProcessosWindows` (ctypes: `CreateToolhelp32Snapshot`/`Process32FirstW`/`NextW`, `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `QueryFullProcessImageNameW` + `GetProcessTimes`, `OpenProcess(PROCESS_TERMINATE)` + `TerminateProcess`).
- `@dataclass class ResultadoEncerrar: encerrados: list[int]; falhas: list[tuple[int, str]]; recusa: str | None`
- `encerrar_arvore(processos, pid, exe_esperado, sha256, *, hash_fn=sha256_arquivo, proprio_pid=os.getpid()) -> ResultadoEncerrar`

Regras, nesta ordem (a primeira que falhar vira `recusa` e nada é encerrado):
`pid <= 4` ou `pid == proprio_pid` → "Processo do sistema ou do próprio Mandacaru: não será encerrado."; `info is None` → "O processo já terminou."; caminho diferente (`os.path.normcase`) → "O número do processo agora pertence a outro programa; nada foi encerrado."; SHA-256 diferente → "O executável mudou desde a detecção; nada foi encerrado.". Descendentes por `ppid` (busca em largura, sem repetir) só se `filho.criado` e `pai.criado` são conhecidos e `filho.criado >= pai.criado`. Encerra o alvo primeiro (não deixa recriar filhos) e depois os descendentes; `OSError` vira falha com a mensagem.

- [ ] **Step 1: Testes que falham** com um `ProcessosFalsos` em memória: `test_encerra_alvo_e_descendentes` (árvore 100→101→102 e 200 sem relação: encerrados `[100, 101, 102]`, 200 vivo); `test_recusa_pid_reaproveitado`; `test_recusa_exe_alterado`; `test_recusa_sistema_e_proprio` (pids 0, 4 e `proprio_pid`); `test_orfao_mais_antigo_nao_e_filho` (ppid=100 mas `criado` anterior ao do 100 → vivo); `test_ciclo_de_ppid_termina`; `test_falha_de_um_filho_nao_para_os_outros`; `test_processos_windows_reais` (só Windows: inicia `sys.executable -c "import time; time.sleep(60)"`, `encerrar_arvore` com o `sha256_arquivo(sys.executable)` → encerrado e `proc.wait(10)` volta).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implementar.** **Step 4: Run** → PASS + ruff.
- [ ] **Step 5: Commit** `feat(windows): encerrar processo do usuário conferindo caminho e SHA-256`.

---

### Task 3: Persistência — `Run`/`RunOnce` do `HKCU` e pasta Inicializar (`incident_persist.py`)

**Interfaces — Consumes:** `sha256_arquivo`, `IncidentError`. **Produces:**
- `CHAVE_RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"`, `CHAVE_RUNONCE = CHAVE_RUN + "Once"`; tipos `"hkcu_run"`, `"hkcu_runonce"`, `"startup_user"`, `"schtask_user"`, `"schtask_sistema"`.
- `@dataclass(frozen=True) class Entrada: tipo: str; local: str; nome: str; comando: str; sha256: str | None = None; exige_servico: bool = False`
- `class Registro(Protocol)`: `valores(chave) -> list[tuple[str, object, int]]`; `apagar(chave, nome)`; `gravar(chave, nome, valor, tipo_reg)`. `class RegistroWindows` (`winreg`, `HKEY_CURRENT_USER`).
- `menciona(texto: str, alvo: str) -> bool` — expande `%VAR%` (`ntpath.expandvars`), troca `/` por `\`, compara com `casefold`; o alvo precisa terminar em fronteira (fim ou caractere fora de `[0-9a-z_.-]`, então `C:\proj` casa `C:\proj\x.js` mas não `C:\projeto`).
- `class Persistencia(*, registro=None, pasta_inicializar=None, run=None, usuario=None)`: `detectar(alvos: list[str], hashes: set[str] = frozenset()) -> list[Entrada]`; `remover(e: Entrada) -> dict` (backup); `restaurar(backup: dict) -> None`. Erros → `IncidentError` com mensagem para a pessoa.

Comportamento: só valores `str` do registro; arquivos regulares da Inicializar (sem seguir link), lidos até 1 MiB (texto como `latin-1` e `utf-16-le` para achar o caminho dentro de `.lnk`), casando por menção ou por SHA-256. `remover` relê a entrada e recusa se mudou ("A entrada mudou desde a detecção; nada foi removido."). Backup da Inicializar guarda o conteúdo embaralhado (XOR com `b"mandacaru-incidente"` + base64) e o SHA-256; arquivo acima de 1 MiB → "Arquivo grande demais para guardar no incidente; use a Quarentena.". `restaurar` valida o backup (tipo conhecido, chave exatamente `CHAVE_RUN`/`CHAVE_RUNONCE`, nome de arquivo sem separador nem `..`, pasta igual à configurada), não sobrescreve (valor idêntico já presente = sucesso; diferente → "Já existe outra entrada com esse nome; nada foi alterado."), cria arquivo com `O_EXCL` e confere o SHA-256.

- [ ] **Step 1: Testes que falham** com `RegistroFalso` (dict) e `tmp_path` como pasta Inicializar: `test_menciona_fronteira_e_variaveis`; `test_detecta_so_entradas_do_incidente` (Run com o exe do incidente, Run do OneDrive e RunOnce com a pasta do projeto → duas entradas); `test_ignora_valor_nao_texto`; `test_inicializar_por_mencao_lnk_e_hash` (`.lnk` falso com o caminho em UTF-16, `.exe` com o SHA do incidente, `.bat` sem relação); `test_remover_e_restaurar_run`; `test_remover_recusa_se_mudou`; `test_restaurar_nao_sobrescreve`; `test_restaurar_valor_identico_ok`; `test_remover_e_restaurar_inicializar` (conteúdo volta byte a byte; JSON do backup não contém o texto original em claro); `test_inicializar_grande_demais`; `test_backup_adulterado_recusado` (chave `Software\Classes\...`, nome `..\x.bat`, tipo desconhecido); `test_registro_windows_real` (só Windows, chave de teste `Software\MandacaruTeste\Run` apagada no fim).
- [ ] **Step 2–4:** Run → FAIL; implementar; Run → PASS + ruff.
- [ ] **Step 5: Commit** `feat(windows): remover e restaurar persistência do usuário (Run e Inicializar)`.

---

### Task 4: Persistência — tarefas agendadas do usuário (`incident_persist.py`)

**Interfaces — Consumes:** `Persistencia`, `Entrada`, `menciona`. **Produces:** detecção/remoção/restauração de `schtask_user` dentro da mesma `Persistencia`; executor `run(args: list[str], timeout: float) -> tuple[int, str]` (padrão `_run_oem`: sem shell, sem janela, saída decodificada com `oem` no Windows).

Comportamento: `schtasks /Query /FO CSV /V /NH`, colunas fixas `1` = nome, `8` = "Tarefa a executar", `14` = "Executar como" (independem do idioma); linhas repetidas por gatilho viram uma só. Tarefa do usuário = último trecho de "Executar como" (`DOMINIO\usuario`) igual ao `usuario` (padrão `%USERNAME%`), senão `schtask_sistema` com `exige_servico=True`. `remover`: só `schtask_user`; guarda `schtasks /Query /TN <nome> /XML` no backup, depois `schtasks /Delete /TN <nome> /F`. `restaurar`: grava o XML em arquivo temporário UTF-16 e roda `schtasks /Create /TN <nome> /XML <arquivo>` (sem `/F`: não sobrescreve). Nome válido: começa com `\`, até 260 caracteres, sem `"`, controles ou `\0`. Código ≠ 0 → `IncidentError` com a saída exibível.

- [ ] **Step 1: Testes que falham** com executor falso que grava os `args`: `test_detecta_tarefa_do_usuario_e_do_sistema`; `test_tarefas_repetidas_por_gatilho_viram_uma`; `test_remover_tarefa_guarda_xml_antes_de_apagar` (ordem dos comandos: `/Query … /XML` antes de `/Delete`); `test_remover_tarefa_do_sistema_recusa` (nenhum comando de apagar); `test_restaurar_tarefa_cria_sem_sobrescrever` (args contêm `/XML`, não contêm `/F`; arquivo temporário apagado depois); `test_nome_de_tarefa_invalido`; `test_schtasks_falha_vira_erro`.
- [ ] **Step 2–4:** Run → FAIL; implementar; Run → PASS + ruff.
- [ ] **Step 5: Commit** `feat(windows): remover e restaurar tarefas agendadas do usuário`.

---

### Task 5: Checklist de credenciais (`incident_cred.py`)

**Produces:** `HOSTS_OFICIAIS = frozenset({"github.com", "myaccount.google.com", "account.microsoft.com", "console.aws.amazon.com", "docs.npmjs.com", "pypi.org"})`; `@dataclass(frozen=True) class ItemCredencial: id: str; texto: str; url: str | None; destaque: bool`; `CATALOGO: dict[str, tuple[str, str | None]]`; `montar_checklist(ameaca: str) -> list[ItemCredencial]` (todos os itens, destacados primeiro; `projeto` destaca `ssh`, `env`, `github_tokens`, `npm`, `pypi`, `aws`; `malware` destaca `navegador`, `google`, `microsoft`, `bancos`, `ssh`; `vulnerabilidade` destaca `navegador`, `google`, `microsoft`); `url_oficial(item_id) -> str | None`.

Itens e URLs: `github_senha` https://github.com/settings/security · `github_tokens` https://github.com/settings/tokens · `ssh` https://github.com/settings/keys · `google` https://myaccount.google.com/security · `microsoft` https://account.microsoft.com/security · `aws` https://console.aws.amazon.com/iam/home#/security_credentials · `npm` https://docs.npmjs.com/revoking-access-tokens · `pypi` https://pypi.org/manage/account/ · `env`, `navegador`, `bancos` sem link.

- [ ] **Step 1: Testes que falham:** `test_links_auditados` (todo URL é `https`, host em `HOSTS_OFICIAIS`, sem usuário/porta/query); `test_os_seis_provedores_tem_link`; `test_destaques_por_ameaca`; `test_ameaca_desconhecida` (`IncidentError`); `test_url_oficial_so_do_catalogo` (id desconhecido → `None`).
- [ ] **Step 2–4:** Run → FAIL; implementar; Run → PASS + ruff.
- [ ] **Step 5: Commit** `feat(windows): checklist de credenciais com links oficiais fixos`.

---

### Task 6: Relatório exportável (`incident_report.py`)

**Interfaces — Consumes:** `Incidente`, `montar_checklist`. **Produces:** `@dataclass(frozen=True) class Ambiente: perfil: str; usuario: str; host: str` + `Ambiente.atual()`; `sanitizar(texto: str, amb: Ambiente) -> str`; `exportar_json(inc, *, ocultar=True, amb=None) -> str`; `exportar_html(inc, *, ocultar=True, amb=None) -> str`; `salvar_relatorio(destino: Path, texto: str) -> None` (atômico).

Sanitização: o perfil (`C:\Users\fulano`, também com `/` e qualquer caixa) vira `%USERPROFILE%`; qualquer outro `X:\Users\<nome>` vira `%USERPROFILE%`; usuário e host com 3+ caracteres, como palavra inteira, viram `<usuário>` e `<computador>`. Campos preservados sem sanitizar: `id`, `regra`, `sha256`, `mitre`, `severidade`, `tipo`, `fase`, `modo`, `resultado`. Backups (`backup`) nunca saem. O JSON leva `"exportado"` e `"sanitizado"`. O HTML tem título "Relatório de incidente — Mandacaru", achados, linha do tempo (desfeitas marcadas), checklist com estado e URLs como texto; tudo passa por `html.escape`.

- [ ] **Step 1: Testes que falham:** `test_sanitiza_perfil_e_outros_usuarios`; `test_usuario_curto_preserva_regra_e_hash` (usuário `agente`, regra `projeto.agente.injecao` intacta); `test_json_sem_backup_e_sanitizado_por_padrao`; `test_json_sem_ocultar_mantem_caminhos`; `test_html_autocontido` (sem `<script`, sem `src=`, sem `http` fora do texto dos links da checklist, CSP presente); `test_html_escapa_texto_do_achado` (`<img onerror>` num caminho vira texto); `test_salvar_relatorio_atomico`.
- [ ] **Step 2–4:** Run → FAIL; implementar; Run → PASS + ruff.
- [ ] **Step 5: Commit** `feat(windows): relatório de incidente em HTML e JSON com sanitização`.

---

### Task 7: Fachada `Resposta` e verificação final (`incident_resposta.py`)

**Interfaces — Consumes:** tudo acima. **Produces:** `class Resposta(store, inc, *, processos=None, persistencia=None)` com `encerrar_processo(pid, exe, sha256, *, modo="guiada") -> Acao`, `detectar_persistencia() -> list[Entrada]` (alvos = caminhos dos achados + `inc.pasta`; hashes = SHA-256 dos achados), `remover_persistencia(e, *, modo="guiada") -> Acao`, `desfazer(indice) -> Acao`, `marcar_credencial(item_id, feito) -> None`.

Regras: a ação é registrada com `resultado="em_andamento"` e o backup **antes** de agir, e regravada com o resultado; nunca levanta exceção para a interface (falha vira `resultado="falhou"` com `detalhe`). `desfazer` só aceita ação `concluida`, com `backup` e ainda não desfeita; marca `desfeita=True` e registra uma ação `tipo="desfazer"`. `marcar_credencial` aceita só ids do `CATALOGO`.

- [ ] **Step 1: Testes que falham:** `test_toda_acao_fica_registrada` (sucesso, recusa e falha aparecem no JSON recarregado); `test_backup_gravado_antes_de_remover` (persistência falsa que lê o JSON do disco dentro de `remover` e vê a ação `em_andamento` com backup); `test_desfazer_restaura_e_marca`; `test_desfazer_duas_vezes_recusa`; `test_desfazer_encerramento_recusa` (não reversível); `test_marcar_credencial_persiste_e_valida`; `test_modulos_sem_qt` (subprocesso `python -c "import mandacaru_win.incident_resposta, mandacaru_win.incident_report, sys; print('PySide6' in sys.modules)"` imprime `False`).
- [ ] **Step 2–4:** Run → FAIL; implementar; Run → PASS + ruff.
- [ ] **Step 5: Verificação final:** `cd windows && pytest -q`, `ruff check .` na raiz, `mandacaru dev . --sem-rede` → código de saída `0` (0 críticos, 0 altos).
- [ ] **Step 6: Commit** `feat(windows): fachada Resposta que registra toda ação do incidente`.
- [ ] **Step 7: Verificação manual no Windows real (dono):** criar um `Run` e uma tarefa agendada apontando para um `.bat` de teste numa pasta, rodar `detectar_persistencia` com essa pasta como `inc.pasta`, remover e desfazer as duas; abrir o HTML exportado no navegador sem rede.
