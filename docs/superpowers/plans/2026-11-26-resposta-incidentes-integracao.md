# Resposta a incidentes — integração (b + c.2 + d) com a Proteção avançada instalável — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Uma branch (`feat/integracao-resposta-incidentes`) com os PRs #26, #27 e #28, as correções da revisão e a ligação completa do Guard: instalador com a opção **Proteção avançada**, `Mandacaru.exe` rodando como serviço e painel usando o `GuardClient`, para o dono testar tudo num instalador só.

**Architecture:** O instalador ganha o diálogo do Inno Setup "para todos os usuários / só para mim" (`PrivilegesRequiredOverridesAllowed=dialog`). No modo para todos, o app vai para `{autopf}\Mandacaru` (Arquivos de Programas) e a tarefa **Proteção avançada** registra o serviço `MandacaruGuard` com `"{app}\Mandacaru.exe" --guard-servico` e grava `guard.json` com `{app}\Mandacaru.exe` como único cliente. O modo só para mim continua igual a hoje, sem Guard. No app, a fachada `Resposta` ganha um `guard` opcional (o `GuardClient`) e encaminha para ele o que o usuário não consegue fazer sozinho; o painel só chama a fachada.

**Tech Stack:** Python 3.10–3.13, PySide6, Inno Setup 6, PyInstaller; testes pytest (`offscreen`), ruff.

**Spec:** [docs/superpowers/specs/2026-11-26-resposta-a-incidentes-design.md](../specs/2026-11-26-resposta-a-incidentes-design.md) e os planos dos marcos [b](2026-11-26-resposta-incidentes-marco-b.md), [c.1](2026-11-26-resposta-incidentes-marco-c1.md) e [d](2026-11-26-resposta-incidentes-marco-d.md). Revisões: comentários nos PRs #26 e #27.

## Global Constraints

- O dono autorizou mexer em `app.py`, `incident_ui.py`, `__main__.py`, `updater.py` e `installer.iss` nesta branch; os PRs #26/#27 ficam superados por ela.
- A janela nunca roda elevada; só o instalador (no modo para todos) e o serviço têm privilégio.
- O serviço só roda de Arquivos de Programas (`guard_service.pasta_protegida`) — por isso o Guard só existe no modo para todos.
- `--guard-servico` e `--guard-remover-regras` são tratados **antes** de importar o PySide6 (o serviço não carrega Qt).
- Sem Proteção avançada, tudo continua como antes: passos elevados desativados com o selo *"Requer Proteção avançada"*.
- Textos em pt-BR com acentos; testes sem rede e sem administrador; commits sem `Co-Authored-By`.
- Ao fim de cada tarefa: `cd windows && pytest -q` verde e `ruff check .` limpo; no fim `mandacaru dev . --sem-rede` → 0.

## Review Focus

1. **Processo cujo executável mudou no disco** → botão Encerrar desativado (o SHA-256 vem do achado, nunca do disco) (Tarefa 1).
2. **Painel com o Guard fora do ar** (serviço parado, pipe ausente) → selo "Requer Proteção avançada", nada trava (Tarefas 3 e 4).
3. **Desfazer de ação feita pelo Guard** depois que o serviço foi removido → falha registrada com motivo, sem exceção (Tarefa 3).
4. **Atualização automática no modo para todos** → o setup recebe `/ALLUSERS` e não cria uma segunda cópia por usuário (Tarefa 5).
5. **Reinstalar por cima com o serviço rodando** → o serviço para antes da cópia dos arquivos e volta depois (Tarefa 6).

---

### Task 1: Correções da revisão (#26 e #27)

**Files:** `incident_ui.py`, `app.py`; testes `test_incident_ui.py`, `test_projeto_app.py`.

- [ ] Testes que falham: `test_encerrar_usa_sha_do_achado` (achado com SHA A e arquivo no disco com B → botão "Encerrar processo" desativado com o motivo "O executável mudou desde a detecção" e `encerrar_processo` nunca chamado; processo casado só pela pasta usa o SHA do disco); `test_render_nao_redetecta_a_cada_acao` (fachada falsa conta chamadas: abrir o incidente detecta 1×; encerrar/remover/desfazer não detectam de novo; **Atualizar** detecta); `test_desfazer_quarentena_com_disco_cheio_nao_levanta` (`store.salvar` levanta `IncidentError` → nenhuma exceção sai do slot, aviso mostrado); `test_destruir_projeto_lembra_que_nao_desfaz` (mensagem final contém "Destruir a pasta não desfaz o que já foi executado").
- [ ] Implementar: SHA esperado = do achado cujo `caminho` é o `proc.exe` (`ntpath.normcase`); sem achado do caminho → SHA do disco; achado ≠ disco → desativado; remover `sha_padrao`. Detecção só em `load_incident`/`refresh` (cache em `_detected_*`; ação bem-sucedida tira o item da lista). `try/except IncidentError` nos `salvar` do Desfazer. Em `_on_shred_done`, se o alvo estava em `_flagged_projects`, acrescentar o aviso.
- [ ] Run → PASS + ruff. Commit `fix(windows): correções da revisão do painel e do Destruir projeto`.

### Task 2: Detectar persistência do sistema (c.1)

**Files:** `incident_persist.py`; teste `test_incident_persist.py`.

- [ ] Testes: com registro HKLM falso, pasta Inicializar global em `tmp_path` e serviços falsos (`ImagePath` mencionando o alvo), `detectar` devolve `hklm_run`, `hklm_runonce`, `startup_all` e `service` com `exige_servico=True`; nada sem menção; serviço com binário em `System32` não aparece. `backup()` dessas entradas continua recusando ("Proteção avançada").
- [ ] Implementar: `Persistencia(..., registro_hklm=None, pasta_inicializar_global=None)`; leitura só (sem admin). `schtask_sistema` continua como está.
- [ ] Run → PASS + ruff. Commit `feat(windows): detectar persistência do sistema ligada ao incidente`.

### Task 3: Fachada com Guard (`incident_resposta.py`)

**Produces:** `Resposta(..., guard=None)`; `guard_disponivel() -> bool`; `remover_persistencia` encaminha `exige_servico` ao Guard (`hklm_run`/`hklm_runonce`/`startup_all`/`service` iguais; `schtask_sistema` → `schtask`; `startup_all` manda o SHA-256 como `valor`) com `backup={"guard": "persistencia", "id": …}`; `desfazer` → `persistence_restore`; `bloquear_rede(exe) -> Acao` (regra `Mandacaru-<16 hex>`, `backup={"guard": "firewall", "regra": …}`; desfazer → `firewall_unblock`); `quarentenar(caminho, sha256, severidade, regras) -> Acao` (local; se falhar e houver Guard, `quarantine_file`; `backup` diz qual; desfazer restaura no mesmo lugar); `encerrar_processo` tenta o Guard para os PIDs que falharam por acesso negado.

- [ ] Testes com `GuardFalso` (registra pedidos, responde ok/erro, `disponivel`): cada encaminhamento, Desfazer de cada um, Guard ausente → `falhou` com "Requer Proteção avançada", `GuardError` → `falhou` com a mensagem, tudo gravado antes de agir.
- [ ] Run → PASS + ruff. Commit `feat(windows): fachada Resposta usa a Proteção avançada quando instalada`.

### Task 4: Painel ligado ao Guard

**Files:** `incident_ui.py`, `app.py`; teste `test_incident_ui.py`.

- [ ] Testes: com `guard_available=True` e fachada falsa, o passo "Bloquear rede" fica ativo e chama `bloquear_rede`; entrada `exige_servico` ativa chama `remover_persistencia`; quarentena do painel passa por `Resposta.quarentenar` (o código duplicado sai); `guard_available` é consultado uma vez por render.
- [ ] Implementar; no `app.py`, `guard_available` = `GuardClient().disponivel()` com cache de 30 s e `resposta_factory` passando o `GuardClient`.
- [ ] Run → PASS + ruff. Commit `feat(windows): painel usa a Proteção avançada`.

### Task 5: `Mandacaru.exe` como serviço e atualização no modo para todos

**Files:** `__main__.py`, `updater.py`; testes `test_app.py`/`test_updater.py`.

- [ ] Testes: `guard_argv(["--guard-servico"]) == ["servico"]`, `["--guard-remover-regras"] → ["remover-regras"]`, outros → `None`; `install_command` acrescenta `/ALLUSERS` quando o app roda de Arquivos de Programas e não acrescenta no modo por usuário.
- [ ] Implementar o despacho no topo do `__main__` (antes do PySide6) e o `/ALLUSERS` no `updater`.
- [ ] Run → PASS + ruff. Commit `feat(windows): Mandacaru.exe roda o MandacaruGuard e atualiza no modo para todos`.

### Task 6: Instalador com Proteção avançada (`installer.iss`)

- [ ] Teste `test_installer_iss` (lê o arquivo): `PrivilegesRequiredOverridesAllowed=dialog`, `DefaultDirName={autopf}\Mandacaru`, `Root: HKA` no menu de contexto, tarefa `protecaoavancada` com `Check: IsAdminInstallMode`, `--guard-servico` no `binPath`, `--guard-remover-regras` e `delete MandacaruGuard` na desinstalação.
- [ ] Implementar: `[Tasks]` `protecaoavancada` (só no modo para todos, marcada); `[Code]` para em `ssInstall` (`sc stop`, espera) e, em `ssPostInstall`, grava `guard.json`, `sc create`/`sc config` (`start= auto`, `obj= LocalSystem`), `sc description` e `sc start`; `[UninstallRun]` com `--guard-remover-regras`, `sc stop` e `sc delete`. Ícones em `{autoprograms}`/`{autodesktop}`.
- [ ] Run → PASS + ruff. Commit `feat(windows): instalador com a opção Proteção avançada`.

### Task 7: Verificação e entrega

- [ ] `cd windows && pytest -q`, `ruff check .`, `mandacaru dev . --sem-rede` → 0; push; CI `windows.yml` gera o instalador; baixar para `Downloads` do Windows; roteiro de teste para o dono.
