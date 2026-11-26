# Plano de Implementação — Resposta a Incidentes (Marco c.2: Painel PySide6 das 3 Fases)

> **Para agentes executores:** Siga o fluxo TDD (escrever testes `offscreen` → confirmar falha → implementar `incident_ui.py`, `theme.py` e `app.py` → validar `pytest`, `ruff` e `mandacaru dev`).

**Objetivo:** Construir em PySide6 o painel guiado **Resposta a incidente** (`windows/src/mandacaru_win/incident_ui.py`) integrado à `MainWindow` (`app.py`), consumindo a fachada `Resposta` e os módulos puros do **Marco (c.1)** para conduzir o usuário pelas três fases em ordem (**1. Conter → 2. Neutralizar → 3. Recuperar**), com suporte a **Desfazer**, selo *"Requer Proteção avançada"* quando o serviço opcional não estiver ativo, checklist de credenciais persistida e exportação de relatório HTML/JSON sanitizada por padrão.

**Arquitetura:** Novo módulo `windows/src/mandacaru_win/incident_ui.py` contendo `ExportIncidentDialog` e `IncidentPanel` (aba **Incidentes** na `MainWindow`). `MainWindow` passa a instanciar `IncidentStore(self._data / "incidents")` e oferece atalhos diretos **"Responder…"** em achados `HIGH`/`CRITICAL` da varredura, **"Responder ao incidente…"** na `#faixaProjetoAlerta` (cobrindo todos os achados do projeto) e **"Responder a incidente…"** na aba **Atualizações** quando houver programas de risco `Explorada` ou `Alta`.

**Stack Técnica:** Python ≥ 3.10, PySide6 (`QT_QPA_PLATFORM=offscreen`), `pytest`, `ruff`.

**Spec:** [docs/superpowers/specs/2026-11-26-resposta-a-incidentes-design.md](../specs/2026-11-26-resposta-a-incidentes-design.md) — seções 2, 3, 5, 6 e linha **Marco (c) → c.2**.

---

## Restrições Globais

- **Fronteira de arquivos:** `windows/src/mandacaru_win/incident_ui.py`, `windows/src/mandacaru_win/theme.py`, `windows/src/mandacaru_win/app.py`, `windows/tests/test_incident_ui.py`, `README.md`, `windows/README.md` e este plano. Não modificar `incident*.py` (Marco c.1) nem criar `guard_service.py` (Marco d).
- **A janela continua sem privilégio de administrador:** passos que exigem privilégio elevado (bloqueio de executável no Firewall, persistência `HKLM`/serviços e tarefas agendadas de sistema `exige_servico=True`) aparecem visíveis, porém desabilitados com o selo **"Requer Proteção avançada"** e botão **"Como ativar"** explicando como habilitar pelo instalador.
- **Sanitização visual obrigatória:** todo texto vindo de achados, processos ou entradas de persistência passa por `exibivel(..., limite=None)` antes de ir para rótulos ou detalhes expansíveis.
- **Credenciais e links:** `IncidentPanel` usa exclusivamente `montar_checklist` e `url_oficial` de `incident_cred.py`; nunca lê arquivos sensíveis e só abre URLs `https://` auditadas mediante clique explícito no botão **"Abrir página"**.
- **Exportação segura por padrão:** `ExportIncidentDialog` traz a caixa **"Ocultar nome de usuário e caminhos pessoais"** marcada (`True`) por padrão.
- **Idioma:** código, comentários, docstrings e documentação em **português brasileiro (pt-BR)**.

---

## Tarefas

### Tarefa 1: Diálogo de exportação e painel `IncidentPanel` (`incident_ui.py` + `theme.py`)
- [ ] Adicionar estilos claro/escuro em `theme.py` para cartões de fase (`#incidentPhaseCard`), selos de estado (`#incidentStatusBadge` com propriedade `state`: `auto`, `done`, `pending`, `failed`, `admin`) e detalhes técnicos (`#incidentDetails`).
- [ ] Implementar `ExportIncidentDialog` em `incident_ui.py`: escolha de formato (`HTML autocontido` ou `JSON`), checkbox `"Ocultar nome de usuário e caminhos pessoais"` marcada por padrão e gravação via `exportar_html` / `exportar_json` + `salvar_relatorio`.
- [ ] Implementar `IncidentPanel` em `incident_ui.py`:
  - Seletor de incidentes salvos (`cmb_incidents`) + botão `"Atualizar"`;
  - Faixa fixa de pós-exploração no topo quando `inc.ameaca == "projeto"` ou `inc.origem == "projeto"`;
  - **Fase 1 — Conter:** processos ativos (`Resposta.detectar_processos` + `encerrar_processo`), quarentena de arquivo suspeito com **Desfazer** (`Quarantine.add` / `restore`), bloqueio de rede no Firewall desabilitado com selo *"Requer Proteção avançada"* (quando `not guard_available()`) e orientação de desconexão manual de Wi-Fi/cabo;
  - **Fase 2 — Neutralizar:** entradas de persistência (`detectar_persistencia`, `remover_persistencia`, **Desfazer** via `desfazer(indice)`, selo *"Requer Proteção avançada"* para `exige_servico=True` e `HKLM`/serviços), atalho **Destruir projeto…** (para incidentes de projeto) e atalho **Atualizar programa vulnerável (`winget`)** (para incidentes de vulnerabilidade);
  - **Fase 3 — Recuperar:** botão **Iniciar varredura completa (em lotes)**, checklist marcável de credenciais (`marcar_credencial`) com botões **"Abrir página"** sob clique + nota sobre extensões de navegador, e botão **"Exportar relatório…"**;
  - **Linha do tempo:** histórico das ações registradas no incidente com estado e botão **Desfazer** para ações reversíveis não desfeitas.

### Tarefa 2: Integração na `MainWindow` (`app.py`)
- [ ] Instanciar `self._incident_store = IncidentStore(self._data / "incidents")` e adicionar a aba **"Incidentes"** (`self.incident_panel`).
- [ ] Em achados da varredura com `f.severity >= Severity.HIGH`, incluir botão **"Responder…"** que cria (ou reabre) o incidente correspondente e leva à aba **Incidentes**.
- [ ] Na `#faixaProjetoAlerta`, adicionar botão **"Responder ao incidente…"** ao lado de **"Destruir projeto…"**, abrindo um incidente unificado com os achados do projeto.
- [ ] Na aba **Atualizações**, adicionar botão **"Responder a incidente…"** habilitado quando houver programas de risco `Explorada`, `Explorada (produto)` ou `Alta`.
- [ ] Conectar os callbacks do `IncidentPanel` para varredura completa em lotes (`start_full_recovery_scan`), destruição de projeto (`shred_project`) e navegação para `Atualizações`.

### Tarefa 3: Testes `offscreen` (`windows/tests/test_incident_ui.py`) e documentação
- [ ] Cobrir em `windows/tests/test_incident_ui.py`:
  1. Abertura de incidente a partir de achado `HIGH` na varredura, de projeto armado (`#faixaProjetoAlerta`) e de `Atualizações`;
  2. As 3 fases visíveis em ordem, detalhes técnicos expansíveis, encerramento de processo falso e quarentena + **Desfazer** de arquivo pelo painel;
  3. Remoção e **Desfazer** de persistência (`HKCU\...\Run`) pela interface e exibição do selo *"Requer Proteção avançada"* + instrução de ativação nos itens elevados;
  4. Marcação persistida da checklist de credenciais e abertura de URL oficial somente ao clicar em *"Abrir página"*;
  5. Exportação HTML e JSON pelo diálogo com sanitização marcada por padrão (`ocultar=True`) e desmarcada (`ocultar=False`).
- [ ] Atualizar `README.md` e `windows/README.md` com o painel **Incidentes** (Conter → Neutralizar → Recuperar).
- [ ] Validar `QT_QPA_PLATFORM=offscreen pytest -c windows/pyproject.toml -q windows/tests`, `pytest -q tests/test_packaging.py`, `ruff check .` e `mandacaru dev . --sem-rede`.
