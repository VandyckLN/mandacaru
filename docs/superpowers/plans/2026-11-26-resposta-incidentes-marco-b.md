# Plano de Implementação — Resposta a Incidentes (Marco b: Ações Diretas em Projetos)

> **Para agentes executores:** Siga o fluxo TDD tarefa por tarefa (escrever testes que falham → confirmar falha → implementar → rodar `pytest` e `ruff` → commitar). Use caixas de seleção (`- [ ]`) para acompanhar o progresso.

**Objetivo:** Permitir responder diretamente a ameaças detectadas em projetos no app do Windows — colocando em quarentena apenas o arquivo perigoso do projeto (ex.: `.vscode/tasks.json`, hook do Git, `AGENTS.md`, `setup.py`), oferecendo destruição definitiva da pasta inteira do projeto armado e exibindo o aviso fixo de pós-exploração sempre que houver achado `HIGH` ou `CRITICAL`.

**Arquitetura:** Reaproveita integralmente `Quarantine` (`windows/src/mandacaru_win/quarantine.py`) convertendo os `Achado` da linha do projeto em `Finding` via `Achado.to_alert(raiz)`, endurecendo antes `Quarantine.add()` contra links simbólicos e junções (corrida TOCTOU entre a leitura e o clique). Na interface (`windows/src/mandacaru_win/app.py`), as linhas de projeto ganham o botão **Quarentena** (habilitado para arquivos perigosos e desabilitado com explicação quando a linha tiver apenas achados de biblioteca declarada `projeto.dep.*` ou arquivo ilegível), e a aba **Varredura** ganha a faixa `#faixaProjetoAlerta` (visível sempre que uma verificação de projeto trouxer achado não ignorado `≥ HIGH`) com o aviso fixo e o botão **Destruir projeto…** integrado ao `ShredThread` (já seguro contra hard links no PR #24).

**Stack Técnica:** Python ≥ 3.10, PySide6, `pytest` (`QT_QPA_PLATFORM=offscreen`), `ruff`.

**Spec:** [docs/superpowers/specs/2026-11-26-resposta-a-incidentes-design.md](../specs/2026-11-26-resposta-a-incidentes-design.md) — **Marco (b)**.

---

## Restrições Globais

- **Nada é movido ou destruído automaticamente no Marco (b):** tanto **Quarentena** do arquivo quanto **Destruir projeto…** exigem clique e confirmação explícita do usuário (`self.confirm(...)`).
- **Pré-requisito de hard link preservado:** `shred_file` (`windows/src/mandacaru_win/shred.py`) já desvincula (`os.unlink`) sem sobrescrever quando `st_nlink > 1`; nenhum código novo pode contornar `shred_path` / `_assert_safe_target`.
- **Nunca seguir link simbólico ou junção na quarentena:** mesmo que um arquivo legítimo do projeto seja trocado por symlink/junção entre o fim da verificação e o clique em **Quarentena** (TOCTOU), `Quarantine.add()` deve recusar sem ler nem apagar o destino.
- **Texto vindo do projeto nunca entra cru na UI:** caminhos de projeto, nomes de pastas e nomes de arquivos exibidos na faixa de alerta, nos tooltips e nos diálogos de confirmação passam sempre por `_visivel(...)` / `exibivel(...)` (neutralizando RLO `U+202E`, controles e quebras de linha).
- **Dependências declaradas (`projeto.dep.*`):** colocar `package-lock.json` ou `requirements.txt` em quarentena não remove pacotes já instalados e quebra a trava de versões; quando todos os achados da linha forem `_por_chave(a)`, o botão **Quarentena** fica desabilitado com motivo claro em português.
- **Idioma:** toda documentação, comentários, docstrings e mensagens de interface em **português brasileiro (pt-BR)** com acentuação correta.
- **Qualidade a cada tarefa:** `ruff check .` sem erros e suítes `pytest -q` (raiz e `windows/tests`) 100% verdes.

## Focos de Revisão

1. **Corrida TOCTOU com link simbólico/junção na quarentena:** o arquivo `tasks.json` era regular durante `verificar_projeto`, mas virou symlink para fora da pasta antes do clique em **Quarentena**. Esperado: `Quarantine.add` recusa com `QuarantineError`, não cria `.bin`/`.json` e mantém o arquivo-alvo externo intacto (Tarefa 1).
2. **Linha só de biblioteca vulnerável/maliciosa (`projeto.dep.*`) vs linha mista:** em `package-lock.json` só com `projeto.dep.malicioso`, **Quarentena** fica desabilitado com tooltip explicativo; já em `package.json` com `projeto.instalar.hook` (`postinstall` suspeito), **Quarentena** fica habilitado e restaura no caminho original pela aba *Quarentena* (Tarefa 2).
3. **Aviso fixo persistente após isolar um arquivo:** mesmo depois que o usuário puser `tasks.json` em quarentena, se o projeto teve `HIGH` ou `CRITICAL`, o aviso *"Se você já abriu ou instalou este projeto…"* **permanece visível** até nova varredura limpa ou até o projeto ser destruído — para evitar a falsa sensação de que remover o arquivo desfez algo já executado (Tarefa 3).
4. **Limpeza de linhas órfãs após Destruir projeto:** ao concluir a destruição de uma pasta de projeto, todas as linhas da árvore pertencentes àquela pasta (antivírus em `_items`, projeto em `_proj_items` e entradas em `_proj_low_item`) são removidas da árvore, evitando botões apontando para arquivos que não existem mais (Tarefa 3).
5. **Nome de pasta hostil (RLO / quebras de linha) e múltiplos projetos arrastados:** soltar duas pastas de projeto com `HIGH` mantém ambas acessíveis para destruição e exibe nomes sanitizados com `_visivel` sem caracteres invisíveis (Tarefa 3).

---

## Estrutura de Arquivos

```text
windows/src/mandacaru_win/
  quarantine.py            # Recusar symlink/junção em add() e destino symlink em restore()   (T1)
  theme.py                 # Estilo claro/escuro para #faixaProjetoAlerta                     (T3)
  app.py                   # Quarentena na linha de projeto + faixa de aviso + Destruir proj. (T2, T3)
windows/tests/
  test_quarantine.py       # Testes de symlink/junção em add() e restore()                    (T1)
  test_projeto_app.py      # Testes de quarentena de arquivo de projeto, aviso fixo e shred   (T2, T3)
  test_widgets.py          # Teste de estilo claro/escuro da #faixaProjetoAlerta              (T3)
windows/README.md          # Documentar ações diretas em projetos (Quarentena e Destruir)     (T3)
README.md                  # Atualizar resumo do app Windows com ações em projetos            (T3)
```

---

### Tarefa 1: Endurecer `Quarantine` contra links simbólicos e junções

**Arquivos:**
- Modificar: `windows/src/mandacaru_win/quarantine.py`
- Testar: `windows/tests/test_quarantine.py`

**Interfaces e comportamento esperado:**
- Em `quarantine.py`:
  - Helper `_is_link(path: Path) -> bool` usando `os.path.islink(p) or getattr(os.path, "isjunction", lambda _: False)(p)`.
  - Em `Quarantine.add(finding)`:
    - Antes de abrir `original`, verifica `if _is_link(original): raise QuarantineError("Links simbólicos e junções não podem ser movidos para a quarentena.")`.
    - Ao abrir `original` para leitura, usa `os.open` com `O_RDONLY | O_BINARY | O_NOFOLLOW` (onde `O_NOFOLLOW` existir) e confere `stat.S_ISREG(os.fstat(fd).st_mode)` antes de ler os blocos — fechando qualquer janela TOCTOU entre a checagem e o `open`.
    - Antes de `_remove_original(original)`, revalida `if _is_link(original): raise QuarantineError(...)` (limpando `.bin`/`.json` se falhar).
  - Em `Quarantine.restore(qid)`:
    - Na escolha de `dest` (`while dest.exists() or _is_link(dest):`), trata symlink quebrado como nome ocupado para nunca tentar sobrescrever/seguir um link existente, e recusa se `orig.parent` for link/junção fora do esperado apenas caso `open(dest, "xb")` falhe.

- [ ] **Passo 1: Escrever os testes que falham** em `windows/tests/test_quarantine.py`:
  - `test_symlink_is_refused_without_touching_target`: cria `fora.txt` com `"segredo"` e um symlink `link.ps1 -> fora.txt` (pula com `pytest.skip` se o SO negar criação de symlink sem admin); montar `Finding` com o SHA-256 de `fora.txt` e chamar `q.add(...)` deve levantar `QuarantineError`, deixar `fora.txt` intacto, manter o `link.ps1` intacto e deixar a pasta `q/` vazia.
  - `test_restore_when_dangling_symlink_occupies_original_name`: coloca `a.ps1` em quarentena, cria no lugar `a.ps1 -> nao_existe` (symlink quebrado, onde `dest.exists()` seria `False` mas `islink` é `True`) e chama `q.restore(qid)` → restaura em `a (restaurado).ps1` sem tocar no symlink.
- [ ] **Passo 2: Rodar** `QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -c windows/pyproject.toml windows/tests/test_quarantine.py -v`. Esperado: FALHA nos testes novos.
- [ ] **Passo 3: Implementar** as validações sem seguir links em `windows/src/mandacaru_win/quarantine.py`.
- [ ] **Passo 4: Rodar** `QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -c windows/pyproject.toml windows/tests/test_quarantine.py -q && .venv/bin/ruff check windows/`. Esperado: PASS e lint limpo.
- [ ] **Passo 5: Commit** `fix(windows): recusar links simbolicos e juncoes na quarentena`.

---

### Tarefa 2: Quarentena por arquivo perigoso nas linhas de verificação de projeto

**Arquivos:**
- Modificar: `windows/src/mandacaru_win/app.py`
- Testar: `windows/tests/test_projeto_app.py`

**Interfaces e comportamento esperado:**
- Em `MainWindow` (`windows/src/mandacaru_win/app.py`):
  - `self._proj_rows` passa a guardar `dict[Path, tuple[Path, list[Achado], str | None]]` → `(raiz, achados, sha)` (atualizando `copy_project_detail` e `ignore_project_row` para desempacotar os 3 campos).
  - Em `_add_project_row(self, raiz: Path, path: Path, caminho: str, achados: list[Achado], sha: str | None)`:
    - Calcula `no_quarantine: str | None`:
      - Se `all(_por_chave(a) for a in achados)`: `"Achado em biblioteca declarada: atualize a dependência ou destrua a pasta do projeto."`
      - Senão, se `sha is None`: `"Não foi possível ler o arquivo para colocá-lo em quarentena."`
      - Senão: `None` (botão habilitado).
    - Botões da linha via `_row_buttons(path, [...])`:
      1. `("Abrir local", self.open_location, "neutral", None)`
      2. `("Copiar detalhe", self.copy_project_detail, "neutral", None)`
      3. `("Ignorar sempre", self.ignore_project_row, "neutral", no_ignore)`
      4. `("Quarentena", self.quarantine_project_row, "quarantine", no_quarantine)`
    - Ajustar largura inicial da coluna 3 de `self.tree` se necessário (ex.: `440`) para acomodar confortavelmente os 4 botões compactos.
  - Novo método `quarantine_project_row(self, path: Path) -> None`:
    - Busca `(raiz, achados, sha)` em `self._proj_rows.get(path)`; se não existir, retorna.
    - Se `all(_por_chave(a) for a in achados)` ou `sha is None`, avisa com `self.notify(...)` e retorna.
    - Pede confirmação: `self.confirm(f"Mover este arquivo do projeto para a quarentena?\n{_visivel(str(path))}")`.
    - Monta `Finding(path=path, sha256=sha, severity=achados[0].severidade, alerts=[a.to_alert(raiz) for a in achados if not _por_chave(a)])`.
    - Chama `self._quarantine.add(finding)`; em `QuarantineError`, chama `self.notify(str(e))` e mantém a linha.
    - Em sucesso: remove a linha (`self._remove_project_row(path)`), remove também de `self.findings`/`self._items` caso o mesmo arquivo estivesse listado pelo antivírus (`self._remove_row(path)`), chama `self.refresh_tabs()` e mostra na status bar `"Arquivo movido para a quarentena"`.

- [ ] **Passo 1: Escrever/atualizar os testes** em `windows/tests/test_projeto_app.py`:
  - Atualizar `test_botao_verificar_projeto_sem_quarentena` → renomear para `test_botoes_da_linha_de_projeto` verificando `["Abrir local", "Copiar detalhe", "Ignorar sempre", "Quarentena"]` e conferindo que `"Quarentena"` está habilitado em `AGENTS.md`.
  - `test_quarentena_de_arquivo_perigoso_do_projeto_e_restauracao`: projeto com `.vscode/tasks.json` armado (`runOn: folderOpen` + comando suspeito) e `README.md` limpo:
    - após `verificar(win, d)`, clicar em `"Quarentena"` na linha de `.vscode/tasks.json` remove `.vscode/tasks.json` do disco, mantém `README.md` intacto, tira a linha da árvore e adiciona 1 item em `win.tbl_quarantine` com a regra `projeto.abrir.tarefa_automatica`;
    - chamar `win.restore_item(qid)` devolve `.vscode/tasks.json` exatamente ao lugar original dentro de `.vscode/` com o mesmo conteúdo.
  - `test_quarentena_recusada_na_confirmacao_nao_move`: com `win.confirm = lambda _: False`, clicar em `"Quarentena"` mantém o arquivo no projeto e a linha na árvore.
  - `test_quarentena_desabilitada_em_linha_so_de_dependencia`: com `_rel_dep(d, ["MAL-2026-0001"])`, o botão `"Quarentena"` na linha de `package-lock.json` vem `isEnabled() is False` e com tooltip mencionando biblioteca declarada.
- [ ] **Passo 2: Rodar** `QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -c windows/pyproject.toml windows/tests/test_projeto_app.py -v`. Esperado: FALHA nos testes novos/atualizados.
- [ ] **Passo 3: Implementar** `quarantine_project_row` e a atualização de `_proj_rows`/`_add_project_row` em `windows/src/mandacaru_win/app.py`.
- [ ] **Passo 4: Rodar** `QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -c windows/pyproject.toml -q windows/tests && .venv/bin/ruff check .`. Esperado: PASS completo.
- [ ] **Passo 5: Commit** `feat(windows): quarentena por arquivo perigoso em projetos verificados`.

---

### Tarefa 3: Faixa de aviso fixo (`HIGH`/`CRITICAL`) e botão "Destruir projeto…"

**Arquivos:**
- Modificar: `windows/src/mandacaru_win/theme.py`, `windows/src/mandacaru_win/app.py`, `windows/README.md`, `README.md`
- Testar: `windows/tests/test_projeto_app.py`, `windows/tests/test_widgets.py`

**Interfaces e comportamento esperado:**
- Em `theme.py` (`build_stylesheet`):
  - Adicionar estilo para `#faixaProjetoAlerta` adaptado ao tema claro e escuro:
    - Escuro: fundo `#361b1b`, borda `#8c3232`, texto `#ffcdd2`;
    - Claro: fundo `#fdecea`, borda `#e57373`, texto `#7f1d1d`;
    - `border-radius: 6px;` e `QLabel` com `font-weight: 600;`.
- Em `app.py`:
  - Estado: `self._flagged_projects: list[Path] = []` (raízes de projetos verificados na sessão atual que apresentaram ao menos um achado não ignorado com `severidade >= Severity.HIGH`).
  - Widget `self.project_alert_bar = QFrame()` (`objectName="faixaProjetoAlerta"`, `setVisible(False)`), inserido no layout da aba **Varredura** entre `self.lbl_count` e `self.tree`:
    - `self.lbl_project_alert = QLabel("")` (`wordWrap=True`) exibindo o aviso fixo obrigatório (com o nome do(s) projeto(s) sanitizado via `_visivel`):
      > *"Atenção ({projetos}): se você já abriu ou instalou este projeto, faça uma varredura completa e troque chaves e tokens. Destruir a pasta não desfaz o que já foi executado."*
    - `self.btn_shred_project = style_button(QPushButton("Destruir projeto…"), "danger", compact=True)`, conectado a `self.shred_flagged_project`.
  - Em `_clear_results()`: limpa `self._flagged_projects.clear()` e esconde `self.project_alert_bar.setVisible(False)`.
  - Em `_add_project_rows(rel, hashes)`: se houver qualquer achado exibido (não ignorado) com `a.severidade >= Severity.HIGH`, adiciona `Path(rel.raiz)` a `self._flagged_projects` (sem duplicar) e chama `self._refresh_project_alert_bar()`. Projetos só com `MEDIUM` ou `LOW` **não** ligam a faixa.
  - Persistência intencional do aviso: colocar um arquivo individual em quarentena ou clicar em *Ignorar sempre* **não** esconde a faixa naquela sessão (pois o projeto já pode ter sido aberto antes); ela só limpa em nova varredura (`_clear_results`) ou quando todos os projetos sinalizados forem destruídos.
  - Método `shred_project(self, raiz: Path) -> None`:
    - Se `self._busy()`, retorna.
    - Mensagem de confirmação reforçando o aviso com caminho sanitizado por `_visivel(str(raiz))` e delegação para a execução de `ShredThread(Path(raiz))` (reaproveitando o fluxo de `shred_target`, guardando `self._shredding_project: Path | None = Path(raiz)` ou limpando por prefixo de caminho em `_on_shred_done`).
  - Método `shred_flagged_project(self) -> None`:
    - Se `len(self._flagged_projects) == 1`: chama `self.shred_project(self._flagged_projects[0])`.
    - Se `len(self._flagged_projects) > 1`: abre um `QMenu` ancorado em `self.btn_shred_project` listando cada pasta sanitizada (`_visivel(p.name) — _visivel(str(p))`) para o usuário escolher qual destruir.
  - Em `_on_shred_done(summary)`:
    - Quando `summary.completed` for `True` (e `summary.target` não vazio), remove da árvore todas as linhas em `self._items` e `self._proj_items` (e filhos de `self._proj_low_item`) cujo caminho esteja dentro de `summary.target` (`scan._is_under(p, (norm_target,))`); se `self._proj_low_item` ficar sem filhos, remove-o também.
    - Remove de `self._flagged_projects` qualquer projeto igual ou contido em `summary.target` e atualiza `self._refresh_project_alert_bar()`.
- Documentação (`windows/README.md` e `README.md`):
  - Atualizar a seção do Windows explicando o botão **Quarentena** por arquivo em projetos, o aviso de segurança em achados graves de projeto e o botão **Destruir projeto…**.

- [ ] **Passo 1: Escrever os testes que falham** em `windows/tests/test_projeto_app.py` e `windows/tests/test_widgets.py`:
  - `test_aviso_fixo_aparece_em_high_e_nao_em_medium_ou_low`:
    - projeto só com `LOW` (`postinstall: husky`) ou só com `MEDIUM` → `win.project_alert_bar.isVisible()` é `False`;
    - projeto com `HIGH` (`AGENTS.md` com prompt injection) → `win.project_alert_bar.isVisible()` é `True` e `win.lbl_project_alert.text()` contém `"Se você já abriu ou instalou este projeto, faça uma varredura completa e troque chaves e tokens"` (case-insensitive) e `"não desfaz"`;
    - colocar `AGENTS.md` em quarentena remove a linha, mas mantém `win.project_alert_bar.isVisible() is True`.
  - `test_destruir_projeto_pela_faixa_apaga_pasta_e_limpa_linhas`:
    - projeto com `AGENTS.md` (`HIGH`), `a.ps1` (`ps_text`) e `package.json` (`LOW` `husky`), solto via `soltar(win, [d])`;
    - clicar em `win.btn_shred_project` (com `win.confirm = lambda _: True` e esperando `win.shred_finished`) apaga a pasta `d` do disco, limpa `win.findings`, `win._proj_items` e `win._proj_low_item`, e esconde `win.project_alert_bar`.
  - `test_aviso_fixo_sanitiza_nome_hostil_do_projeto`: pasta com `\u202e` no nome não deixa `\u202e` cru em `win.lbl_project_alert.text()`.
  - Em `windows/tests/test_widgets.py`: conferir que `#faixaProjetoAlerta` existe em `build_stylesheet(False)` e `build_stylesheet(True)`.
- [ ] **Passo 2: Rodar** `QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -c windows/pyproject.toml windows/tests/test_projeto_app.py windows/tests/test_widgets.py -v`. Esperado: FALHA nos testes novos.
- [ ] **Passo 3: Implementar** o estilo em `theme.py`, a faixa + `shred_project` + limpeza de linhas órfãs em `app.py` e a atualização em `windows/README.md` e `README.md`.
- [ ] **Passo 4: Rodar** `QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -c windows/pyproject.toml -q windows/tests && .venv/bin/python -m pytest -q && .venv/bin/ruff check .`. Esperado: 100% PASS e lint zero erros.
- [ ] **Passo 5: Commit** `feat(windows): aviso fixo e botao Destruir projeto em achados graves`.

---

## Verificação Final do Marco (b)

- [ ] `.venv/bin/pytest -q` (suíte principal) — 100% verde.
- [ ] `QT_QPA_PLATFORM=offscreen .venv/bin/pytest -c windows/pyproject.toml -q windows/tests` — 100% verde.
- [ ] `.venv/bin/ruff check .` — 0 erros.
- [ ] Conferir `git status` garantindo que nenhuma amostra/fixture maliciosa foi commitada no repositório (`.venv/bin/python -m mandacaru dev . --sem-rede` continua saindo com código `0`).
