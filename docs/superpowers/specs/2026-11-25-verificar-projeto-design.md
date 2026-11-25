# Verificar projeto: ataques a desenvolvedores e a agentes de IA

Data: 2026-11-25 · Estado: rascunho

## Por quê

Os ataques mudaram de alvo. Além do executável baixado, agora miram **o projeto que o desenvolvedor abre** e **o agente de IA que lê esse projeto por ele** (Claude Code, Copilot, Cursor). Um repositório clonado pode:

- trazer instruções escondidas para o agente: prompt injection em `AGENTS.md`, README, comentários ou texto Unicode invisível;
- executar algo só de abrir a pasta no editor, como tarefas do VS Code, hooks do agente e servidores MCP;
- executar algo ao instalar as dependências, com `postinstall` ou `setup.py`;
- esconder lógica com caracteres bidirecionais (Trojan Source);
- depender de bibliotecas com falha conhecida ou de **pacotes maliciosos** já catalogados.

O Mandacaru já tem parte disso para arquivos soltos: duas regras de prompt injection em `base.yar`, a heurística de script ofuscado e o comportamento de agente lendo credenciais. Falta um modo que olhe para **um projeto como projeto**.

Quem usa: o desenvolvedor, no Windows (app) ou no Linux (linha de comando), **antes de abrir um projeto de terceiros no editor ou no agente**. A pergunta que a ferramenta responde é: "posso abrir isso?".

## Objetivos

- **`mandacaru dev <pasta>`** (linha de comando, Linux e Windows) e **arrastar a pasta para a janela** do app Windows verificam o projeto e mostram um relatório por **arquivo e linha**, em português.
- **Cinco famílias de técnicas** (detalhe em "O que procurar"):
  1. instruções para agentes;
  2. execução ao abrir a pasta;
  3. execução ao instalar dependências;
  4. Trojan Source;
  5. CI inseguro.
- **Bibliotecas sempre verificadas** em toda verificação de projeto. São lidos os lockfiles de npm e Python e consultados o OSV.dev e o CISA KEV. Aparece só o que tem **falha conhecida ou é malicioso**, com severidade, marca "já explorada" (KEV) e "corrigida na versão X".
- Nada é movido nem apagado. **Sem quarentena** neste modo, porque mover arquivos quebraria o projeto.

## Não-objetivos

- Listar bibliotecas que só têm versão mais nova sem falha (decidido: apenas falha conhecida ou pacote malicioso).
- Procurar segredos vazados (`.env`, chaves no código). gitleaks e similares já fazem isso bem.
- Relatório SARIF ou integração específica com CI. O código de saída permite usar em CI, mas não é o foco desta versão.
- Vigiar pastas de projeto continuamente (o `monitor`).
- Ecossistemas além de npm e PyPI nesta versão: Go, Rust, Maven, NuGet e Composer ficam para depois.
- Verificar o código de cada pacote dentro de `node_modules` ou `.venv`. As dependências entram pelo lockfile e pelo OSV.

## Anti-objetivos (seria falha mesmo funcionando)

- **Aceitar supressão vinda do próprio projeto.** Um arquivo `.mandacaruignore` ou um comentário "mandacaru: ignore" dentro do repositório seria o primeiro truque do atacante. A lista de ignorados vive só na máquina do usuário.
- **Enviar código para fora.** Só saem nome, versão e ecossistema das bibliotecas para o OSV.dev, como já faz o `vuln`. Nunca conteúdo, caminho ou nome do projeto.
- **Executar qualquer coisa do projeto** para analisá-lo: nada de `npm ls`, `pip`, `git` com hooks ou build. Tudo é leitura de arquivo.
- **Alarme à toa.** Num projeto comum (React, Django), uma verificação deve sair limpa ou quase. Um projeto que só *documenta* prompt injection, como o próprio `base.yar`, não deve virar HIGH.
- Alterar a varredura antivírus comum de Downloads e outras pastas. Ela continua exatamente como está.

## Restrições

- Núcleo em `src/mandacaru/` (Python, pacote `mandacaru-edr`). Única dependência nova: PyYAML (ver "Decisões minhas").
- App Windows em PySide6 (`windows/src/mandacaru_win/`). Trabalho pesado fora da thread da interface, no padrão `ScanThread`/`worker.py`.
- Reaproveitar:
  - `vuln/osv_client.py`: `OsvClient.query_packages` aceita `InstalledPackage` com `ecosystem="npm"` ou `"PyPI"`;
  - `vuln/kev_cache.py`;
  - `vuln/scorer.py`;
  - `events.Alert`/`Severity`;
  - as regras YARA existentes.
- Sem rede: o resto da verificação roda normalmente e o relatório diz "bibliotecas não verificadas (sem conexão com o OSV.dev)". Nunca "nenhuma falha".
- Interface e mensagens em português com acentos.

## Abordagens consideradas

- **A. Verificador de projetos próprio (escolhida).** Módulo novo com leitores que entendem a estrutura de cada arquivo (JSON, YAML, TOML, lockfiles) e regras de texto para os arquivos de agentes. As dependências passam pelo `vuln`. Dá arquivo e linha, aviso com contexto e menos ruído, e não toca a varredura comum. É a que mais exige código.
- **B. Só regras YARA novas, sem pular `node_modules`.** Barata, mas o YARA não entende estrutura: um `postinstall` citado em documentação parece um real. Não dá linha nem verifica bibliotecas, e encheria a varredura comum de falsos positivos.
- **C. Embutir ferramentas prontas (osv-scanner, zizmor).** Maduras, mas pesam no instalador, falam inglês, tiram o controle sobre falso positivo e fogem da linha do projeto de regras próprias por técnica.

O dono escolheu **A**.

## Desenho

### Módulo `src/mandacaru/projeto/`

```
projeto/
  __init__.py      # verificar_projeto(raiz, osv=..., kev=...) -> RelatorioProjeto
  achado.py        # Achado (regra, severidade, arquivo, linha, trecho, explicação, mitre)
  agentes.py       # família 1: arquivos lidos por agentes
  abrir.py         # família 2: execução ao abrir a pasta
  instalar.py      # família 3: scripts de instalação
  unicode.py       # família 4: bidi / invisíveis (usada também pela família 1)
  ci.py            # família 5: GitHub Actions
  dependencias.py  # lockfiles -> InstalledPackage -> OSV + KEV
  cli.py           # subcomando `mandacaru dev`
```

- **`Achado`** tem `regra`, `severidade`, `caminho` relativo à raiz, `linha` (1-based, opcional), `trecho` (até cerca de 120 caracteres, com invisíveis mostrados como `<U+202E>`), `explicacao` em português de uma ou duas frases dizendo o que aconteceria e `mitre`. Converte para `Alert` (`to_alert`) para reaproveitar `--json` e `jsonl_sink`.
- **Percurso.** Anda pela árvore sem seguir links e pula `node_modules`, `.venv`, `venv`, `__pycache__`, `dist`, `build`, `.git/objects`. Lê `.git/config` e `.git/hooks` (ver família 2). Limite por arquivo de 2 MB e limite de cerca de 20 mil arquivos, com aviso no relatório quando for atingido.
- **Exclusões do usuário** vêm da configuração local (`[exclude] paths` e as pastas ignoradas do app), nunca do repositório.

### O que procurar

**Família 1: instruções para agentes.** Arquivos-alvo: `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/*`, `.windsurfrules`, `.github/copilot-instructions.md`, `.github/instructions/*`, `.clinerules`, `README*`, `CONTRIBUTING*`, `docs/**/*.md` e templates de issue e PR.

| Regra | Quando | Severidade |
|---|---|---|
| `projeto.agente.unicode_oculto` | sequência de Unicode Tags (U+E0000–E007F), ou 3+ caracteres de largura zero seguidos, num arquivo de agente | HIGH |
| `projeto.agente.injecao` | frases de injection (as de `Prompt_Injection_Instructions` e variantes) **num arquivo de agente** | HIGH |
| `projeto.agente.exfiltracao` | pedido a uma IA para enviar `.ssh`, `.env`, token ou credenciais (padrão `$act1` + `$ai` da regra existente) | HIGH |
| `projeto.agente.comentario_oculto` | comentário HTML `<!-- -->` num `.md` com verbo imperativo dirigido ao agente ("execute", "run", "rode", "ignore", "não mencione") | MEDIUM |
| `projeto.texto.injecao` | as mesmas frases em **outros** arquivos (README, código, comentários) | MEDIUM; LOW se o arquivo estiver em `tests/`, `docs/` ou tiver extensão `.yar`/`.yara` |

O rebaixamento em `tests/`, `docs/` e `.yar` existe para que projetos de segurança, que citam ataques de propósito, não virem HIGH. Ele **não** vale para os arquivos de agente propriamente ditos.

**Família 2: execução ao abrir a pasta.**

| Arquivo | Regra | Severidade |
|---|---|---|
| `.vscode/tasks.json` com `"runOptions": {"runOn": "folderOpen"}` | `projeto.abrir.tarefa_automatica` | MEDIUM; HIGH se o comando baixa e executa (`curl`/`wget`/`iwr`/`Invoke-WebRequest` + `sh`/`bash`/`iex`/`python`, ou base64 decodificado) |
| `.vscode/settings.json` apontando executável para dentro do projeto (`python.defaultInterpreterPath`, `*.path`, `terminal.integrated.env.*` com `PATH`/`NODE_OPTIONS`/`PYTHONSTARTUP`) | `projeto.abrir.executavel_do_projeto` | MEDIUM |
| `.claude/settings.json` e `.claude/settings.local.json` com `hooks` | `projeto.abrir.hook_agente` | MEDIUM; HIGH se o comando baixa e executa ou lê credenciais |
| `.claude/settings.json` com `permissions.allow` amplo (`Bash(*)`, `Bash`) ou `enableAllProjectMcpServers: true` | `projeto.abrir.permissao_ampla` | MEDIUM |
| `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` | `projeto.abrir.mcp` | LOW para qualquer servidor declarado (informativo); HIGH se o comando baixa e executa, ou usa `npx`/`uvx` de pacote com falha ou malicioso no OSV |
| `.devcontainer/devcontainer.json` com `postCreateCommand`, `postStartCommand`, `initializeCommand` (este roda **no host**) | `projeto.abrir.devcontainer` | `initializeCommand`: MEDIUM; os outros: LOW; HIGH se baixam e executam |
| `.git/hooks/*` executável sem `.sample`, ou `core.hooksPath` / `core.fsmonitor` / `core.sshCommand` em `.git/config` | `projeto.abrir.git_hook` | MEDIUM; HIGH se baixa e executa |

**Família 3: execução ao instalar dependências.**

| Arquivo | Regra | Severidade |
|---|---|---|
| `package.json` com `preinstall`, `install`, `postinstall` ou `prepare` | `projeto.instalar.script_npm` | LOW (informativo); HIGH se baixa e executa, usa `node -e` com base64 ou chama `.js` com ofuscação (reusar `script_heuristics`) |
| `setup.py` com rede (`urllib`, `requests`, `socket`, `subprocess` com `curl`) ou `exec`/`eval` de conteúdo decodificado no nível do módulo | `projeto.instalar.setup_py` | HIGH |
| `pyproject.toml` com `build-backend` apontando para módulo local (`backend-path`) | `projeto.instalar.backend_local` | LOW |

**Família 4: Trojan Source.** Em arquivos de código (`SCRIPT_EXT` + `.ts`, `.tsx`, `.jsx`, `.go`, `.rs`, `.java`, `.c`, `.cpp`, `.h`, `.cs`, `.kt`, `.swift`):

- `projeto.unicode.bidi` (HIGH): caracteres de controle bidirecional U+202A–U+202E e U+2066–U+2069 (CVE-2021-42574).
- `projeto.unicode.homoglifo` (MEDIUM): identificador que mistura escrita latina com cirílica ou grega na mesma palavra. Strings e comentários **não** contam.

**Família 5: CI inseguro.** Em `.github/workflows/*.yml` e `*.yaml`:

- `projeto.ci.pull_request_target` (HIGH): gatilho `pull_request_target` **e** `actions/checkout` com `ref` vindo do PR (`github.event.pull_request.head.*`, `github.head_ref`).
- `projeto.ci.injecao_expressao` (MEDIUM): `${{ github.event.issue.title }}`, `...body`, `...head_ref`, `...comment.body` ou similares direto dentro de `run:`.
- `projeto.ci.baixa_e_executa` (MEDIUM): `curl ... | sh` em `run:`.

"Baixa e executa" é **uma** função compartilhada (`abrir._baixa_e_executa(cmd) -> bool`), usada nas famílias 2, 3 e 5.

### Dependências

- **Lockfiles lidos:**
  - npm: `package-lock.json` (v1, v2, v3), `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (v1 e berry);
  - Python: `poetry.lock`, `uv.lock`, `Pipfile.lock`, e `requirements*.txt` **só com versão fixada** (`==`).
- Projetos com vários lockfiles (monorepo) entram todos, com o caminho do lockfile no achado.
- Sem lockfile, ou com versões não fixadas: o relatório diz "N dependências sem versão fixa não verificadas" e não tenta adivinhar.
- Cada pacote vira `InstalledPackage(binary_name=nome, source_name=nome, version=v, ecosystem="npm"|"PyPI")`. Nomes PyPI normalizados (PEP 503). Sem duplicatas.
- Consulta via `OsvClient.query_packages`. O cache fica na pasta de dados do usuário (Windows: a mesma do app; Linux: `~/.cache/mandacaru/`), não em `/var/lib`, porque roda sem root.
- **Pacote malicioso** (id `MAL-…`): `projeto.dep.malicioso`, **CRITICAL**, explicação "pacote catalogado como malicioso; não instale".
- **Falha conhecida:** `projeto.dep.vulneravel`, com severidade pelo `classify_finding` existente (CVSS e KEV). Na KEV vira CRITICAL. Mostra a versão que corrige, lida de `affected[].ranges[].events[].fixed` para o ecossistema.
- Um achado **por pacote e versão**, listando os ids (CVE/GHSA). Avisos redundantes saem com `drop_redundant_advisories`.

### Relatório e código de saída

- **Linha de comando:** agrupa por família e mostra, por achado, `SEVERIDADE  caminho:linha  explicação` e o trecho. No fim, um resumo: arquivos lidos, bibliotecas verificadas (ou "não verificadas: motivo") e totais por severidade.
- `--json` emite os achados como `Alert` (JSON Lines), como o `scan`.
- `--sem-rede` pula as dependências de propósito.
- **Código de saída:** `0` sem achados de MEDIUM ou mais; `2` com HIGH ou CRITICAL (mesma convenção do `scan`); `1` erro de uso.

### App Windows

- **Arrastar uma pasta** que tem marca de projeto (`.git`, `package.json`, `pyproject.toml`, `requirements*.txt`, um dos lockfiles, `.vscode` ou um arquivo de agente): roda a varredura antivírus de sempre **e** a verificação de projeto, e os achados de projeto aparecem na mesma lista com o tipo "Projeto". Ver a pergunta em aberto abaixo.
- **Botão "Verificar projeto…"** na aba Varredura, para escolher uma pasta.
- Ações por achado de projeto:
  - **Abrir local:** abre a pasta com o arquivo selecionado.
  - **Copiar detalhe:** caminho:linha, regra e explicação.
  - **Ignorar sempre:** grava na lista local de confiáveis a chave (regra, SHA-256 do arquivo). Se o arquivo mudar, o achado volta.
- **Sem botão de quarentena** para achados de projeto.
- **Progresso:** a barra mostra "Verificando projeto · 312 de 900 arquivos · 35%" e depois "Consultando bibliotecas no OSV.dev · 240 pacotes".

## Decidido com o dono

- Uso **antes de abrir o projeto**, pela linha de comando (`mandacaru dev`) e arrastando a pasta no app (2026-11-25).
- Bibliotecas **sempre** verificadas. Aparece só falha conhecida ou pacote malicioso, nunca "só desatualizada" (2026-11-25).
- Abordagem A, com verificador próprio (2026-11-25).

## Decisões minhas (o dono pode corrigir)

- **YAML com PyYAML, sempre `yaml.safe_load`.** Entra como dependência: `PyYAML>=6` no `pyproject.toml`, `python3-yaml` no `Depends` do `debian/control`, e o PyInstaller empacota. Um parser caseiro para entrada controlada pelo atacante seria mais arriscado que uma dependência pequena e madura. Para dar a **linha** do achado, o leitor de workflow usa `yaml.compose` (os nós trazem `start_mark.line`) em vez de reler o texto.
- **Achados LOW** (informativos: "este projeto tem `postinstall`", "declara servidor MCP") aparecem numa seção separada, "Para conhecimento", no fim do relatório, e não contam para o código de saída. No app, ficam recolhidos por padrão.
- **Caches do OSV e do KEV** ficam na mesma pasta de cache que o app Windows já usa em `updates.py` (`cache_dir/osv.db` e `kev.db`). No Linux, sem root, `~/.cache/mandacaru/`.
- **Limites:** 2 MB por arquivo e 20 mil arquivos por projeto, para não travar em monorepos gigantes. O relatório avisa quando cortar.

## Deixado para quem constrói

- Lista exata de frases de injection e de verbos imperativos (partir das regras existentes, em português e inglês).
- **Formato visual do relatório no terminal**, dentro do padrão do `scan`.
- **Testes:**
  - repositórios-fixture pequenos em `tests/projeto/fixtures/`, um por regra, com um caso limpo e um sujo;
  - um "projeto comum" (React e Django mínimos) que deve sair sem MEDIUM ou mais;
  - o próprio repositório do Mandacaru, que **não** pode dar HIGH;
  - o OSV com `http` falso, como nos testes do `vuln`.

## Em aberto (do dono)

- Arrastar uma pasta de projeto roda as duas verificações juntas, na mesma lista, ou só a de projeto? (ver mensagem)
