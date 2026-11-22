# Mandacaru para Windows — design

Data: 2026-11-21 · Estado: rascunho para aprovação

## Intenção

Levar a detecção do Mandacaru (regras YARA, heurísticas de script, classificador) para quem usa Windows, com
uma janela amigável onde a pessoa dispara a varredura, acompanha o andamento e decide o que fazer com cada
achado. É um pacote **separado e independente**: a versão Linux não muda em nada.

## Objetivos

- Aplicativo de janela (PySide6) com:
  - atalhos **Downloads**, **Área de Trabalho** e **Pasta…**, e arrastar arquivos/pastas para a janela;
  - durante a varredura: barra de progresso, arquivo atual, contagem de arquivos e de achados, botão **Parar**;
  - lista de achados com severidade, nome do arquivo, motivo (regra YARA/heurística, técnica MITRE, razões do
    classificador) e três botões por linha: **Abrir local**, **Ignorar sempre**, **Quarentena**;
  - aba **Quarentena** com **Restaurar** e **Apagar**;
  - aba **Confiáveis** (a lista do "Ignorar sempre") com **Remover**;
  - aba **Histórico** com o resumo das últimas varreduras.
- Instalador por usuário, **sem pedir administrador**.
- Nada é movido ou apagado sem o clique da pessoa.

Esboço da tela principal:

```
┌ Mandacaru ───────────────────────────────┐
│ [Downloads] [Área de Trabalho] [Pasta…]  │
│ ████████░░░░ 62%  C:\Users\...\setup.exe │
│ 1.204 arquivos · 2 achados      [Parar]  │
├──────────────────────────────────────────┤
│ HIGH  fatura.js   YARA: js_dropper       │
│   [Abrir local] [Ignorar sempre] [Quar.] │
└──────────────────────────────────────────┘
  Abas: Varredura · Quarentena · Confiáveis · Histórico
```

## Fora do escopo (v1)

- Monitor em tempo real, serviço em segundo plano, inicialização com o Windows.
- Quarentena automática (fica para quando houver monitor em segundo plano).
- Varredura de vulnerabilidades, telemetria, socket de alertas, registro de decisões, ícone de bandeja.
- Atualização automática de regras/modelos (vêm no instalador; nova versão = novo instalador).
- Classificador para executáveis PE (`.exe`/`.dll`); no Windows ele só atua em scripts.
- Assinatura de código (sem certificado o SmartScreen mostra "Editor desconhecido").
- ARM64; só x64.
- Idiomas além do português.

## Anti-objetivos (seria fracasso mesmo funcionando)

- Qualquer alteração em `src/mandacaru/`, `packaging/`, `tests/` ou nos workflows existentes.
- Precisar de administrador para instalar ou varrer.
- Mover, apagar ou isolar arquivo sem o clique da pessoa.
- Janela travada durante a varredura.
- Quarentena que perde o arquivo (falha no meio do caminho tem que deixar o original intacto).

## Restrições verificadas

- **O núcleo importa no Windows.** Simulado em Linux bloqueando `grp`, `pwd` e `fcntl`:
  `mandacaru.detectors.static.StaticScanner` e `mandacaru.ml` importam e carregam as 7 regras. O pacote novo
  **não pode** importar `mandacaru.cli`, `quarantine`, `quarantine_cli`, `decisions` nem `alert_socket` (esses
  dependem de `grp`/`pwd`/`fcntl`/`AF_UNIX`).
- **yara-python** tem wheel `win_amd64` (4.5.4) para Python 3.10–3.13, **não para 3.14**. O build usa
  **Python 3.13**; como o PyInstaller embute o Python, o usuário não instala nada.
- `StaticScanner.scan_tree` só entrega alertas, sem aviso de progresso por arquivo. O pacote faz a própria
  caminhada de pastas (pulando os mesmos `.git`, `node_modules`, `__pycache__`, `.venv` e respeitando
  `is_excluded`) e chama `scanner.scan_file(path)` por arquivo. São poucas linhas duplicadas; preferível a mexer
  no núcleo.
- O núcleo lê no máximo 8 MiB de cada arquivo (`MAX_BYTES`); arquivos maiores são analisados só no começo.
- Classificador: a montagem dele está em `cli.py` (`build_classifier`), que não importa no Windows. O pacote
  replica a regra do scan avulso: `ml.load_default("alert")`; sem modelo instalado ou modelo inválido, segue
  sem classificador. O índice do dpkg (`DpkgKnownGood`) só é carregado no modo `isolate`, que não é usado aqui.
- **Hoje não existe modelo publicado** (`ml/models/` só tem README e `MODEL_SHA256` está vazio), e `ml/kind.py`
  só reconhece `elf, sh, python, perl, js, php` (não `.ps1`/`.bat`/`.vbs`/`.cmd`). *Decisão do autor:* a v1 sai
  efetivamente **sem classificador**; o gancho fica pronto (quando o núcleo passar a trazer modelo, o instalador
  o embute sem mudança no pacote Windows) e a interface mostra as razões do classificador só quando houver.
  Embarcar modelos exigiria mexer em `ml/__init__.py`, o que está vetado.
- Regras e modelos são *package data* de `mandacaru` (`rules/yara/*.yar`, `ml/models/*.json`), lidos via
  `importlib.resources`; o PyInstaller precisa incluí-los (`--collect-data mandacaru`).
- Licença: o projeto é GPL-3.0-or-later; PySide6 é LGPL, compatível.

## Abordagens consideradas

**Como reaproveitar a detecção**
1. *Escolhida:* pacote novo que importa o núcleo como biblioteca. Zero mudança no Linux.
2. Refatorar o núcleo para ficar portável (tirar `grp`/`pwd`/`fcntl` do caminho do `cli.py`). Descartada: mexe
   no código Linux, o que foi vetado.
3. Copiar o núcleo para o pacote novo. Descartada: duas cópias das regras e heurísticas divergindo com o tempo.

**Interface**
1. *Escolhida:* **PySide6 (Qt)**. Acompanha modo claro/escuro, alta resolução, arrastar e soltar nativo,
   botões por linha na lista. Custo: instalador de ~100 MB e dependência grande.
2. Tkinter (vem no Python). Instalador de ~30 MB, sem dependência nova, mas aparência datada, sem modo escuro,
   botões só para a linha selecionada e arrastar-soltar exige pacote extra.
3. pywebview + HTML. Mais flexível, mas duas linguagens, ponte Python↔JS e dependência do WebView2 — demais para
   uma tela.

**O que fazer ao detectar**
1. *Escolhida:* mostrar e deixar a pessoa decidir (Abrir local / Ignorar sempre / Quarentena).
2. Quarentena automática para HIGH ou mais. Descartada na v1: varredura é manual, a pessoa já está olhando.
3. Só relatório. Descartada: deixaria a remoção por conta do Explorer.

## Como fica

### Estrutura (nova, ao lado do código Linux)

```
windows/
  pyproject.toml            # name = "mandacaru-windows"; deps: mandacaru-edr, PySide6
  src/mandacaru_win/
    __main__.py             # abre a janela
    app.py                  # janela, abas, lista de achados
    worker.py               # varredura em thread (QThread), sinais de progresso
    store.py                # pasta de dados, lista de confiança, histórico
    quarantine.py           # mover/embaralhar, restaurar, apagar
  tests/
  mandacaru-win.spec        # PyInstaller
  installer.iss             # Inno Setup
.github/workflows/windows.yml   # novo; não altera ci.yml/deb.yml/release.yml
```

Instalação para desenvolvimento/build: `pip install . ./windows` a partir da raiz (o núcleo entra pelo
`pyproject.toml` da raiz; o `windows/pyproject.toml` só declara `mandacaru-edr` pelo nome).

### Varredura

- Uma varredura por vez; os botões de iniciar ficam desabilitados enquanto ela roda.
- O worker roda fora da thread da interface e emite: `progress(arquivo_atual, n_arquivos)`,
  `finding(alerta)`, `done(resumo)`. **Parar** liga uma flag checada entre arquivos.
- Achados de severidade `INFO` não aparecem; `LOW` em diante sim, ordenados por severidade.
- *Decisão do autor:* **uma linha por arquivo**, não por alerta. A linha mostra a pior severidade e, ao
  expandir, todos os motivos (YARA, heurística, classificador). Os botões agem sobre o arquivo, então agrupar
  evita "Quarentena" duas vezes no mesmo arquivo.
- Antes de mostrar um achado, calcula o SHA-256 do **arquivo inteiro** (leitura em blocos); se estiver na lista
  de confiança, descarta. Hash só de arquivos com achado, para não pesar a varredura. Hash inteiro (e não só
  dos 8 MiB lidos) para que um arquivo confiado e alterado depois volte a ser analisado.
- *Decisão do autor:* varre todos os tipos de arquivo, sem filtro de extensão (malware muda de extensão).
  **Pula arquivos só-online do OneDrive** (atributos `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`/`RECALL_ON_OPEN`/
  `OFFLINE` em `os.stat().st_file_attributes`), para não disparar download em massa, e **não entra em junções
  nem links de pasta** (pontos de reparse), para não sair da pasta escolhida nem entrar em laço.
- Arquivos sem permissão, em uso ou com caminho longo demais são pulados em silêncio (o núcleo já faz isso).

### Dados do usuário — `%LOCALAPPDATA%\Mandacaru\`

- `trust.json`: lista de `{sha256, caminho_quando_confiado, data}`. A decisão vale só pelo hash; o caminho é
  informativo, para a aba Confiáveis mostrar de onde veio.
- `history.jsonl`: uma linha por varredura (data, pastas, arquivos lidos, achados, duração,
  concluída/interrompida). A aba mostra as últimas 50.
- `quarantine\<id>.bin` + `quarantine\<id>.json` (caminho original, sha256, data, regra, severidade).

### Quarentena

- **Mover:** lê o original, grava `<id>.bin` com o conteúdo embaralhado (XOR com chave fixa, só para o arquivo
  não executar nem ser reconhecido por acidente), confere que gravou, grava o `.json` e **só então** apaga o
  original. Se apagar falhar (arquivo em uso), remove o `.bin`/`.json` e avisa: o original fica intacto.
- **Restaurar:** desembaralha para o caminho original; se já existir um arquivo lá, usa
  `nome (restaurado).ext`. Confere o sha256 antes de apagar a cópia da quarentena.
- **Apagar:** remove `.bin` e `.json`, com confirmação.
- *Decisão do autor:* o embaralhamento é só para não executar nem ser reconhecido por acidente; não há
  requisito de sigilo nem de impedir abuso da quarentena. Restaurar é decisão consciente da pessoa (pede
  confirmação dizendo que o arquivo foi marcado como suspeito); a pasta de dados é do próprio usuário.

### Ações na lista

- **Abrir local:** `explorer /select,<caminho>` (lista de argumentos, sem shell).
- **Ignorar sempre:** adiciona o sha256 à lista de confiança e tira o achado da lista.
- **Quarentena:** como acima; o achado sai da lista e aparece na aba Quarentena.

### Empacotamento

- PyInstaller em modo **pasta** (`onedir`, janela sem console): abre mais rápido que `onefile` e gera menos
  falso positivo de antivírus.
- Inno Setup com `PrivilegesRequired=lowest`, instalando em `{localappdata}\Programs\Mandacaru`, atalho no
  Menu Iniciar e desinstalador.
- Workflow `windows.yml` em `windows-latest`, Python 3.13: roda os testes, monta o `.exe` e o instalador e
  publica o instalador como artefato.
- *Decisão do autor:* gatilhos do `windows.yml`: PR e push em `main` que mexam em `windows/**` ou
  `src/mandacaru/**` (artefato do Actions), e tag `v*` (anexa o instalador ao GitHub Release da mesma tag, ao
  lado do `.deb`). A versão do instalador vem de `mandacaru.__version__`.
- O `.spec` exclui `psutil` e `watchdog` (dependências do núcleo que a varredura sob demanda não usa), para
  reduzir o instalador.

### Testes

- `quarantine`: ida e volta preserva os bytes; o original some só depois da cópia; falha ao apagar deixa tudo
  como estava; restaurar com o nome ocupado.
- `store`: lista de confiança e histórico (gravar, ler, remover).
- `worker`: uma pasta com um arquivo que dispara uma regra de `base.yar` (ex.: PowerShell com
  `-EncodedCommand`) gera o achado; arquivo confiado é descartado; **Parar** interrompe.
- Fumaça da janela com `QT_QPA_PLATFORM=offscreen` (constrói a janela e fecha).
- Os testes ficam em `windows/tests` com configuração de pytest própria no `windows/pyproject.toml`. No CI
  rodam só no `windows.yml` (o `ci.yml` não muda); localmente também rodam em Linux, exceto os que dependem de
  atributos do Windows (OneDrive, junções), que ficam marcados para pular fora do Windows.
- Verificação manual: instalar no Windows de verdade (a máquina de desenvolvimento roda WSL2 sobre Windows, dá
  para testar no host).

## Escolhas que ficam com o implementador

- Estilo visual do Qt (padrão do Windows 11 ou `Fusion`), ícones, cores das severidades.
- Detalhes do layout das abas e da lista, desde que mantenham o esboço acima.
- Nome exato dos sinais/classes internas.
- Versão do pacote: seguir `mandacaru.__version__`.
