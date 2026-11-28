# Mandacaru para Windows

Interface gráfica (PySide6) do Mandacaru para Windows. Reaproveita o núcleo de
detecção do pacote `mandacaru-edr`.

## Instalar (usuário)

Baixe `Mandacaru-<versão>-setup.exe` na página de Releases e execute. Não
precisa de administrador: instala em `%LOCALAPPDATA%\Programs\Mandacaru`, cria
atalhos no Menu Iniciar (e opcionalmente na Área de Trabalho) e integra o menu
de contexto do Explorer (em `HKCU`, removido automaticamente ao desinstalar).
Desinstalar não apaga `%LOCALAPPDATA%\Mandacaru` (histórico, quarentena,
confiáveis e pastas ignoradas).

## Como usar cada funcionalidade

- **Varredura (`Varredura`):** clique em **Downloads**, **Área de Trabalho**,
  **Pasta…** ou arraste arquivos/pastas para a janela. Cada achado oferece:
  - **Analisar:** consulta somente o hash SHA-256 no Team Cymru MHR e no CIRCL
    hashlookup (gratuito, sem chave; o conteúdo do arquivo nunca sai da máquina).
  - **Abrir local:** seleciona o arquivo no Windows Explorer.
  - **Ignorar sempre:** grava o SHA-256 na lista de arquivos confiáveis.
  - **Quarentena:** isola o arquivo embaralhado na aba **Quarentena**, onde é
    possível **Analisar**, **Restaurar** (com checagem de hash) ou **Apagar**
    definitivamente (com sobrescrita aleatória).
- **Verificar projeto (desenvolvedores):** antes de abrir um repositório
  baixado no editor ou de rodar `npm install`, clique em **Verificar projeto…**
  e escolha a pasta. Arrastar para a janela uma pasta com cara de projeto (com
  `.git`, `package.json`, `pyproject.toml`, `AGENTS.md`, lockfiles e afins) roda
  a varredura antivírus e, em seguida, a verificação do projeto. São cinco
  famílias: instruções para agentes de IA (`AGENTS.md`, `CLAUDE.md`,
  `.cursorrules` com prompt injection ou Unicode invisível), o que executa ao
  abrir a pasta (tarefas do VS Code, servidores MCP, hooks do Claude Code e do
  Git, devcontainer), o que executa ao instalar dependências (`postinstall`,
  `setup.py`), código com Unicode enganoso (Trojan Source) e GitHub Actions
  inseguras. As bibliotecas fixadas nos lockfiles também são cruzadas com o
  OSV.dev e a CISA KEV. Aparece uma linha por arquivo, com **Abrir local**,
  **Copiar detalhe**, **Ignorar sempre** e **Quarentena** (habilitado para
  isolar apenas o arquivo perigoso do projeto e desabilitado com explicação
  quando a linha for apenas de biblioteca declarada em lockfile). **Ignorar
  sempre** vale só para aquele conteúdo: se o arquivo mudar, o achado volta.
  Quando houver achado de severidade **Alta** ou **Crítica**, a aba exibe um
  aviso fixo lembrando de fazer uma varredura completa e trocar chaves e tokens
  caso o projeto já tenha sido aberto ou instalado, junto com o botão
  **Destruir projeto…** para sobrescrever e apagar a pasta inteira. Os achados
  de severidade baixa ficam recolhidos em **Para conhecimento**. Só sai da
  máquina o ecossistema, o nome e a versão de cada biblioteca, enviados ao
  OSV.dev; o catálogo KEV é baixado inteiro. Nenhum caminho, conteúdo de arquivo
  ou nome de usuário sai da máquina, e as pastas ignoradas na aba **Confiáveis**
  ficam de fora também aqui.
- **Menu de contexto no Explorer (botão direito):**
  - **Varrer com Mandacaru** (`--scan`): aparece em arquivos, pastas e no fundo
    de pastas; se o Mandacaru já estiver aberto, encaminha a varredura para a
    janela ativa.
  - **Destruir definitivamente com Mandacaru** (`--shred`): aparece apenas no
    clique direto sobre arquivos ou pastas (nunca no fundo de pasta) e sempre
    pede confirmação na janela antes de apagar.
  - **No Windows 11:** use **`Shift + botão direito`** (ou clique em **Mostrar
    mais opções** / `Shift + F10`) para ver as opções do Mandacaru direto no
    menu clássico do Explorer.
- **Destruição segura (shred):** use o botão **Destruir pasta…** na aba
  *Varredura*, o atalho do botão direito no Explorer ou o botão **Apagar** na
  *Quarentena*. Cada arquivo é sobrescrito com bytes aleatórios (`fsync`),
  truncado para 0 bytes, renomeado para um nome aleatório e removido sem ir para
  a Lixeira. Raízes de unidade (`C:\`), pastas do sistema e a pasta do usuário
  são bloqueadas por segurança, e symlinks/junções nunca são seguidos.
- **Pastas ignoradas na varredura (`Confiáveis`):** abaixo da lista de arquivos
  confiáveis por hash, clique em **Adicionar pasta…** para excluir pastas da
  varredura (ex.: pastas de projetos ou jogos) e **Remover** para voltar a
  varrê-las.
- **Atualizações (`Atualizações`) e autoatualização:** verifica programas
  desatualizados/vulneráveis via `winget`, CISA KEV e NVD, atualiza os
  selecionados um por vez e avisa quando houver versão nova do próprio Mandacaru
  (também em **Ajuda → Verificar atualizações**).

## Montar (desenvolvedor)

Na raiz do repositório, em um Python 3.10–3.13 no Windows:

```powershell
pip install . "./windows[dev]"
cd windows
python -m pytest -q
pyinstaller mandacaru-win.spec --noconfirm   # gera dist\Mandacaru\
dist\Mandacaru\Mandacaru.exe --selftest       # código de saída 0 = ok
iscc /DMyAppVersion=0.5.0 installer.iss       # gera dist\installer\ (requer Inno Setup)
```

O CI (`.github/workflows/windows.yml`) faz o mesmo e, em tags `v*`, anexa o
instalador ao release criado pelo `release.yml`.
