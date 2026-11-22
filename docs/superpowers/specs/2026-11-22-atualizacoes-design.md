# Atualizações: programas desatualizados/vulneráveis e autoatualização do Mandacaru

Data: 2026-11-22 · Estado: aprovado (2026-11-22)

## Por quê

O Mandacaru detecta malware, mas o caminho mais comum de invasão num computador doméstico é um programa velho com falha conhecida (navegador, leitor de PDF, 7-Zip, Java...). A usuária-alvo é a **Mariana**: Windows, instala o Mandacaru pelo `Mandacaru-X-setup.exe`, não usa terminal. Ela precisa:

1. saber, num clique, se os programas dela estão em dia e quais têm falha conhecida;
2. atualizar o que importa sem entender `winget`, sem caçar instaladores;
3. receber as versões novas do próprio Mandacaru sem reinstalar à mão.

O administrador (Linux, e também Windows) é o segundo público: quer relatório e atualizar de forma controlada.

## Objetivos

- **Varredura rápida** (segundos): lista programas com versão nova e marca os que têm falha **já explorada** (CISA KEV). Não altera nada.
- **Varredura minuciosa** (minutos): a rápida + consulta CVEs por programa (NVD) + mostra atualizações pendentes do Windows. Não altera nada.
- **Atualizar selecionados**: lista com caixas; os vulneráveis vêm pré-marcados; a pessoa desmarca o que quiser e clica uma vez.
- **Autoatualização do Mandacaru** (Windows): faixa "versão X disponível" → um clique → baixa, confere hash, instala em silêncio, reabre.
- **Linux**: o `mandacaru vuln scan` existente passa a listar também o que está desatualizado (apt, Snap, Flatpak) e ganha "atualizar selecionados" com senha de administrador.

## Não-objetivos

- Instalar atualizações do **Windows Update** pelo Mandacaru. Só lemos o que está pendente e oferecemos um botão que abre *Configurações → Windows Update*.
- Atualizar programas que o `winget` não conhece. Aparecem como "atualize pelo próprio programa", sem botão.
- Atualizar o Mandacaru sem a pessoa ver (atualização silenciosa sem aviso).
- Gerenciar frotas / várias máquinas.

## Anti-objetivos (seria falha mesmo funcionando)

- Atualizar algo que a pessoa não marcou.
- Dar ao serviço root do Linux acesso à rede, ou ao processo com rede privilégio de root (desfaz a separação da 0.5: `_mandacaru-net` sem privilégio, root sem rede).
- Instalar um `setup.exe` cujo hash não bate com o publicado.
- Alarmar à toa: chamar de "vulnerável" um programa por coincidência de nome sem dizer que é uma suspeita.

## Restrições

- Windows 10 1809+ / 11, x64, instalador **por usuário sem administrador** (`PrivilegesRequired=lowest`, `AppId` fixo em `windows/installer.iss`). Rodar um setup novo atualiza por cima.
- App gráfico em PySide6 (`windows/src/mandacaru_win/`); trabalho pesado sempre fora da thread da interface (padrão `worker.py` / `ScanThread`).
- `mandacaru_win.__version__` == `mandacaru.__version__` (teste `test_version_matches_core`).
- NVD sem chave: ~5 requisições / 30 s. Cache obrigatório.
- Linux: atualizar exige root; usar `pkexec` + polkit como já faz a quarentena (`packaging/polkit/`, `packaging/libexec/`), com auxiliar que aceita só argumentos validados.
- Privacidade: a lista de programas instalados **não sai da máquina**, exceto as consultas mínimas à NVD (nome do produto e versão) na varredura minuciosa, que a pessoa inicia.

## Abordagens consideradas

1. **`winget` como base** — *escolhida.* `winget upgrade` lista o que tem versão nova e o mesmo `winget` instala, pelas fontes oficiais. Rápida = `winget` + KEV; minuciosa = + NVD + Windows Update (leitura). Contra: programas fora do `winget` não se atualizam; NVD é lenta e casa nomes de forma imperfeita.
2. Inventário próprio pelo registro + NVD — descartada: enxerga mais, mas não sabe atualizar (teria de baixar instaladores de cada fabricante).
3. Chocolatey / Patch My PC — descartada: outra dependência e outra fonte de confiança.

A usuária escolheu, para a ação de atualizar: **lista com os vulneráveis pré-marcados + "Atualizar selecionados"** (contra "atualizar tudo" e "só indicar").

## Desenho

### Parte 1 — Autoatualização do Mandacaru (Windows) — primeira entrega

- Ao abrir o app e no máximo 1×/24 h (carimbo em `%LOCALAPPDATA%\Mandacaru\update.json`), uma thread consulta `https://api.github.com/repos/VandyckLN/mandacaru/releases/latest`.
- Se `tag_name` > versão atual (comparação de versão, não de texto) e existir o asset `Mandacaru-<versão>-setup.exe`, mostra a faixa no topo da janela: "Mandacaru X disponível (você tem Y). [Atualizar agora] [Depois]". "Depois" esconde até a próxima versão nova ou 7 dias.
- **Atualizar agora**: baixa o asset para `%LOCALAPPDATA%\Mandacaru\updates\`, compara o SHA-256 com o campo `digest` do asset na API do GitHub; diferente → apaga, avisa, não instala. Igual → executa `setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART` e fecha o app; o `[Run]` do instalador reabre o Mandacaru (ajustar o `installer.iss` para reabrir também no modo silencioso de atualização).
- Falha de rede = silêncio (sem faixa). Nada roda sem o clique.
- Menu/botão "Verificar atualizações" força a consulta.
- Próximo passo recomendado, fora deste escopo: assinar o instalador (Authenticode) e verificar a assinatura antes de instalar — o hash só protege o transporte, não uma release falsa.

### Parte 2 — Programas desatualizados e vulneráveis (Windows)

Nova aba **"Atualizações"** no app, com dois botões: **Verificação rápida** e **Verificação completa**.

**Inventário/atualizações**: `winget upgrade --include-unknown --accept-source-agreements` com saída estruturada (ver "Para o builder"), produzindo `(nome, id winget, versão instalada, versão disponível, fonte)`.

**Rápida**: cruza cada item com o KEV pelo par `vendorProject`/`product` do catálogo (normalizado: minúsculas, sem pontuação/sufixos como "Inc."). O `KevCache` passa a guardar também `vendorProject`, `product`, `cveID`, `dateAdded` (hoje guarda só CVEs). Usa o cache se a rede falhar.

*Decisão do builder-check (chamada minha):* o KEV não traz versões, então na rápida o casamento é por produto. Como todo item da lista **já tem versão nova disponível**, pré-marcar um falso positivo custa pouco (atualiza algo que já estava velho). Regra: item desatualizado + produto no KEV → risco **"Explorada (produto)"**, pré-marcado, com o texto "este programa tem falhas usadas em ataques; versões antigas podem estar afetadas — atualizar é a correção recomendada". Se uma varredura completa anterior deixou em cache o CPE e as faixas de versão, a rápida usa isso e diz **"Explorada"** (casamento forte). "Suspeita" fica só para casamento de nome fraco (similaridade, não igualdade normalizada) e não é pré-marcada.

**Completa**: a rápida + para cada item, consulta NVD (`/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:<vendor>:<product>:<versão>`) com cache SQLite de 24 h e respeito ao limite (fila com espera); CPE vendor/product obtidos do dicionário de CPE da NVD pelo nome do programa, guardando o mapeamento em cache. Mostra o pior CVSS e a contagem de CVEs; KEV destacado. Também lê as atualizações pendentes do Windows via COM `Microsoft.Update.Session` (`IUpdateSearcher.Search("IsInstalled=0 and IsHidden=0")`, não exige administrador) e mostra quantas e quais são de segurança, com botão "Abrir Windows Update" (`ms-settings:windowsupdate`).

**Lista**: colunas ☐ · Programa · Instalada → Disponível · Risco (Explorada / Alta / Média / Sem CVE conhecida / Suspeita). Pré-marcados: tudo com risco Explorada ou Alta. Botão **Atualizar selecionados** → para cada id, `winget upgrade --id <id> --exact --silent --accept-package-agreements --accept-source-agreements`, um por vez, com progresso e resultado por linha (ok / falhou / precisa fechar o programa). O UAC pode aparecer para programas instalados para todos os usuários — o texto avisa antes.

**Sem winget**: mensagem explicando e botão para a página do "Instalador de Aplicativo" na Microsoft Store.

Histórico: cada atualização feita vai para o `History` existente.

### Parte 3 — Linux

*Decisão do builder-check (chamada minha):* o `mandacaru vuln scan`, o `mandacaru-vuln-scan.service`, o formato do `last-scan.json` e o `publish.py` **não mudam**. Tudo novo vai num subcomando próprio, rodado à mão pela pessoa (não pelo serviço, que não tem `$HOME` nem sessão para Snap/Flatpak de usuário):

- `mandacaru atualizacoes listar [--completo] [--json]`
  - Desatualizados: `apt list --upgradable` (sem root; mostra a data do último `apt update` e avisa se tiver mais de 24 h), `snap refresh --list`, `flatpak remote-ls --updates` (sistema e usuário; cada fonte só se o comando existir). Nomes são os **binários** que o gerenciador atualiza (`libssl3`, não `openssl`).
  - Risco: cada pacote binário apt é ligado ao seu pacote-fonte (já feito em `inventory.parse_dpkg_status`) e herda a pior prioridade dos achados do OSV/KEV desse fonte. Rápida (padrão): usa o relatório do último `vuln scan` (`last-scan.json`) e o cache, sem rede; se não houver relatório, diz "rode com --completo para ver as falhas". `--completo`: roda o fluxo OSV/KEV atual na hora.
  - Saída: tabela com `*` nos pré-selecionados (prioridade `CRITICAL_ACTIVE`/`HIGH`); `--json` com objetos `{gerenciador, nome, instalada, disponivel, risco, cves, selecionado}`. Não gera alertas nem popups; código de saída 0 (nada pendente), 2 (há itens de risco alto), 1 (erro).
- `mandacaru atualizacoes aplicar (--selecionados | <nome>...) [--sim]`: sem `--sim`, mostra a lista e pede confirmação (s/N). Pacotes apt, Snap e Flatpak de sistema vão pelo auxiliar com `pkexec` (abaixo); Flatpak de usuário roda `flatpak update --user -y <ids>` direto, sem senha.
- Auxiliar `/usr/libexec/mandacaru/update-packages apt|snap|flatpak <nomes>`: revalida nomes (`^[a-z0-9][a-z0-9+.-]*$` para apt; formatos próprios para snap/flatpak), executa só `apt-get install --only-upgrade -y <nomes>`, `snap refresh <nomes>` ou `flatpak update --system -y <ids>`. Nova ação polkit `io.github.vandyckln.mandacaru.update`, `auth_admin` sempre, sem regra de grupo.

**Decisão do dono (2026-11-22): opção A — exceção controlada.** O auxiliar `update-packages` roda como root **com rede**, só por pedido explícito da pessoa e com senha de administrador a cada vez. Ele executa apenas `apt-get install --only-upgrade`, `snap refresh` ou `flatpak update --system` com nomes revalidados, nunca outro comando. A regra da 0.5 continua valendo para o que roda sozinho: o `mandacaru.service` (root) segue sem rede e o `_mandacaru-net` segue sem privilégio. Descartada a opção B (baixar como `_mandacaru-net` e instalar como root sem rede): mais complexa e inviável para Snap/Flatpak.
- O serviço `mandacaru.service` (root, sem rede) não muda.
- Sem interface gráfica Linux nesta etapa.

## O que fica com o builder

- Formato de saída do `winget` (preferir `winget export`/JSON ou o módulo `Microsoft.WinGet.Client` do PowerShell; o texto tabular muda com idioma e largura do terminal — não fazer parse de colunas sem fixar largura e locale).
- Normalização de nomes para casar com KEV/CPE e o limiar de "suspeita".
- Layout exato da aba e da faixa, seguindo o estilo atual do `app.py`.
- Estrutura dos testes (mocks de `winget`, NVD, KEV, API do GitHub; o padrão atual injeta `http` e funções).

## Entregas

1. PR: autoatualização (Parte 1) + `installer.iss` reabrindo após atualização silenciosa.
2. PR: aba Atualizações (Parte 2) + `KevCache` com vendor/product.
3. PR: Linux (Parte 3) + polkit/auxiliar + `.deb`.
