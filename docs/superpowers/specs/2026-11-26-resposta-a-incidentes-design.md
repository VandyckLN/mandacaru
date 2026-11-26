# Resposta a incidentes em cadeia no Windows: conter, neutralizar, recuperar

Data: 2026-11-26 · Estado: **aprovado pelo dono** (substitui o rascunho [2026-11-26-resposta-a-incidentes-rascunho.md](2026-11-26-resposta-a-incidentes-rascunho.md))

## Por quê

Hoje o Mandacaru detecta e avisa (varredura estática, verificação de projetos, análise de hash, CVEs/KEV). Quando encontra algo crítico — malware confirmado, pacote malicioso `MAL-`, projeto armado ou programa com falha já explorada —, a pessoa ainda precisa decidir sozinha o que fazer e em qual ordem.

Este design define uma **cadeia de resposta a incidentes** no app do Windows (`windows/src/mandacaru_win/`) organizada em três fases:

1. **Conter** a ameaça, para que ela pare de agir e não se espalhe;
2. **Neutralizar** a ameaça, removendo arquivo, persistência e brecha;
3. **Recuperar** a máquina com varredura, troca orientada de credenciais e relatório do incidente.

## Objetivos

- **Modo misto:** contenção **automática e imediata** apenas nos critérios estreitos de **certeza alta**, com notificação na bandeja e opção **Desfazer** nas ações reversíveis; nos demais casos, **fluxo guiado** com os passos pré-selecionados para confirmação.
- **Separação de privilégio (abordagem C):** a janela PySide6 continua **sem privilégio**. Um **serviço do Windows opcional** ("Proteção avançada"), escolhido uma única vez no instalador, executa apenas uma lista fechada de ações privilegiadas via canal protegido (`named pipe` com ACL).
- **Transparência sem Proteção avançada:** quem não instalou o serviço continua usando todas as ações de usuário normalmente; as ações que exigem administrador aparecem desabilitadas com o selo *"Requer Proteção avançada"* e instrução de como ativar no instalador.
- **Rastreabilidade e reversibilidade:** toda ação (automática ou guiada) é gravada no registro do incidente (`%LOCALAPPDATA%\Mandacaru\incidents\<id>.json`) com data, motivo, resultado e backup para **Desfazer** quando aplicável.
- **Relatório exportável com privacidade:** exportação em HTML autocontido ou JSON, com a opção **"Ocultar nome de usuário e caminhos pessoais"** marcada por padrão.
- **Entrega incremental** em 5 marcos independentes e testáveis.

## Não-objetivos (fora da v1)

- **Linux:** a cadeia de resposta entra primeiro no app do Windows; Linux fica para uma etapa posterior.
- **Rootkits de kernel e processos protegidos (PPL):** atingir esse nível exige driver assinado pela Microsoft. Nesses casos, o Mandacaru assume o limite e orienta desconectar a rede, fazer backup e reinstalar o sistema.
- **Isolamento global da máquina via firewall:** fica fora da v1 (entra na v2, quando o serviço privilegiado estiver amadurecido em campo). Na v1, o serviço bloqueia apenas o executável suspeito; em casos graves, o app orienta desligar Wi-Fi/cabo manualmente.
- **Persistência em WMI Event Subscriptions e extensões de navegador:** ficam para a v2 (na v1, a fase *Recuperar* orienta revisar extensões quando relevante).
- **Envio direto do relatório por e-mail/webhook/MISP:** na v1 o relatório é salvo localmente e exportável para arquivo (HTML/JSON).
- **Leitura de conteúdo de credenciais:** o Mandacaru nunca lê conteúdo de `.env`, chaves privadas ou cookies do navegador; apenas orienta a troca.

## Anti-objetivos (seria falha mesmo funcionando)

- O serviço privilegiado virar um vetor de escalação de privilégio (aceitar comandos arbitrários, encerrar qualquer PID sem validação ou apagar caminhos fora das áreas permitidas).
- Encerrar ou bloquear automaticamente um programa legítimo por falso positivo (ex.: CVE/KEV de navegador ou regra YARA genérica de técnica).
- Bloquear a rede de um executável sem caminho claro e imediato para **Desfazer**.
- Qualquer ação automática sem registro no incidente ou sem notificação ao usuário.
- Induzir a pessoa a achar que "destruir a pasta resolveu" quando o projeto ou arquivo já tinha sido executado.

## Restrições

- Windows 10 1809+ ou 11 (x64), PySide6 e Python 3.10–3.13. Instalador Inno Setup sem assinatura digital paga (SmartScreen avisa na primeira instalação).
- A janela nunca roda elevada como administrador.
- O serviço **Proteção avançada** é mínimo:
  - aceita somente ações de uma lista fechada com parâmetros estritamente validados (PID, caminho absoluto canônico dentro de áreas permitidas, nome de regra de firewall com prefixo `Mandacaru-`, entrada de persistência validada);
  - nunca lê conteúdo de arquivos suspeitos nem abre conexões de rede; toda detecção e análise continua na janela sem privilégio.
- Textos da interface em português brasileiro com acentos.
- Todos os testes rodam sem rede e sem privilégio de administrador (o serviço e o canal IPC são testados com alvos falsos/injetados).

## Abordagens consideradas

**Privilégio (decidida pelo dono):**
1. **Escolhida — Abordagem C (serviço opcional "Proteção avançada"):** instalador pede admin uma única vez só para quem marcar a opção; janela segue sem privilégio e fala com o serviço por `named pipe` com ACL.
2. *Descartada — Abordagem A (rodar o app inteiro como admin):* qualquer bug em parser exporia a máquina inteira e o UAC apareceria a cada abertura.
3. *Descartada — Abordagem B (UAC a cada ação):* inviabiliza a contenção automática.

**Automação da contenção:**
1. **Escolhida — Imediata com notificação e Desfazer:** malware ativo (infostealer/ransomware) age em poucos segundos e pode disparar durante varredura em segundo plano. Como o critério de certeza alta é estreito e quarentena + regra de firewall são reversíveis em 1 clique, agir na hora oferece melhor proteção.
2. *Descartada — Contagem regressiva de 10 s:* abre janela para exfiltração/criptografia e perde efeito quando o usuário está longe da tela.

## Desenho

### 1. Critérios de certeza alta (únicos que disparam contenção automática)

| Gatilho | Condição exata | Trava de segurança |
|---|---|---|
| **Hash malicioso confirmado** | `analysis.analyze()` retorna `verdict == "malicioso"` (Team Cymru MHR e, se configurados, MalwareBazaar ou VirusTotal) | Se CIRCL hashlookup retornar `legitimo_conhecido`, **nunca** dispara automático |
| **Pacote malicioso (`MAL-`)** | Achado `projeto.dep.malicioso` (OSV `MAL-*`) em projeto ou servidor MCP | Validação do lockfile/manifesto já feita em `src/mandacaru/projeto/dependencias.py` |
| **Regra YARA de família `CRITICAL`** | Regra com `severity = "CRITICAL"` **e** marcação explícita de família/contenção automática no `meta` (ex.: `family` / `auto_contain = true`) | Regras genéricas de técnica (como `Reverse_Shell_Patterns` em `base.yar`) **não** disparam contenção automática |

Todo o restante — **CVE (mesmo listada na CISA KEV com processo em execução)**, achados gerais de projeto, heurísticas de script e classificador de IA — entra sempre no **fluxo guiado**.

### 2. A cadeia de ações (Conter → Neutralizar → Recuperar)

| Fase | Ação | Quem executa | Automática com certeza alta? | Reversível (Desfazer)? |
|---|---|---|---|---|
| **Conter** | Encerrar processo e processos filhos | Serviço (qualquer processo não-PPL) ou app (processos do usuário) | Sim (imediata) | Não |
| **Conter** | Quarentena do arquivo suspeito | App (perfil do usuário) ou serviço (caminhos do sistema) | Sim (imediata) | Sim (restaurar com conferência de SHA-256) |
| **Conter** | Bloquear rede do executável (regra de firewall de saída `Mandacaru-<id>`) | Serviço (*Proteção avançada*) | Sim (imediata) | **Sim** (remover regra `Mandacaru-<id>` em 1 clique) |
| **Conter** | Orientação para desconectar rede manualmente (casos graves / suspeita de rootkit ou PPL) | App (orientação) | Não | Não se aplica |
| **Neutralizar** | Remover persistência ligada ao incidente: `Run`/`RunOnce` (`HKCU`/`HKLM`), pasta `Inicializar`, tarefas agendadas e serviços do Windows | App (`HKCU`, Inicializar e tarefas do usuário) ou serviço (`HKLM`, tarefas do sistema, serviços) | Não (guiada) | **Sim** (backup da entrada salvo no incidente) |
| **Neutralizar** | Quarentena apenas do arquivo perigoso de um projeto (`tasks.json`, hook git, `setup.py`, etc.) | App | Não (guiada) | Sim |
| **Neutralizar** | Destruir projeto armado (`shred_path`, já seguro contra hard links) | App | Não (guiada, com confirmação) | Não |
| **Neutralizar** | Atualizar programa vulnerável (`winget`, reaproveitando `updates.py`) | App | Não (guiada) | Não |
| **Recuperar** | Varredura completa (em lotes leves) | App | Sugerida | Não se aplica |
| **Recuperar** | Checklist marcável de credenciais para trocar + links oficiais fixos sob clique | App | Não se aplica | Estado salvo no incidente |
| **Recuperar** | Relatório do incidente (JSON local + exportação HTML/JSON sanitizada) | App | Sempre registrado | Não se aplica |

### 3. Painel "Resposta a incidente" na interface

- Abre a partir de um achado crítico/alto (ou automaticamente na bandeja quando a contenção automática agir), mostrando as **três fases em ordem** (**1. Conter**, **2. Neutralizar**, **3. Recuperar**).
- Cada passo mostra:
  - estado visual (`Feito automaticamente`, `Concluído`, `Pendente`, `Falhou`, `Requer Proteção avançada`);
  - botão de ação (ou **Desfazer**, quando reversível);
  - detalhes técnicos expansíveis (PID, caminho, nome da regra de firewall, entrada de persistência).
- **Aviso fixo em projetos HIGH/CRITICAL:** sempre exibido no topo quando o incidente vier de verificação de projeto:
  > *"Se você já abriu ou instalou este projeto, faça uma varredura completa e troque chaves e tokens. Destruir a pasta não desfaz o que já foi executado."*
- **Sem Proteção avançada:** passos elevados aparecem visíveis, porém desabilitados com o selo *"Requer Proteção avançada"* e link de ajuda explicando como ativá-la executando o instalador novamente.

### 4. Persistência na v1

- O detector de persistência procura **somente entradas associadas ao incidente** (referência ao caminho/executável/pasta detectada ou hash correspondente), nunca listando programas legítimos aleatórios do usuário:
  1. Registro `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` e `RunOnce` (app, sem admin);
  2. Registro `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` e `RunOnce` (serviço);
  3. Pasta `Inicializar` do usuário (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, app) e global (serviço);
  4. Tarefas agendadas do Windows (consulta `schtasks` / Task Scheduler; remoção de tarefas do usuário no app e tarefas do sistema no serviço);
  5. Serviços do Windows apontando para o executável do incidente (parar e desabilitar/remover via serviço *Proteção avançada*).
- Antes de remover qualquer entrada, o valor original completo é salvo em `incidents\<id>.json` para permitir **Desfazer**.

### 5. Checklist de credenciais (fase Recuperar)

- Montada conforme o tipo de ameaça (ex.: projeto/agente de IA destaca SSH, `.env`, GitHub, npm, PyPI, nuvem; malware/infostealer destaca navegador, Google, Microsoft, bancos e chaves).
- Cada item tem caixa de seleção persistida no incidente (para a pessoa acompanhar o que já trocou).
- Para provedores principais (**GitHub, Google, Microsoft, AWS, npm, PyPI**), exibe botão discreto *"Abrir página"* apontando para uma **tabela fixa e auditada de URLs HTTPS oficiais** no código.
- Nunca abre abas automaticamente e nunca lê o conteúdo de arquivos de credenciais.

### 6. Registro e exportação de relatório

- **Registro local:** `%LOCALAPPDATA%\Mandacaru\incidents\<id>.json` (gravação atômica com `fsync`, mesmo padrão de `store.py`), contendo: id, data/hora, origem (varredura, projeto, atualizações), achados (regras, severidade, MITRE, SHA-256), linha do tempo de ações (automática vs guiada, resultado, timestamp), backups para Desfazer e progresso da checklist de credenciais.
- **Exportação:** botão **"Exportar relatório…"** permite escolher **HTML autocontido** (sem recursos externos, imprimível em PDF) ou **JSON**.
- **Sanitização padrão:** caixa **"Ocultar nome de usuário e caminhos pessoais"** marcada por padrão ao exportar — substitui `C:\Users\<usuario>` por `%USERPROFILE%` e omite hostname/usuário, preservando hashes, regras, técnicas MITRE e ações tomadas.

### 7. Serviço opcional "Proteção avançada" (marco d)

- Instalável de forma opcional no `windows/installer.iss` (quem não marcar mantém `PrivilegesRequired=lowest` por usuário; quem marcar eleva uma única vez para instalar o serviço `MandacaruGuard`).
- Comunicação por `named pipe` (`\\.\pipe\MandacaruGuard`) com ACL restrita ao usuário local interativo / grupo autorizado e verificação do PID do cliente conectado (confere que o executável cliente é o `Mandacaru.exe` instalado).
- **Protocolo JSON fechado (únicas ações aceitas):**
  - `ping` → versão e status do serviço;
  - `terminate_process(pid, exe_path, sha256)` → valida que o PID atual ainda corresponde ao `exe_path` e `sha256` antes de encerrar (evita corrida de reutilização de PID);
  - `quarantine_file(path, sha256)` → valida caminho fora de diretórios críticos do Windows e confere `sha256` antes de mover;
  - `firewall_block(rule_id, exe_path)` / `firewall_unblock(rule_id)` → aceita apenas nomes `Mandacaru-<hex>` e caminho absoluto de executável existente;
  - `persistence_remove(kind, ref)` / `persistence_restore(backup)` → apenas `hklm_run`, `startup_all`, `schtask`, `service`, sempre com validação estrita.
- Ao desinstalar o serviço, remove todas as regras de firewall com prefixo `Mandacaru-`.

## Decidido com o dono

1. **Plataforma e arquitetura:** Windows primeiro; modo misto; serviço opcional *Proteção avançada* (abordagem C); rootkits/PPL fora do teto (orientação manual).
2. **Critérios de certeza alta:** lista estreita — hash malicioso confirmado (com trava negativa do CIRCL), pacote `MAL-` no OSV e regra YARA específica de família marcada `CRITICAL`. CVE/KEV fica guiada.
3. **Automação na prática:** age imediatamente e avisa depois (notificação na bandeja + painel com **Desfazer**); bloqueio de rede do executável sempre reversível.
4. **Isolamento completo da máquina:** fora da v1 (entra na v2); na v1 o serviço bloqueia só o executável e o app orienta desligar Wi-Fi/cabo.
5. **Sem a Proteção avançada:** executa ações de usuário normalmente e mostra as demais desabilitadas com *"Requer Proteção avançada"* e como ativar.
6. **Persistência na v1:** `Run`/`RunOnce` (HKCU/HKLM), pasta `Inicializar`, tarefas agendadas e serviços do Windows (com Proteção avançada); WMI e extensões de navegador na v2.
7. **Credenciais:** checklist marcável salva no incidente + links oficiais fixos sob clique (GitHub, Google, Microsoft, AWS, npm, PyPI).
8. **Relatório:** salvo localmente em JSON + botão *"Exportar relatório…"* (HTML autocontido ou JSON) com opção de sanitizar usuário/caminhos marcada por padrão.
9. **Ordem de entrega:** incremental `(a) → (b) → (c) → (d) → (e)`.

## Ordem de entrega e divisão de trabalho (Antigravity + Claude)

O desenvolvimento segue na ordem **(a) → (b) → (c) → (d) → (e)**, dividido entre **Antigravity** e **Claude** com fronteiras claras de arquivos e revisão cruzada a cada PR:

| Marco | Escopo | Implementação | Revisão / Integração | Fronteira de arquivos |
|---|---|---|---|---|
| **Marco (a)** | Release **`0.8.3`** publicando a correção de hard link no Destruir (`shred.py`, PR #24) + `mandacaru dev <pasta>`, junto com este spec aprovado e o plano do Marco (b) | **Antigravity** | Dono / Claude | `CHANGELOG.md`, `debian/changelog`, `__init__.py`, `windows/pyproject.toml`, `README.md`, `docs/superpowers/` |
| **Marco (b)** | Ações diretas em projetos: endurecer `Quarantine` contra symlink/junção, botão **Quarentena** por arquivo de projeto, faixa de aviso fixo (`HIGH`/`CRITICAL`) e botão **Destruir projeto…** ([plano detalhado](../plans/2026-11-26-resposta-incidentes-marco-b.md)) | **Antigravity** | **Claude** (revisão do PR focada em TOCTOU, links e UX) | `windows/src/mandacaru_win/{quarantine,theme,app}.py`, `windows/tests/test_{quarantine,projeto_app,widgets}.py` |
| **Marco (c)** | Painel **Resposta a incidente** (3 fases, ações de usuário) dividido em duas frentes sem conflito:<br>• **c.1 Motor de usuário (sem Qt):** registro `incidents/*.json`, encerrar processos do usuário, persistência `HKCU`/Inicializar/tarefas com backup/Desfazer, checklist de credenciais e exportação HTML/JSON sanitizada.<br>• **c.2 Interface PySide6:** painel das 3 fases, selo *"Requer Proteção avançada"*, integração com `winget`/varredura e diálogo de exportação. | **Claude** implementa **c.1**<br>**Antigravity** implementa **c.2** | Revisão mútua entre os dois | **c.1:** `windows/src/mandacaru_win/incident*.py` (puro Python)<br>**c.2:** `windows/src/mandacaru_win/incident_ui.py` e `app.py` |
| **Marco (d)** | Serviço opcional **Proteção avançada**: serviço Windows mínimo, `named pipe` com ACL, validação estrita de PID/SHA-256/caminhos, firewall reversível (`Mandacaru-*`), `HKLM`/serviços + opção no `installer.iss` | **Claude** implementa o serviço e protocolo IPC;<br>**Antigravity** integra na UI, ajusta `installer.iss` e valida o instalador no CI | Auditoria cruzada obrigatória de segurança (anti-escalação de privilégio) | **Serviço:** `windows/src/mandacaru_win/guard_service.py` (e protocolo)<br>**UI/Setup:** `app.py`, `installer.iss` |
| **Marco (e)** | **Modo misto (automação):** disparo imediato nos 3 critérios de certeza alta (hash malicioso com trava CIRCL, `MAL-`, YARA de família `CRITICAL`), notificação na bandeja e **Desfazer** | **Claude** (regras de disparo/motor) + **Antigravity** (fluxo em segundo plano/bandeja/UI) | Revisão dupla contra falsos positivos + validação manual do dono no Windows | `incident*.py`, `worker.py`, `app.py` |

## Testes

- **Sem rede e sem admin:** toda lógica de decisão (certeza alta vs guiado, trava CIRCL, persistência, checklist, sanitização/exportação HTML e JSON, validação de parâmetros do serviço e protocolo IPC) é testada em Python puro com alvos falsos/injetados.
- **UI (PySide6 `offscreen`):** abertura do painel nas 3 fases, estados das ações, **Desfazer**, modo sem Proteção avançada, marcação da checklist e exportação de relatório.
- **Verificação manual no Windows real:** a cada marco, validar no host Windows (incluindo instalação sem admin vs com Proteção avançada no marco d).
