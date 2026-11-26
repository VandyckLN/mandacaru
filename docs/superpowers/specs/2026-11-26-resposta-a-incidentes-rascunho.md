# Resposta a incidentes em cadeia no Windows: conter, neutralizar, recuperar

Data: 2026-11-26 · Estado: **rascunho para amadurecer**. Nada aprovado para implementação.

> **Para o agente que vai continuar:** este documento registra o que o dono do projeto (VandyckLN) já decidiu e o que está em aberto. Antes de escrever qualquer código, amadureça a ideia com ele:
>
> 1. Leia este arquivo e as partes do código citadas em "Ponto de partida".
> 2. Faça as perguntas de "Em aberto", uma por vez, na ordem.
> 3. Feche um design aprovado (spec) e só depois escreva o plano.
>
> Converse em português. O dono prefere ver as opções com uma recomendação.

## Por quê

Hoje o Mandacaru detecta e avisa. Quando encontra algo crítico (malware confirmado, pacote malicioso, projeto armado, programa com falha já explorada), a pessoa fica sozinha para decidir o que fazer e em que ordem. O dono quer que o Mandacaru tenha uma **sequência de ações em cadeia** que:

1. **contenha** a ameaça, para que ela pare de agir e não se espalhe;
2. **neutralize** a ameaça, removendo o arquivo, a persistência e a falha;
3. ajude a **recuperar** a máquina com varredura, troca de credenciais e relatório.

Isso vale para os tipos de ameaça que o Mandacaru já detecta.

## Decisões já tomadas pelo dono

- **Plataforma:** primeiro o **app do Windows** (`windows/src/mandacaru_win/`). O Linux fica para depois.
- **Modo misto:** a contenção é **automática só quando há certeza alta**. Nos demais casos é **guiada**: o Mandacaru mostra os passos já pré-selecionados e a pessoa confirma.
- **Privilégio, abordagem C:** um **serviço do Windows opcional** ("Proteção avançada"). O instalador oferece a opção e pede administrador **uma única vez**.
  - A janela (PySide6) continua **sem privilégio**.
  - O serviço privilegiado aceita **apenas uma lista fechada de ações**, pedidas pela janela por um canal protegido (named pipe com ACL).
  - O serviço **nunca lê conteúdo de arquivo suspeito ou de projeto**. Toda análise continua na janela.
  - Abordagens descartadas:
    - (A) Rodar o app inteiro como admin: um bug num parser daria controle total da máquina, e o UAC apareceria a cada abertura.
    - (B) UAC a cada ação: a contenção automática não funciona.
- **Teto assumido:** mesmo com admin, rootkits de kernel e processos protegidos do sistema (PPL) ficam fora de alcance, porque chegar neles exige driver assinado pela Microsoft. Nesses casos o Mandacaru **orienta**: desligar a rede, fazer backup e reinstalar o sistema.

## Propostas do Claude (o dono ainda não confirmou)

**Critérios de certeza alta, os únicos que disparam ação automática:**
- hash SHA-256 confirmado como malicioso pelas bases que o botão **Analisar** já consulta (Team Cymru MHR e CIRCL hashlookup);
- pacote com aviso `MAL-` no OSV, encontrado num projeto ou num servidor MCP;
- regra YARA específica de família, com severidade CRITICAL.

Todo o resto fica guiado: CVE (mesmo listada no KEV), achado de projeto, heurística e classificador de IA.

**A cadeia:**

| Fase | Ação | Quem executa | Automática com certeza alta? | Dá para desfazer? |
|---|---|---|---|---|
| Conter | encerrar o processo e os filhos | serviço (qualquer processo) ou app (só os processos do usuário) | sim | não |
| Conter | quarentena do arquivo | app (perfil do usuário) ou serviço (caminhos do sistema) | sim | sim (restaurar) |
| Conter | bloquear a rede do executável (regra de firewall de saída) | serviço | sim | sim (remover a regra) |
| Conter | isolar a máquina (bloquear toda a saída, exceto o próprio Mandacaru) | serviço | **não**, sempre guiado | sim |
| Neutralizar | remover persistência: chaves Run HKCU/HKLM, pasta Inicializar, tarefas agendadas, serviços | app (HKCU) ou serviço (HKLM, sistema) | não | sim (o backup da entrada fica no registro do incidente) |
| Neutralizar | destruir o projeto armado (o Destruir atual) | app | não | não |
| Neutralizar | quarentena só do arquivo perigoso de um projeto (`tasks.json`, hook, `setup.py`) | app | não | sim |
| Neutralizar | atualizar o programa vulnerável (`winget`, que já existe na aba Atualizações) | app | não | não |
| Recuperar | varredura completa | app | sugerida | não se aplica |
| Recuperar | lista de credenciais para trocar (SSH, `.env`, tokens de nuvem, navegador) conforme o tipo de ameaça | app | não se aplica | não se aplica |
| Recuperar | relatório do incidente (o que foi detectado e quando, cada ação tomada e seu resultado) | app | sempre | não se aplica |

**Na tela:** um painel "Resposta a incidente" com as três fases em ordem. Cada passo mostra o estado (feito, pendente ou falhou) e um botão. O que foi feito automaticamente aparece marcado, com a opção "Desfazer".

**Aviso fixo** sempre que houver HIGH ou CRITICAL num projeto: "Se você já abriu ou instalou este projeto, faça uma varredura completa e troque chaves e tokens." Destruir a pasta **não desfaz** o que já foi executado.

## Pré-requisito: bug real no Destruir — CORRIGIDO no mesmo PR (#24)

O Destruir sobrescreve arquivos que têm **hard link**, ou seja, o mesmo arquivo com dois nomes. Isso destrói o conteúdo do arquivo de fora da pasta.

- **Reproduzido em 2026-11-26:** com `usuario/tese.txt` e um hard link `proj/AGENTS.md` apontando para ela, rodar `shred_path(proj)` deixa `usuario/tese.txt` **vazia**.
- **Onde:** `windows/src/mandacaru_win/shred.py`, em `shred_file`. Os links simbólicos e as junções já são tratados corretamente: são removidos sem serem seguidos.
- **Correção proposta:** se `os.lstat(p).st_nlink > 1`, apenas desvincular (`os.unlink`), sem sobrescrever. Incluir um teste com `os.link` (pular onde o sistema não suportar).
- **Alcance:** o problema está em todas as versões desde a 0.8.0. Merece um release de correção (0.8.3) separado desta ideia.

## Ponto de partida no código

- `windows/src/mandacaru_win/app.py`: janela, varredura, linhas de achado, botões por linha (`_row_buttons`), quarentena, Destruir, Analisar e verificação de projeto.
- `windows/src/mandacaru_win/quarantine.py`: quarentena por arquivo (embaralha, guarda metadados, restaura).
- `windows/src/mandacaru_win/shred.py`: Destruir, com travas em `_assert_safe_target`.
- `windows/src/mandacaru_win/updates.py`: `winget`, CISA KEV e NVD.
- `windows/src/mandacaru_win/worker.py`: threads (`ScanThread`, `ProjetoThread` e outras). O trabalho pesado nunca roda na thread da interface.
- `windows/installer.iss`: hoje usa `PrivilegesRequired=lowest`, ou seja, instalação só no usuário (`{localappdata}\Programs\Mandacaru`). A "Proteção avançada" muda isso para quem escolher a opção.
- `src/mandacaru/analysis.py`: consulta de hash (Analisar).
- `src/mandacaru/projeto/`: verificação de projeto. `projeto.dep.malicioso` (`MAL-`) é um dos gatilhos de certeza alta.
- Spec anterior, como referência de formato e de decisões: `docs/superpowers/specs/2026-11-25-verificar-projeto-design.md`.

## Restrições

- Windows 10 1809+ ou 11, x64. App em PySide6 e Python. Instalador Inno Setup **sem assinatura digital paga**, então o SmartScreen reclama.
- A janela nunca roda como admin.
- O serviço privilegiado é mínimo:
  - só ações de uma lista fechada, com parâmetros validados (PID, caminho absoluto dentro de áreas permitidas, nome de regra com prefixo `Mandacaru-`);
  - não executa comando arbitrário, não lê conteúdo suspeito e não abre conexões de rede.
- Toda ação, automática ou guiada, é registrada com data, motivo e resultado.
- Textos da interface em português com acentos. Os testes rodam sem rede e sem admin; o serviço é testado com um alvo falso.

## Anti-objetivos (seria falha mesmo funcionando)

- O serviço privilegiado virar um caminho para escalar privilégio: qualquer processo do usuário pede "encerre o PID X" ou "apague este caminho" e o serviço obedece sem validar.
- Encerrar automaticamente um programa legítimo por causa de um falso positivo. Isso explica o critério estreito de certeza alta.
- Isolar a máquina de forma automática ou sem caminho de volta.
- Uma ação automática sem registro ou sem "Desfazer" quando ele é possível.
- Fazer a pessoa achar que "destruir resolveu" quando a ameaça já tinha executado.

## Em aberto (perguntar ao dono, nesta ordem)

1. **Critérios de certeza alta:** a lista proposta acima serve? Algo entra ou sai? Por exemplo, CVE no KEV com o programa em execução.
2. **Automação na prática:** quando a contenção automática dispara, a pessoa só é avisada depois (notificação na bandeja) ou há uma contagem regressiva para cancelar (ex.: 10 segundos)?
3. **Isolamento da máquina:** entra na primeira versão? Isolar sem admin é impossível, então isso depende do serviço.
4. **Sem a Proteção avançada:** o que a cadeia faz para quem não instalou o serviço? A proposta é usar só as ações de usuário e mostrar "precisa da Proteção avançada" nas demais.
5. **Persistência:** quais locais verificar na primeira versão? Run/RunOnce, a pasta Inicializar e tarefas agendadas são o mínimo. Serviços, WMI e extensões de navegador entram também?
6. **Credenciais:** a lista para trocar é só orientação (texto) ou o Mandacaru abre as páginas de troca dos serviços detectados?
7. **Relatório:** só local (JSON e HTML) ou exportável para enviar a alguém?
8. **Ordem de entrega:** a sugestão é (a) correção do Destruir, depois (b) quarentena por arquivo e Destruir projeto, (c) painel guiado só com ações de usuário, (d) serviço da Proteção avançada e (e) automação misto.

## Próximo passo esperado

Fechar as perguntas acima com o dono e escrever o spec aprovado em `docs/superpowers/specs/AAAA-MM-DD-resposta-a-incidentes-design.md`. Depois vem o plano. A correção do hard link no Destruir pode seguir antes, por conta própria.
