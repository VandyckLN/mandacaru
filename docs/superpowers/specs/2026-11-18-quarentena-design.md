# Quarentena com decisão do usuário — design

Data: 2026-11-18 · Tamanho: projeto

## Intenção

Hoje o Mandacaru só detecta e registra. Quando ele encontrar um malware (ou suposto malware) num arquivo,
deve **isolá-lo num ambiente de quarentena seguro** e **sempre perguntar ao usuário** o que fazer:

- **Confio** — devolve o arquivo ao lugar de origem;
- **Analisar** — consulta serviços globais e gratuitos de reputação e mostra o resultado;
- **Manter isolado** — continua na quarentena e é apagado sozinho depois de 30 dias.

**Toda decisão é registrada em log.** A pergunta aparece no popup do vigia (`lumen-edr-notify`, na distro)
com botões, e a mesma coisa pode ser feita pelo terminal.

Por que assim: o Mandacaru passa a mexer em arquivos do usuário pela primeira vez. Um falso positivo agora
custa caro (arquivo some do lugar), então o usuário tem a palavra final; e um malware deixado no lugar enquanto
ninguém responde é o pior caso, então o isolamento vem **antes** da pergunta.

## Objetivos

1. Arquivo detectado com severidade alta é isolado automaticamente, de forma que não execute por acidente nem
   dispare outros antivírus.
2. O usuário sempre recebe a pergunta (popup com botões; terminal como alternativa).
3. "Confio" exige **senha de administrador** (polkit). Um malware rodando na sessão do usuário não consegue
   se libertar sozinho.
4. "Analisar" funciona **sem configurar nada**, só por hash, com serviços gratuitos e sem chave:
   Team Cymru MHR e CIRCL hashlookup. Com chave opcional no config: MalwareBazaar e VirusTotal.
5. Sem resposta, vale o lado seguro: fica isolado e é apagado em 30 dias.
6. Log de decisões à prova de falsificação por usuário comum.

## Não-objetivos

- Matar ou suspender processos (a quarentena é de **arquivos**).
- Quarentena a partir de alertas de comportamento (`behavior.*`): o alvo de `ransomware_burst` são os
  arquivos da vítima; o de `exec_from_temp` pode ser um binário rodando. Ficam só alertando, como hoje.
- Sandbox dinâmica (executar o arquivo para observar).
- Windows/macOS (polkit, systemd e caminhos são de Linux; ver a discussão de portabilidade).
- Os botões do popup em si: são entrega separada no `lumen-edr-notify`. Aqui só o contrato que ele consome.

## Anti-objetivos (falha mesmo que "funcione")

- O serviço root passar a **ler comandos** de fora (socket de controle). O socket de alertas continua só
  transmitindo.
- O serviço root acessar a internet.
- Enviar o **conteúdo** de um arquivo para fora sem uma confirmação explícita e separada.
- Embutir chave de API do projeto no código.
- Perder um arquivo: mover para a quarentena e falhar no meio, ou devolver por cima de outro arquivo.
- Um usuário comum conseguir forjar ou apagar linhas do log de decisões.

## Restrições encontradas no projeto

- `debian/mandacaru.service` tem `ProtectHome=read-only`: o serviço **não consegue tirar arquivos de /home**.
  Precisa virar `ReadWritePaths=` das pastas vigiadas (ou `ProtectHome=no`); a escolha mínima fica com o builder,
  mas o resultado tem que ser "o serviço move arquivos das pastas vigiadas e de mais nada".
- `ProtectSystem=full` deixa `/var` gravável; usar `StateDirectory=mandacaru` (→ `/var/lib/mandacaru`, 0750).
- `StaticScanner.scan_file` lê no máximo 8 MiB (`MAX_BYTES`); o hash da quarentena é do arquivo **inteiro**.
- Socket de alertas, contrato v1: a linha não leva `evidence`. O popup precisa do id do caso — campo novo
  **opcional** `quarantine_id` (adicionar campo é compatível com v1; clientes antigos ignoram).
- Python ≥ 3.10, sem dependências novas obrigatórias: HTTP com `urllib.request`, DNS do Team Cymru com
  `socket.getaddrinfo` (resposta A) — sem `dnspython`.
- O grupo `mandacaru` já existe (criado no `postinst`).

## Abordagens consideradas

1. **Só terminal** (`mandacaru quarentena ...`). Simples e seguro, mas não é uma pergunta: quem não abre o
   terminal nunca decide. Descartada como solução única; vira a base da escolhida.
2. **Popup falando com o serviço por um socket de controle.** Experiência mais direta, mas o processo root
   passa a interpretar comandos de usuários — a superfície de ataque mais perigosa de um antivírus — e a análise
   pela internet rodaria dentro do serviço. Descartada.
3. **Popup com botões que chamam a linha de comando — escolhida pelo usuário.** O serviço só isola e avisa.
   Cada botão roda um comando; as decisões passam por auxiliares privilegiados via `pkexec`, com política do
   polkit: "confiar" pede senha de administrador; "manter" e "analisar" não pedem senha para quem é do grupo
   `mandacaru`. O serviço continua sem receber comandos e sem rede.

## Design

### Visão geral

```
arquivo detectado (alerta de arquivo, severidade >= HIGH)
        │  serviço root (mandacaru monitor)
        ▼
  isolar → /var/lib/mandacaru/quarantine/<id>.bin + <id>.json
  log de decisões: {"action": "isolar", ...}
  alerta (socket + alerts.jsonl) com quarantine_id
        │
        ▼  popup do lumen-edr-notify (entrega separada)
 [Confio]               [Analisar]              [Manter isolado]
 pkexec ... confiar     pkexec ... analisar     pkexec ... manter
 (senha de admin)       (sem senha p/ grupo)    (sem senha p/ grupo)
        │                     │                       │
 restaura + lista de    consulta por hash,      registra; expira em
 confiança              registra resultado      30 dias
                        e pergunta de novo
        ▼
  timer diário: mandacaru quarentena limpar → apaga vencidos, registra "expirado"
```

### 1. Quando isolar

- Só no `monitor` (o serviço). O `scan` avulso continua só relatando. *(Chamada minha: `scan` roda como
  usuário comum e não tem para onde mover com segurança.)*
- Só alertas com `evidence.path` vindos do `StaticScanner` (`yara.*`, `heur.*`) e severidade
  `>= quarantine.min_severity` (padrão `HIGH`).
- Só quando a varredura veio de um **evento de arquivo** (`file_create`/`file_write`/`file_rename`) e o caminho
  está **dentro de uma pasta vigiada**. As varreduras disparadas por `process_start` (o `exe` e os scripts da linha
  de comando) continuam só alertando: o arquivo está em uso e costuma estar fora das pastas vigiadas. Para isso a
  quarentena entra no `Engine.process`, no ramo dos eventos de arquivo, e não como sink. *(Chamada minha.)*
- O alerta de um arquivo isolado **sempre** chega ao socket e ao jsonl: ignora o dedup de 30 s do `Engine.emit`
  e o `alerts.min_severity`, porque cada caso novo tem que gerar a pergunta. *(Chamada minha, pelo "sempre uma
  pergunta ao usuário".)*
- Antes de isolar, calcula o SHA-256 do arquivo inteiro. Se o hash está na **lista de confiança**, não isola e
  não incomoda: o alerta sai rebaixado para `INFO` só no jsonl (com `"trusted": true`; `INFO` não passa pelo
  filtro padrão do socket) e registra `"action": "ignorado_confiavel"`. Isso cobre também a nova varredura logo
  depois do "Confio". *(Chamada minha.)*
- Arquivos maiores que `quarantine.max_file_mb` (padrão 256) não são isolados; só alertam e registram
  `"action": "nao_isolado", "motivo": "tamanho"`. Idem se a quarentena passaria de `max_total_mb` (padrão 2048)
  — o alerta diz isso, para o usuário saber que o arquivo ficou no lugar.
- Symlinks nunca são seguidos (o scanner já ignora). Arquivo que some antes de isolar: registra `"nao_isolado",
  "motivo": "sumiu"`.

### 2. Como isolar (sem perder o arquivo)

Diretório `/var/lib/mandacaru/quarantine/`, root:mandacaru, 0750. Para cada caso, `id` = UUID4 hex.

1. Abre o original com `O_NOFOLLOW`, faz `fstat` (guarda dono, grupo, modo, mtime).
2. Copia para `<id>.bin.tmp` (0600, root) **embaralhando** cada byte com XOR por uma chave de 1 byte
   fixa (`0xA5`), calculando o SHA-256 do conteúdo original no caminho. `fsync`.
3. Escreve `<id>.json` (0640, root:mandacaru) com os metadados (abaixo), via arquivo temporário + `rename`.
4. `rename(<id>.bin.tmp, <id>.bin)`, `fsync` do diretório.
5. Só então `unlink` do original. Se o unlink falhar, o caso continua existindo com `"original_removido": false`
   e o alerta diz que o arquivo **não** saiu do lugar.

Falha em qualquer passo antes do 5: apaga os temporários, o original fica intocado, registra
`"nao_isolado", "motivo": "<erro>"`. Nunca há um momento em que o arquivo só exista pela metade.

O XOR não é criptografia nem pretende ser: serve para que o `.bin` não seja um executável válido e para que
assinaturas de outros antivírus não batam nele. *(Chamada minha.)*

Metadados (`<id>.json`):

```json
{"v": 1, "id": "…", "sha256": "…", "size": 1234,
 "original_path": "/home/ana/Downloads/x.py", "uid": 1000, "gid": 1000, "mode": 33188, "mtime": 1763…,
 "rule": "yara.Obfuscated_Exec", "severity": "HIGH", "summary": "…",
 "quarantined_at": 1763…, "expires_at": 1763… ,
 "state": "isolado", "original_removido": true,
 "analysis": null}
```

`state`: `isolado` → `restaurado` | `expirado` (o par `.bin/.json` é apagado ao restaurar ou expirar; o
histórico fica no log de decisões).

### 3. Lista de confiança

`/var/lib/mandacaru/trusted.json`, root, 0644: lista de `{"sha256", "added_at", "original_path", "by"}`.
Escrita atômica (temporário + `rename`). Lida pelo serviço na inicialização e recarregada quando o mtime mudar
(checado no máximo uma vez a cada 5 s, para não reler a cada evento). Remover da lista: `sudo mandacaru
quarentena desconfiar <sha256>`, também registrado.

### 4. Comandos (`mandacaru quarentena ...`)

| Comando | Quem pode | O que faz |
|---|---|---|
| `listar` | grupo `mandacaru` (lê os `.json`) | id, data, arquivo original, regra, dias até expirar, análise |
| `analisar <id> [--enviar]` | via `pkexec`, sem senha p/ grupo | consulta por hash (seção 5), grava `analysis` no `.json`, registra |
| `manter <id>` | via `pkexec`, sem senha p/ grupo | registra a decisão; prazo de 30 dias continua contando |
| `confiar <id>` | via `pkexec`, **senha de admin** | restaura (seção 6), põe o hash na lista de confiança, registra |
| `apagar <id>` | via `pkexec`, senha de admin | apaga já, sem esperar 30 dias, registra |
| `desconfiar <sha256>` | root | tira da lista de confiança, registra |
| `limpar` | root (timer) | apaga vencidos, registra `expirado` |

Os comandos que alteram estado exigem euid 0 e recusam rodar sem ele com uma mensagem clara.

Polkit: cada nível vira um executável pequeno em `/usr/libexec/mandacaru/` (ex.: `quarantine-decide` para
`analisar`/`manter`, `quarantine-release` para `confiar`/`apagar`), cada um com sua ação em
`/usr/share/polkit-1/actions/` (`org.freedesktop.policykit.exec.path`). Ação de `release`: `auth_admin` em
todos os casos. Ação de `decide`: uma regra em `/usr/share/polkit-1/rules.d/` libera sem senha para membros do
grupo `mandacaru` em sessão ativa; os demais caem em `auth_admin`. Os auxiliares aceitam só os subcomandos do seu
nível e validam o `id` (32 hex) antes de qualquer coisa. Como o `pkexec` passa `PKEXEC_UID`, o log grava
**quem** decidiu.

### 5. Análise ("Analisar")

Roda no processo do auxiliar (curto, root, disparado pelo usuário) — **nunca no serviço**. *(Ajuste meu sobre
o que conversamos: rodar a análise como usuário comum deixaria esse usuário escrever um resultado falso no log;
passar pelo auxiliar mantém o log confiável, e o serviço continua sem rede.)* Só o hash sai da máquina.

Fontes, em ordem, cada uma com timeout de 10 s; uma fonte que falha não impede as outras:

1. **Team Cymru MHR** (sem chave, uso não comercial; ligado por padrão porque hoje o Mandacaru e a Lumen são de
   uso pessoal — decisão do usuário — com `analysis.cymru = false` para desligar se isso mudar; o README e o
   comentário do config avisam da restrição). Aceita SHA-256 (a documentação DNS do MHR pede o hash dividido em
   dois blocos de 32), então não é preciso guardar MD5/SHA-1: resolve `<sha256 em dois blocos de 32>.hash.cymru.com`
   (formato exato conforme a documentação DNS do MHR). Resposta `127.0.0.2` = malware conhecido; o TXT traz data e
   taxa de detecção — se ler TXT exigir dependência nova, usar só o A. Sem resposta = desconhecido.
2. **CIRCL hashlookup** (sem chave): `GET https://hashlookup.circl.lu/lookup/sha256/<hash>` com
   `Accept: application/json`. 200 = **arquivo legítimo conhecido** (ex.: de pacote oficial) — forte sinal de
   falso positivo; 404 = desconhecido.
3. **MalwareBazaar** (se `analysis.malwarebazaar_key`): `POST https://mb-api.abuse.ch/api/v1/`,
   `query=get_info&hash=<sha256>`, header `Auth-Key`.
4. **VirusTotal** (se `analysis.virustotal_key`): `GET https://www.virustotal.com/api/v3/files/<sha256>`,
   header `x-apikey`; resume `last_analysis_stats` (ex.: "54/70 detectam").

Saída: um veredito simples — `malicioso` (alguma fonte de malware confirmou), `legitimo_conhecido` (CIRCL achou
e nenhuma fonte de malware achou), `desconhecido` — mais o detalhe por fonte. Gravado em `analysis` no `.json` e
no log. Depois de analisar, o comando imprime o resultado e a pergunta de novo (confiar / manter).

**Envio do arquivo** (`--enviar`): só existe com chave do VirusTotal e só quando o hash é desconhecido. Exige
confirmação interativa separada ("o arquivo ficará acessível a pesquisadores e empresas parceiras do
VirusTotal; enviar? [s/N]"), desembaralha em memória, envia (`POST /api/v3/files`, até 32 MB) e registra
`"enviado": true`. Sem TTY, `--enviar` é recusado.

**Contrato de saída** (o popup depende dele): `analisar <id> --json` imprime uma linha JSON
`{"v": 1, "id", "verdict": "malicioso|legitimo_conhecido|desconhecido", "sources": {<fonte>: {"status":
"achou|nao_achou|erro|desligada", "detail": "…"}}, "summary": "texto curto para mostrar"}`. Sem `--json`, texto
legível com a mesma informação. Sem TTY, nunca pergunta nada (só imprime). Códigos de saída de todos os
subcomandos: `0` ok; `1` erro de uso/config; `3` id inexistente ou já resolvido; `4` quarentena adulterada (hash
não confere); `126`/`127` são os do próprio `pkexec` (autenticação negada / cancelada). O veredito vai no JSON,
não no código de saída. *(Chamada minha.)*

Sem internet / todas as fontes falharam: veredito `desconhecido`, com aviso de que a análise ficou limitada,
mais uma varredura YARA local de novo (regras atuais podem ter mudado).

### 6. Restaurar ("Confio")

- Desembaralha para um temporário **no mesmo diretório do original** (`O_EXCL`), confere o SHA-256 contra o
  `.json` (diferente = recusa e registra: a quarentena foi adulterada), aplica dono/grupo/modo/mtime, `fsync`,
  e faz `rename` para o caminho original **só se ele não existir** (`os.link` + `unlink` do temporário, que
  falha se o destino existe). Se existir, restaura como `<nome>.restaurado-<data>` e avisa.
- Se o diretório original não existe mais, recusa com mensagem; o caso continua isolado.
- Restaurar com o serviço rodando não pode gerar um novo alerta+quarentena do mesmo arquivo: o hash entra na lista
  de confiança **antes** do arquivo voltar.

### 7. Log de decisões

`/var/log/mandacaru/decisions.jsonl`, root:mandacaru, 0640, uma linha JSON por evento, escrita com `O_APPEND` e
`flock` (serviço e auxiliares escrevem no mesmo arquivo). *Na implementação, o log fica só para root: o
`LogsDirectory` é `0750 root:root`.* Campos:

```json
{"v": 1, "ts": 1763…, "id": "…", "sha256": "…", "path": "/home/ana/Downloads/x.py",
 "action": "isolar|nao_isolado|ignorado_confiavel|analisar|manter|confiar|apagar|desconfiar|expirado|restauracao_recusada",
 "by": "sistema|<usuário>", "uid": 1000, "detail": {…}}
```

`by` vem de `PKEXEC_UID` (ou `SUDO_UID`) resolvido para nome; `"sistema"` para o serviço e o timer. Textos passam
por `safe_text`. O logrotate atual (`*.jsonl`, 8 semanas) também pega este arquivo — **as decisões precisam de
mais retenção**: entrada própria no logrotate com `rotate 52` (um ano). *(Chamada minha.)*

### 8. Expiração (30 dias)

`mandacaru-quarantine-clean.timer` (diário, `Persistent=true`) roda `mandacaru quarentena limpar`: apaga
`.bin`/`.json` com `expires_at` vencido e registra `expirado`. Independente do serviço estar no ar.
`retention_days` configurável (padrão 30).

### 9. Configuração

Seções novas no `config.toml` (mesma validação estrita de hoje: chave desconhecida é erro):

```toml
[quarantine]
enabled = true
min_severity = "HIGH"
retention_days = 30
max_file_mb = 256
max_total_mb = 2048

[analysis]
# Team Cymru MHR e gratuito so para uso NAO comercial; em uso por empresa, desligue (false)
cymru = true
# opcionais; sem elas a análise usa só Team Cymru + CIRCL (gratuitos, sem chave)
# virustotal_key = ""
# malwarebazaar_key = ""
```

O `config.toml` passa a guardar chaves: instalar como 0640 root:root (ou root:mandacaru se os auxiliares
precisarem — rodam como root, então root:root basta).

### 10. Contrato com o popup (entrega na distro)

- Linha do socket de alertas ganha `quarantine_id` (opcional, só quando houve isolamento). Restante do
  contrato v1 igual.
- O popup mostra o resumo e três botões, que executam exatamente:
  `pkexec /usr/libexec/mandacaru/quarantine-release confiar <id>`,
  `pkexec /usr/libexec/mandacaru/quarantine-decide analisar <id>`,
  `pkexec /usr/libexec/mandacaru/quarantine-decide manter <id>`.
  Para "analisar", o popup mostra a saída (resumo do veredito) numa segunda notificação, com os botões
  Confio / Manter.
- Fechar o popup sem clicar = nenhuma decisão (vale o padrão de 30 dias).

### 11. Testes

- Isolar/restaurar em `tmp_path` com o diretório da quarentena injetável (sem root): conteúdo embaralhado, hash,
  metadados, original removido; falha simulada em cada passo deixa o original intacto.
- Restaurar sem sobrescrever; restaurar com `.bin` adulterado é recusado.
- Lista de confiança impede nova quarentena do mesmo hash.
- Limpeza apaga só vencidos.
- Log de decisões: linhas válidas, concorrência com dois escritores.
- Análise com fontes simuladas (sem rede no CI): cada combinação de vereditos, timeout, fonte fora do ar.
- Config: seções novas aceitas, chaves desconhecidas recusadas.
- Engine: alerta `HIGH` de arquivo isola; `behavior.*` nunca isola; `MEDIUM` não isola com o padrão.

## O que fica para o builder

- Nome exato dos módulos (sugestão: `src/mandacaru/quarantine.py`, `analysis.py`, `decisions.py`) e como o
  `Engine` chama a quarentena (sink novo ou passo no `process`), desde que o alerta saia com `quarantine_id`.
- A forma mínima de liberar escrita nas pastas vigiadas no unit do systemd.
- Formato exato da consulta DNS do Team Cymru, conferido na documentação oficial.
- Texto das mensagens e da saída do `listar`.
