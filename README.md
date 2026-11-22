# Mandacaru 🌵

[![CI](https://github.com/VandyckLN/mandacaru/actions/workflows/ci.yml/badge.svg)](https://github.com/VandyckLN/mandacaru/actions/workflows/ci.yml)

Antivírus/EDR de código aberto (**GPLv3**) feito para a nova geração de ataques: malware que muda a cada geração (escrito ou reescrito por IA), phishing sob medida e abuso de agentes de IA e servidores MCP.

> Status: **v0.4**, em Python, voltado para Linux. Detecta, registra e põe em quarentena os arquivos detectados (HIGH ou mais); ainda não bloqueia nem mata processos. Também roda no Windows, mas sem eBPF, serviço nem quarentena.

## Por que outro antivírus?

Antivírus clássicos dependem de assinaturas e hashes. Um LLM consegue gerar mil variantes do mesmo malware, cada uma com bytes diferentes. O Mandacaru se apoia no que não muda: **o que o código precisa fazer** para causar dano.

| Camada | O que detecta | Como |
|---|---|---|
| Estática | ofuscação + decodificação + execução, download-e-executa, shells reversos, notas de resgate, prompt injection em arquivos | YARA + heurísticas de técnica (não de bytes) |
| Comportamento | criptografia em massa (ransomware), shell aberto por serviço web/Office, binário rodando de `/tmp`, shell com conexão de rede | regras com estado sobre eventos |
| Agentes de IA | agente/servidor MCP lendo `~/.ssh`, `.env`, credenciais de nuvem; agente abrindo shell com `curl`/`nc` | linhagem de processos |
| Kernel (Linux) | todo `execve`, inclusive processos que vivem milissegundos | eBPF (BCC), opcional |

## Instalação

### Ubuntu 24.04+ / Debian 13+ (recomendado: instala o serviço)

Baixe o `.deb` da [página de Releases](https://github.com/VandyckLN/mandacaru/releases) e instale:

```bash
sudo apt install ./mandacaru_0.4.0_all.deb
systemctl status mandacaru                      # o serviço já sobe sozinho
sudo tail -f /var/log/mandacaru/alerts.jsonl    # alertas em tempo real
```

O apt traz as dependências (`python3-yara`, `python3-psutil`, `python3-watchdog`) e, como recomendado, o `python3-bpfcc` para o coletor eBPF.

### Só a ferramenta de varredura (qualquer Linux)

```bash
pipx install mandacaru-edr
mandacaru scan ~/Downloads
```

No PyPI o pacote se chama `mandacaru-edr`; o comando é `mandacaru`. Se o `pip` precisar compilar o YARA e reclamar de `Python.h`, instale `python3-dev libssl-dev`.

### Desenvolvimento

```bash
git clone https://github.com/VandyckLN/mandacaru && cd mandacaru
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
# opcional, para o coletor eBPF (Ubuntu/Debian):
sudo apt install bpfcc-tools python3-bpfcc
```

## Configuração

O serviço lê `/etc/mandacaru/config.toml`. Depois de editar: `sudo systemctl restart mandacaru`.

```toml
[monitor]
# Sem esta chave: Downloads, Documentos e Desktop de cada usuário, mais /tmp e /dev/shm.
# paths = ["/home/ana/Downloads", "/srv/uploads"]
ebpf = true          # se não funcionar, cai para psutil sozinho

[alerts]
min_severity = "LOW" # INFO | LOW | MEDIUM | HIGH | CRITICAL
json = "/var/log/mandacaru/alerts.jsonl"
socket = "/run/mandacaru/alerts.sock"  # alertas em tempo real; "" desliga

[rules]
dirs = ["/etc/mandacaru/rules.d"]   # suas regras .yar

[exclude]
paths = []           # globs de caminho absoluto, ex.: "/home/*/.cache/*"
```

A precedência é **flag da linha de comando > arquivo > padrão**. Use `--config CAMINHO` para outro arquivo. Chave desconhecida ou tipo errado faz o comando sair com código `1` e uma mensagem dizendo qual chave.

## Uso

```bash
# varrer pastas (código de saída 2 se houver alerta HIGH ou CRITICAL: bom para CI)
mandacaru scan ~/Downloads ./projeto

# monitorar em tempo real (Downloads, Documentos, /tmp...); com sudo, usa eBPF
mandacaru monitor
sudo mandacaru --json /var/log/mandacaru.jsonl monitor

# regras YARA próprias
mandacaru --rules ./minhas-regras scan .
```

Os alertas saem no terminal e, com `--json`, em JSON Lines, já com as técnicas do MITRE ATT&CK. Esse formato serve para mandar para Wazuh, Loki ou Elastic.

### Atualizações pendentes (Linux)

```bash
mandacaru atualizacoes listar               # apt, Snap e Flatpak com versão nova; * = falha alta conhecida
mandacaru atualizacoes listar --completo    # consulta OSV.dev e CISA KEV agora (usa rede)
mandacaru atualizacoes listar --json        # {gerenciador, nome, instalada, disponivel, risco, cves, selecionado}
mandacaru atualizacoes aplicar org.videolan.VLC   # Flatpak do usuário, pede confirmação (s/N); --sim pula
```

Roda com o seu usuário, sem root, e só consulta os gerenciadores instalados. O apt mostra a data do último `apt update` e avisa se passou de 24 h. Cada pacote apt herda a pior prioridade das CVEs do seu pacote-fonte (`libssl3` herda de `openssl`), lidas do último relatório do `vuln scan` (`--relatorio`, padrão `/var/lib/mandacaru/vuln_cache/last-scan.json`), sem rede; sem relatório, o risco fica `DESCONHECIDO` até rodar com `--completo`. Snap e Flatpak ficam `DESCONHECIDO` (o OSV não cobre). Vêm marcados com `*` os de risco `CRITICAL_ACTIVE` ou `HIGH`. Saída: 0 sem item de risco alto, 2 com item de risco alto, 1 erro. Não gera alertas nem popups.

Nesta versão o `aplicar` só atualiza Flatpak instalado para o usuário (`flatpak update --user`). Pacotes apt, Snap e Flatpak do sistema são recusados com uma mensagem: atualize-os pelo gerenciador da distribuição.

## Alertas em tempo real

O serviço publica cada alerta, na hora, no socket Unix `/run/mandacaru/alerts.sock`. Só o root e os membros do grupo `mandacaru` conseguem conectar (`0660`). Para ouvir com o seu usuário: `sudo usermod -aG mandacaru $USER` e entre de novo na sessão.

Cada alerta é uma linha JSON (contrato `v: 1`):

```json
{"v":1,"ts":1794872689.2,"severity":"HIGH","rule":"behavior.revshell","summary":"Shell bash com conexao de rede ativa","mitre":["T1059"]}
```

A `evidence` (linhas de comando, PIDs) não sai pelo socket; ela continua só no `alerts.jsonl`, legível pelo root. O socket só transmite: o que o cliente envia é ignorado, e um cliente que não lê a tempo é desconectado.

```bash
socat - UNIX-CONNECT:/run/mandacaru/alerts.sock
```

## Quarentena

Quando o serviço vê um arquivo novo ou alterado numa pasta vigiada e a varredura estática (YARA ou heurística) acusa severidade `HIGH` ou mais, o arquivo sai do lugar e vai para `/var/lib/mandacaru/quarantine/`, embaralhado para não disparar outros antivírus. O alerta avisa com o `quarantine_id`. Alertas de comportamento (ransomware, shell reverso etc.) só alertam; nada é isolado por eles. O `mandacaru scan` avulso também só relata.

Para cada arquivo isolado há três escolhas:

| Escolha | Botão do popup (`pkexec`) | Quem pode |
|---|---|---|
| **Analisar**: consulta o hash em serviços públicos e mostra o veredito | `/usr/libexec/mandacaru/quarantine-decide analisar <id>` | grupo `mandacaru`, sem senha |
| **Manter isolado**: registra a decisão; o arquivo é apagado ao fim do prazo | `/usr/libexec/mandacaru/quarantine-decide manter <id>` | grupo `mandacaru`, sem senha |
| **Confio**: devolve o arquivo ao lugar e não isola mais esse hash | `/usr/libexec/mandacaru/quarantine-release confiar <id>` | só com senha de administrador |

Sem resposta, vale o lado seguro: o arquivo fica isolado e um timer diário (`mandacaru-quarantine-clean.timer`) o apaga depois de `retention_days` (30 dias por padrão). O polkit pede a senha só onde precisa: um malware rodando na sua sessão não consegue se liberar sozinho. Os auxiliares aceitam só os subcomandos do seu nível e um id de 32 caracteres hexadecimais. No terminal, os mesmos comandos rodam com `sudo`:

```bash
mandacaru quarentena listar                       # grupo mandacaru: id, data, arquivo, regra, dias até apagar
sudo mandacaru quarentena analisar <id>           # só o hash sai da máquina
sudo mandacaru quarentena analisar <id> --enviar  # envia o arquivo ao VirusTotal (pede chave e confirmação)
sudo mandacaru quarentena manter <id>
sudo mandacaru quarentena confiar <id>            # restaura e põe o hash na lista de confiança
sudo mandacaru quarentena apagar <id>             # apaga já, sem esperar o prazo
sudo mandacaru quarentena desconfiar <sha256>     # tira o hash da lista de confiança
```

Códigos de saída: `0` ok, `1` uso ou configuração, `3` id inexistente ou já resolvido, `4` quarentena adulterada. Toda decisão vai para `/var/log/mandacaru/decisions.jsonl` (legível só por root), com quem decidiu.

A análise funciona sem configurar nada, com o Team Cymru MHR e o CIRCL hashlookup (gratuitos, sem chave). Com chaves no config, também usa MalwareBazaar e VirusTotal:

```toml
[quarantine]
enabled = true
min_severity = "HIGH"
retention_days = 30
max_file_mb = 256
max_total_mb = 2048

[analysis]
cymru = true
# virustotal_key = ""
# malwarebazaar_key = ""
```

> **Atenção:** o Team Cymru MHR é gratuito só para **uso não comercial**. Em empresa, desligue com `analysis.cymru = false`.

O `config.toml` é instalado como `0640`, porque pode guardar chaves de API. Quem não é root e roda sem `--config` (por exemplo `mandacaru scan` ou `quarentena listar`) recebe um aviso e segue com a configuração padrão; um `--config` ilegível ou um config inválido continuam sendo erro.

## Vulnerabilidades (CVEs)

> Guia completo, com diagramas e perguntas frequentes: [docs/novidades-0.5.md](docs/novidades-0.5.md).

Um timer diário (`mandacaru-vuln-scan.timer`) cruza os pacotes instalados (`/var/lib/dpkg/status`) com o [OSV.dev](https://osv.dev) e o catálogo de vulnerabilidades exploradas da CISA (KEV). Só saem da máquina nome e versão dos pacotes-fonte; nada de usuário, caminho ou hostname.

| Prioridade | Quando |
|---|---|
| `CRITICAL_ACTIVE` | CVSS ≥ `alert_min_cvss` (ou na KEV) **e** o pacote está carregado em algum processo agora |
| `HIGH` | CVSS ≥ `alert_min_cvss`, prioridade alta da distro ou CVE na KEV |
| `MEDIUM` | CVSS ≥ 4, prioridade média da distro ou aviso de segurança (USN/DSA) com atualização pendente |
| `LOW` | o resto |

Os achados `HIGH` e `CRITICAL_ACTIVE` novos chegam como alertas `vuln.cve_local` no `alerts.jsonl` e no socket (popup). Uma CVE já avisada não se repete no dia seguinte; mais de 5 novas de uma vez viram um alerta-resumo. O relatório completo da última execução fica em `/var/lib/mandacaru/vuln_cache/last-scan.json`.

```bash
mandacaru vuln scan --cache-dir ~/.cache/mandacaru     # na hora, com seu usuário (sai 2 se houver HIGH)
mandacaru vuln scan --cache-dir ~/.cache/mandacaru --json > cves.json
sudo systemctl start mandacaru-vuln-scan.service       # força a execução do serviço
```

O scan com rede roda como o usuário `_mandacaru-net`, sem capabilities e com o sistema de arquivos só para leitura. A única parte que precisa de root, ver quais bibliotecas estão carregadas em `/proc`, roda antes, sem rede, e entrega só a lista de pacotes.

```toml
[vuln]
enabled = true
cache_ttl_hours = 24
kev_enrichment = true
correlate_running_procs = true
alert_min_cvss = 7.0
```

## Telemetria (opt-in)

Desligada por padrão. Ligada, cada arquivo isolado pela quarentena vira um relatório na fila local `/var/lib/mandacaru/telemetry/outbox.db` (só root): hash, tamanho, tipo (ELF, script...), regras YARA, técnicas MITRE, distro e arquitetura. Nunca vai caminho, usuário, hostname, `machine-id` ou IP interno. Nada sai sem você aprovar:

```bash
sudo mandacaru telemetry status
sudo mandacaru telemetry review             # o que vai ser enviado, item por item (--json mostra tudo)
sudo mandacaru telemetry approve <id>       # ou reject <id>; item enviado ou rejeitado nao volta para a fila
sudo systemctl enable --now mandacaru-telemetry.timer   # envio de hora em hora do que foi aprovado
```

Destinos: um MISP próprio (compatível com CSIRTs como o CERT.br; a chave fica só em `/etc/mandacaru/secrets.env`, como `MANDACARU_MISP_API_KEY=...`) e o Mandacaru Threat Hub. O envio roda como `_mandacaru-net`: ele recebe só uma cópia dos itens aprovados e devolve o resultado, sem acesso à fila nem à quarentena.

```toml
[telemetry]
level = "off"              # off | iocs_only | samples_elf (marca ELF/scripts como amostra elegível)
require_approval = true
tlp = "TLP:CLEAR"          # TLP:CLEAR | TLP:GREEN
max_sample_mb = 15
hub_enabled = false
hub_endpoint = ""
misp_enabled = false
misp_url = ""
misp_verify_tls = true
```

## Classificador de IA (em preparação)

Um segundo juiz, além das regras: um modelo pequeno de árvores de decisão que roda **na própria máquina** (sem internet, sem custo, ~13 ms por arquivo) e dá uma nota a cada programa ELF e script novo nas pastas vigiadas. Guia completo, com exemplos: [docs/novidades-0.6.md](docs/novidades-0.6.md).

Esta versão traz o motor completo, mas **ainda sem modelo instalado**: o modelo é treinado num ambiente isolado e entra numa próxima versão. Até lá, o Mandacaru funciona exatamente como antes.

```toml
[ml]
enabled = true
# mode = "shadow"   # off | shadow (só anota o que faria) | alert (alerta) | isolate (isola)
```

```bash
mandacaru ml status              # modelos instalados, tipos aprovados e modo
mandacaru ml avaliar ARQUIVO     # nota, faixa e motivos de um arquivo (não isola)
sudo mandacaru ml sombra         # o que o modelo teria isolado no modo sombra
```

O modelo **nunca libera nada**: ele só acrescenta suspeita. Não anula regras, não mexe na lista de confiança e não tira arquivo da quarentena; liberar continua exigindo "Confio" com senha de administrador.

## Arquitetura

```
coletores (procmon | ebpf | fsmon) ──► fila ──► Engine ──► detectores (static | behavior) ──► sinks (console | jsonl | socket)
```

- `collectors/`: geram `Event`s. `procmon` usa psutil (multiplataforma), `ebpf` usa um tracepoint de `execve` (Linux, root) e `fsmon` usa watchdog (inotify/ReadDirectoryChanges).
- `detectors/static.py`: YARA + heurísticas. Só alerta ofuscação quando aparecem **juntos** conteúdo codificado, decodificação e execução dinâmica.
- `detectors/behavior.py`: regras com janela de tempo e *cooldown* para não inundar o usuário.
- `rules/yara/base.yar`: regras base.
- `vuln/`: inventário dpkg, cliente OSV.dev com cache SQLite, cache da CISA KEV, CVSS 3.1 local e publicação dos achados no monitor.
- `ml/`: classificador local (tipo pelo conteúdo, leitor de ELF, características, modelo em JSON estrito, motivos, decisão por faixas, comandos `ml`).
- `telemetry/`: sanitização (LGPD), fila com aprovação, produtor ligado à quarentena, spool root ↔ `_mandacaru-net` e envio para MISP/Threat Hub.

## Testes e falsos positivos

```bash
pytest -q          # 408 testes (+1 de desempenho opcional), com amostras inofensivas que imitam as técnicas
```

Varredura de cerca de 91 mil arquivos legítimos (stdlib do Python, dist-packages e `/usr/share`): **0 alertas HIGH/CRITICAL**. Ficaram 1 MEDIUM (documentação com `curl | bash`) e 1 LOW (bundle JS grande).

## Roadmap

- [ ] Ações de resposta: suspender processo (`SIGSTOP`)
- [x] Quarentena de arquivos detectados, com decisão do usuário via polkit
- [ ] Modelo de anomalias local (IsolationForest sobre linhagem, rede e arquivos), sem enviar dados para a nuvem
- [ ] eBPF para `openat` em arquivos sensíveis e `connect` (rede)
- [ ] Classificador de scripts gerados por LLM (features de AST + entropia)
- [ ] Proteção do próprio agente: binário em Rust, assinatura das regras
- [ ] Coletor Windows via ETW
- [x] Serviço systemd + pacote `.deb`
- [x] Auditoria diária de CVEs dos pacotes instalados (OSV.dev + CISA KEV), priorizando o que está em execução
- [x] Telemetria opt-in com aprovação manual para MISP/Threat Hub
- [ ] Envio de amostras ELF ao Threat Hub (hoje só a marcação de elegibilidade)

## Contribuindo

Veja [CONTRIBUTING.md](CONTRIBUTING.md). Falhas de segurança: [SECURITY.md](SECURITY.md).

## Licença

GPL-3.0-or-later. Veja [LICENSE](LICENSE). Quem distribuir versões modificadas precisa publicar o código.
