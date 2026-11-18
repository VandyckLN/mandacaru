# Mandacaru 🌵

[![CI](https://github.com/VandyckLN/mandacaru/actions/workflows/ci.yml/badge.svg)](https://github.com/VandyckLN/mandacaru/actions/workflows/ci.yml)

Antivírus/EDR de código aberto (**GPLv3**) feito para a nova geração de ataques: malware que muda a cada geração (escrito ou reescrito por IA), phishing sob medida e abuso de agentes de IA e servidores MCP.

> Status: **v0.2**, em Python, voltado para Linux. Detecta e registra; ainda não bloqueia nem remove nada. Também roda no Windows, mas sem eBPF nem serviço.

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
sudo apt install ./mandacaru_0.2.0_all.deb
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

## Arquitetura

```
coletores (procmon | ebpf | fsmon) ──► fila ──► Engine ──► detectores (static | behavior) ──► sinks (console | jsonl | socket)
```

- `collectors/`: geram `Event`s. `procmon` usa psutil (multiplataforma), `ebpf` usa um tracepoint de `execve` (Linux, root) e `fsmon` usa watchdog (inotify/ReadDirectoryChanges).
- `detectors/static.py`: YARA + heurísticas. Só alerta ofuscação quando aparecem **juntos** conteúdo codificado, decodificação e execução dinâmica.
- `detectors/behavior.py`: regras com janela de tempo e *cooldown* para não inundar o usuário.
- `rules/yara/base.yar`: regras base.

## Testes e falsos positivos

```bash
pytest -q          # 54 testes, com amostras inofensivas que imitam as técnicas
```

Varredura de cerca de 91 mil arquivos legítimos (stdlib do Python, dist-packages e `/usr/share`): **0 alertas HIGH/CRITICAL**. Ficaram 1 MEDIUM (documentação com `curl | bash`) e 1 LOW (bundle JS grande).

## Roadmap

- [ ] Ações de resposta: suspender processo (`SIGSTOP`) e colocar arquivo em quarentena
- [ ] Modelo de anomalias local (IsolationForest sobre linhagem, rede e arquivos), sem enviar dados para a nuvem
- [ ] eBPF para `openat` em arquivos sensíveis e `connect` (rede)
- [ ] Classificador de scripts gerados por LLM (features de AST + entropia)
- [ ] Proteção do próprio agente: binário em Rust, assinatura das regras
- [ ] Coletor Windows via ETW
- [x] Serviço systemd + pacote `.deb`

## Contribuindo

Veja [CONTRIBUTING.md](CONTRIBUTING.md). Falhas de segurança: [SECURITY.md](SECURITY.md).

## Licença

GPL-3.0-or-later. Veja [LICENSE](LICENSE). Quem distribuir versões modificadas precisa publicar o código.
