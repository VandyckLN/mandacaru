# Design: socket de alertas (v0.3.0)

- **Data:** 2026-11-17
- **Status:** Aprovado no brainstorming, aguardando revisão da spec
- **Consumidor:** o vigia `lumen-edr-notify` da distro Linux VDK (spec própria no repositório da distro), que toca um som e mostra um popup na sessão do usuário

## 1. Problema

O serviço do Mandacaru roda como root, sem sessão gráfica e sem áudio. Hoje os alertas saem em dois lugares:
- no journal, como texto colorido do `console_sink`;
- no `/var/log/mandacaru/alerts.jsonl`, que só o root lê (`LogsDirectoryMode=0750`).

Nenhum dos dois serve para um programa da sessão do usuário avisar em tempo real: o texto do journal não é um contrato estável, e o arquivo não é legível para o usuário. Tocar o som direto do serviço (`runuser` na sessão do usuário) briga com o `NoNewPrivileges` e com o resto da blindagem da unit.

## 2. Objetivos

- O monitor publica cada alerta, em tempo real, num socket Unix local, como uma linha JSON com contrato versionado.
- Só os membros do grupo `mandacaru` (e o root) conseguem se conectar.
- Um cliente lento, travado ou mal-comportado nunca atrasa a detecção nem derruba o monitor.
- A versão sobe para 0.3.0, publicada pelo `release.yml` que já existe.

### Fora de escopo

- Qualquer som, popup ou interface. Isso é do consumidor.
- Receber comandos pelo socket. O socket só transmite.
- Reenviar alertas antigos para quem conecta depois. O histórico continua no `alerts.jsonl`.
- Autenticação além da permissão do arquivo do socket.

## 3. Componentes

### 3.1 Configuração

O `[alerts]` ganha a chave `socket` (texto), no `_SCHEMA` do `config.py`, guardada no campo novo `Config.socket_path: str | None = None`.

- `packaging/config.toml` (o config instalado) passa a trazer `socket = "/run/mandacaru/alerts.sock"`, com um comentário de uma linha.
- `socket = ""` desliga o sink. Sem a chave, como em `mandacaru monitor` rodado à mão sem config, o sink também fica desligado, do mesmo jeito que o `json`.
- Tipo errado (número, lista) é `ConfigError`, como as outras chaves.

### 3.2 Unit systemd

`debian/mandacaru.service` ganha:

```
RuntimeDirectory=mandacaru
RuntimeDirectoryMode=0755
```

O systemd cria o `/run/mandacaru` antes de iniciar o serviço e apaga o diretório quando ele para. O `ProtectSystem=full` não bloqueia o `/run`.

### 3.3 Grupo `mandacaru`

- `debian/mandacaru.postinst` (novo) cria o grupo de sistema com `addgroup --system --quiet mandacaru` no `configure`, se ele ainda não existir.
- O `debian/control` passa a depender de `adduser`.
- O pacote não coloca ninguém no grupo. Isso é decisão de quem instala ou da distro.

### 3.4 `socket_sink`, no módulo novo `src/mandacaru/alert_socket.py`

Interface: `socket_sink(path: str, min_sev: Severity) -> tuple[AlertSink, Callable[[], None]]`. Devolve o sink e uma função de parada que fecha o servidor, desconecta os clientes e apaga o arquivo do socket.

1. **Preparar o caminho:**
   - se já existe um socket no caminho (sobra de um crash), apaga;
   - se existe outra coisa (arquivo comum, diretório), não mexe: levanta `OSError`, e o `cmd_monitor` avisa e segue sem socket;
   - se o diretório pai não existe, a regra é a mesma.
2. **Servidor:** `AF_UNIX` + `SOCK_STREAM`, `bind` com a `UMask=0027` da unit, de modo que o socket nasce `0750 root:root` e não há janela com permissão aberta.
3. **Permissão:** se o grupo `mandacaru` existe, faz `chown(root, mandacaru)` e `chmod 0660`. Se não existe, faz `chmod 0600` e imprime `[mandacaru] grupo mandacaru ausente: socket so para root` no stderr.
4. **Aceitar clientes:** uma thread daemon (`accept` em laço) coloca cada cliente, em modo não bloqueante, numa lista protegida por lock. Tudo que o cliente manda é ignorado e nunca é lido.
5. **Enviar** (`_sink(alert)`, chamado na thread do motor):
   - alertas abaixo de `min_sev` são descartados;
   - os demais viram uma linha JSON `+ "\n"`, em UTF-8, enviada com `sendall` não bloqueante para cada cliente;
   - qualquer `BlockingIOError`, `BrokenPipeError`, `ConnectionResetError` ou `OSError` fecha e remove aquele cliente.

   O sink nunca levanta exceção para o motor.

### 3.5 Contrato da linha (v1)

```json
{"v":1,"ts":1794872689.2,"severity":"HIGH","rule":"behavior.revshell","summary":"Shell bash com conexao de rede ativa","mitre":["T1059"]}
```

| Campo | Tipo | Origem |
|---|---|---|
| `v` | inteiro | sempre `1` nesta versão. Mudança incompatível sobe o número. |
| `ts` | número | `Alert.ts` |
| `severity` | texto | `Alert.severity.name` (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| `rule` | texto | `Alert.rule` |
| `summary` | texto | `Alert.summary` |
| `mitre` | lista de textos | `Alert.mitre` |

A `evidence` fica de fora de propósito, porque carrega linhas de comando e PIDs. Quem precisa dela lê o `alerts.jsonl` como root.

### 3.6 `cmd_monitor`

- Se `cfg.socket_path` estiver preenchido, cria o `socket_sink` e soma o sink à lista e a função de parada aos `stoppers`.
- Imprime `[mandacaru] alertas em tempo real: <caminho>`.
- Se o `socket_sink` levantar `OSError`, imprime `[mandacaru] socket de alertas desligado: <erro>` e o monitor segue.

### 3.7 Versão 0.3.0

- `__version__` passa a `"0.3.0"`.
- `CHANGELOG.md` e `debian/changelog` ganham a entrada `0.3.0`.
- O README ganha uma seção curta "Alertas em tempo real", com o contrato e um exemplo: `socat - UNIX-CONNECT:/run/mandacaru/alerts.sock`.
- Publicar é **manual**: o autor faz o push da tag `v0.3.0` e o `release.yml` gera o `.deb`, o wheel, o PyPI e a GitHub Release.

## 4. Tratamento de erros

| Situação | Comportamento |
|---|---|
| Socket velho no caminho | É apagado e recriado. |
| Caminho ocupado por arquivo ou diretório, ou pai inexistente | Aviso no stderr, monitor sem socket, saída normal. |
| Grupo `mandacaru` ausente | Socket `0600 root:root` e aviso no stderr. |
| Cliente com buffer cheio, desconectado ou com erro de escrita | Aquele cliente é derrubado. O motor nunca bloqueia nem vê a exceção. |
| `socket = ""` ou chave ausente | Sink desligado. |
| `socket` com tipo errado | `ConfigError`, saída `1` (como já acontece). |

## 5. Testes (pytest, rodam no CI e no `dh` do `.deb`)

Usam um caminho de socket em `tmp_path`, sem root.

| Arquivo | Caso |
|---|---|
| `tests/test_socket_sink.py` | Um cliente conectado recebe o alerta como JSON v1, com exatamente os campos da §3.5 e sem `evidence`. |
| | Alerta abaixo de `min_sev` não é enviado. |
| | Dois clientes recebem o mesmo alerta. |
| | Um cliente que nunca lê é derrubado quando o buffer enche, e `_sink` retorna em menos de 1 s com os outros clientes ainda recebendo. |
| | Um cliente que fecha a conexão é removido sem exceção no `_sink`. |
| | Com um socket velho no caminho, a criação funciona. Com um arquivo comum, levanta `OSError` e o arquivo continua lá. |
| | O socket nasce com modo `0600` quando o grupo `mandacaru` não existe (o grupo é trocado por monkeypatch). |
| | A função de parada apaga o arquivo do socket. |
| `tests/test_config.py` | `socket = "/x"` preenche `socket_path`, `socket = ""` desliga, e `socket = 1` é `ConfigError`. |
| `tests/test_packaging.py` | A unit tem `RuntimeDirectory=mandacaru`, o `packaging/config.toml` tem `socket = "/run/mandacaru/alerts.sock"`, o `postinst` chama `addgroup --system` e o `control` depende de `adduser`. |
| `tests/test_cli.py` | Com um caminho de socket impossível, o `cmd_monitor` avisa e não sai com erro. Os coletores são trocados por stubs, como já é feito hoje. |

**Critério de pronto:** pytest 100% verde, CI verde no PR e o `.deb` 0.3.0 gerado pelo `deb.yml`.

## 6. Riscos

- **Config modificado pelo usuário:** o `/etc/mandacaru/config.toml` é conffile. Quem editou o arquivo recebe o prompt do dpkg e pode ficar sem a chave `socket`, e aí o sink fica desligado. A ISO da distro sempre instala limpo, então não é afetada.
- **Vazamento de caminho entre usuários:** o `summary` pode citar um arquivo de outro usuário. Esse é o motivo de restringir o socket ao grupo `mandacaru`.
- **Muitos clientes:** cada alerta é enviado para todos os clientes em série, na thread do motor. Como os envios são não bloqueantes e o número de clientes é pequeno (um por sessão), isso é aceitável. Não há limite de clientes nesta versão.
