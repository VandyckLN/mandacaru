# Changelog

## 0.4.0

Quarentena: o arquivo detectado sai do lugar e você decide o que fazer com ele.

- **Isolamento automático** no serviço: arquivo novo ou alterado numa pasta vigiada com alerta estático (`yara.*`, `heur.*`) de severidade `HIGH` ou mais vai para `/var/lib/mandacaru/quarantine/` (embaralhado, `root:mandacaru` `0750`). O alerta no socket ganha o campo opcional `quarantine_id`.
- **`mandacaru quarentena`**: `listar`, `analisar <id> [--enviar]`, `manter <id>`, `confiar <id>`, `apagar <id>`, `desconfiar <sha256>` e `limpar`. Saídas: `0` ok, `1` uso/config, `3` id inexistente ou já resolvido, `4` quarentena adulterada.
- **Análise por hash** sem configurar nada (Team Cymru MHR e CIRCL hashlookup); com chave no config, MalwareBazaar e VirusTotal. O conteúdo do arquivo só sai da máquina com `--enviar`, chave do VirusTotal e confirmação.
- **Polkit**: auxiliares em `/usr/libexec/mandacaru/` para os botões do popup. `confiar` e `apagar` pedem senha de administrador; `analisar` e `manter` são liberados para o grupo `mandacaru` em sessão ativa.
- **Log de decisões** em `/var/log/mandacaru/decisions.jsonl`, legível só por root (fica no `/var/log/mandacaru/`, `0750 root:root`), guardado por um ano no logrotate.
- **Timer diário** `mandacaru-quarantine-clean.timer`: apaga o que passou de `retention_days` (padrão 30).
- Seções novas no config: `[quarantine]` e `[analysis]`. O `config.toml` é instalado como `0640`, porque pode guardar chaves de API; quem atualiza de uma versão anterior também passa a ter o arquivo em `0640` (o `dpkg` preservaria o `0644` de um config modificado). Sem `--config`, quem não consegue ler o arquivo recebe um aviso e segue com os padrões; `--config` ilegível e config inválido continuam sendo erro.
- O pacote passa a depender de `polkitd | policykit-1`.
- `apt purge mandacaru` apaga também `/var/lib/mandacaru` (quarentena e lista de confiança) e `/var/log/mandacaru` (alertas e log de decisões).

## 0.3.1

- **Ícone do Mandacaru** para popups de alerta: PNG 64×64 de 382 bytes, com o nome `mandacaru` no tema hicolor (`/usr/share/icons/hicolor/64x64/apps/mandacaru.png`).

## 0.3.0

Alertas em tempo real para programas da sessão do usuário.

- **Socket de alertas** em `/run/mandacaru/alerts.sock` (chave `[alerts] socket`; `""` desliga). Cada alerta sai como uma linha JSON com contrato versionado (`v: 1`): `ts`, `severity`, `rule`, `summary` e `mitre`. A `evidence` fica de fora, porque traz linhas de comando. Um cliente lento é derrubado; a detecção nunca espera.
- **Grupo `mandacaru`**, criado na instalação do `.deb`. Só root e membros do grupo conectam no socket (`0660`).

## 0.2.0

Primeira versão instalável.

- **Pacote `.deb`** para Ubuntu 24.04+ e Debian 13+, com serviço systemd habilitado na instalação e rotação de log.
- **`pipx install mandacaru-edr`** para quem só quer a ferramenta de varredura.
- **Arquivo de configuração** em `/etc/mandacaru/config.toml` (ou `--config`). Flag da linha de comando vence o arquivo, que vence o padrão. Chave desconhecida ou tipo errado é erro, com saída `1`.
- **Exclusões** por glob de caminho absoluto (`[exclude] paths`). O próprio arquivo de alertas é excluído automaticamente.
- Rodando como root, o monitor vigia Downloads, Documentos e Desktop de cada usuário em `/home`, em vez de `/root`.
- Se o eBPF falhar ao iniciar (sem headers do kernel, WSL, contêiner), o monitor avisa e usa psutil.
- Pisos de dependência reduzidos para o que o Ubuntu 24.04 empacota (`yara-python>=4.3`, `watchdog>=3.0`).

## 0.1.0

Protótipo inicial: varredura estática (YARA + heurísticas de ofuscação), regras de comportamento, coletores psutil, watchdog e eBPF (`execve`).
