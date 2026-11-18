# Changelog

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
