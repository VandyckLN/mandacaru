# Changelog

## 0.8.1

Melhorias visuais no aplicativo Windows, preservando a velocidade da varredura e com adaptação automática ao tema claro e escuro do Windows 11.

- **Barras de progresso personalizadas (`MandacaruProgressBar`)**: visual em pílula com cores semânticas por estado (verde na varredura/atualizações, vermelho/laranja na destruição segura, dourado em interrupções e vermelho em falhas), sem timers em repouso (0% de CPU) e com animação suave apenas no modo indeterminado visível; também presente na faixa de autoatualização.
- **Botões coloridos por função**: verde (varrer/atualizar), azul (analisar), laranja (quarentena), vermelho (destruir/apagar/parar) e neutro, com ajuste de largura mínima nas células para evitar quebra de texto.
- **Badges de severidade e risco em pílula suave (`BadgeDelegate`)**: pintadas direto em `QPainter` (sem widgets extras por linha) nas abas *Varredura*, *Quarentena* e *Atualizações*.

## 0.8.0

Novas regras YARA (JS, cron, Windows LOLBins/persistência e prompt injection oculto), melhorias no motor/ML e grandes novidades no app Windows (destruição segura, análise de hash, menu de contexto no Explorer e pastas ignoradas).

- **Windows, destruição segura (shred)**: sobrescreve arquivos com dados aleatórios + `fsync`, trunca, renomeia e apaga sem passar pela Lixeira (com travas de segurança para raízes de unidade, pastas do sistema e pasta do usuário; não segue symlinks/junções). Disponível pelo botão **Destruir pasta…** na aba *Varredura*, pelo menu de contexto do Explorer e ao clicar em **Apagar** na aba *Quarentena*.
- **Windows, botão "Analisar" (hash)**: nos achados e na aba *Quarentena*, consulta apenas o hash SHA-256 no Team Cymru MHR e no CIRCL hashlookup fora da thread da interface (gratuito, sem chave).
- **Windows, menu de contexto no Explorer (HKCU, sem administrador)**: **Varrer com Mandacaru** (`--scan`) em arquivos, pastas e fundo de pasta, e **Destruir definitivamente com Mandacaru** (`--shred`) em clique direto sobre arquivo/pasta, com encaminhamento para a instância já aberta (no Windows 11, use `Shift + botão direito` ou *Mostrar mais opções*).
- **Windows, pastas ignoradas na varredura**: nova seção na aba *Confiáveis* (`excludes.json` atômico) para adicionar/remover pastas que devem ser puladas.
- **5 novas regras YARA** (`base.yar`, Linux e Windows): `JS_Exec_Decoded_Payload`, `Cron_Persistence_From_Script`, `Win_LOLBin_Download_Exec`, `Win_Persistence_Registry_Or_Task` e `Prompt_Injection_Hidden_Unicode`.
- **Motor e CLI ML**: `mandacaru ml avaliar --jsonl` imprime em streaming (`flush=True`), recusa `--json` + `--jsonl` juntos e trata CRLF e bytes UTF-8 inválidos no `--stdin`; `Engine` passa a usar `SCRIPT_EXT` completo em `process_start` e `BehaviorEngine` amplia credenciais monitoradas em agentes de IA (`.npmrc`, `.pypirc`, `.config/gh/`, `.azure/`, `.config/gcloud/`).

## 0.7.0

Atualizações: o Mandacaru passa a mostrar os programas desatualizados e vulneráveis e a atualizá-los com um clique, e se atualiza sozinho no Windows.

- **Windows, aba "Atualizações"**: verificação rápida (segundos: programas com versão nova pelo `winget` + falhas já usadas em ataques, catálogo CISA KEV) e completa (minutos: + CVEs na NVD com cache e atualizações pendentes do Windows Update, só leitura). Lista com os de risco "Explorada" ou "Alta" já marcados e botão "Atualizar selecionados" (`winget upgrade` um por vez, com resultado por programa e registro no Histórico). Sem `winget`, explica e leva à Microsoft Store.
- **Windows, autoatualização**: ao abrir (no máximo 1×/dia) consulta a versão mais recente e mostra a faixa "Mandacaru X disponível"; "Atualizar agora" baixa só do GitHub do projeto, confere o SHA-256 publicado, instala em silêncio e reabre. "Depois" adia 7 dias. Também em Ajuda → Verificar atualizações.
- **Linux, `mandacaru atualizacoes listar [--completo] [--json]`**: pendências de apt, Snap e Flatpak com o risco das CVEs do pacote-fonte (OSV/KEV); os de risco alto vêm pré-selecionados.
- **Linux, `mandacaru atualizacoes aplicar (--selecionados | nomes…)`**: pede a senha de administrador (pkexec, nova ação polkit `io.github.vandyckln.mandacaru.update`) e roda só `apt-get install --only-upgrade`, `snap refresh` ou `flatpak update --system` com nomes validados pelo auxiliar `/usr/libexec/mandacaru/update-packages`. Flatpak do usuário atualiza sem senha. O serviço do Mandacaru continua sem rede como root.
- `KevCache` guarda fabricante, produto e data de cada falha do KEV.
- **`mandacaru.exe` (linha de comando) com dois cliques**: antes abria e fechava na hora (sem argumentos só mostrava o uso). Agora varre Downloads, Documentos e Área de Trabalho, diz se achou algo e espera um Enter para fechar. Com argumentos continua igual. A versão com janela continua sendo o `Mandacaru-*-setup.exe`.

## 0.6.1

Versão para Windows com interface gráfica (pacote `mandacaru-windows`).

- Janela com varredura de Downloads, Área de Trabalho, pasta ou arrastar e soltar; achados com Abrir local, Ignorar sempre e Quarentena.
- Quarentena do usuário com restauração conferida por hash; abas Confiáveis e Histórico.
- Instalador por usuário (sem administrador), ícone próprio e anexado ao release.

## 0.6.0

Classificador local de malware por IA (o motor completo, ainda sem modelo instalado) e o Mandacaru volta a rodar no Windows, agora também como `mandacaru.exe`.

- **Windows**: `mandacaru scan` quebrava ao abrir (`ModuleNotFoundError: grp`). `grp`, `pwd` e `fcntl` agora são opcionais; no Windows só a varredura funciona (sem serviço, socket de alertas nem quarentena).
- **`mandacaru.exe`**: executável único para Windows (PyInstaller) anexado à release, com o SHA-256 ao lado. O CI testa o exe numa pasta limpa e numa amostra antes de publicar.

- **Pacote `mandacaru.ml`**: tipo do arquivo pelo conteúdo (ELF executável e scripts sh, Python, Perl, JS, PHP), leitor de ELF tolerante a arquivos hostis, ~60 características por tipo, modelo em JSON estrito (nada de pickle) avaliado em Python puro, motivos em português e técnicas MITRE.
- **Decisão por faixas** (`alto`, `reforco`, `medio`, `baixo`), com limiar próprio no `/tmp` e reforço quando uma regra `MEDIUM` concorda. Arquivo idêntico a um de pacote instalado (md5 do dpkg) nunca é isolado pelo modelo.
- **Alertas `ml.malware`, `ml.malware_reforco` e `ml.suspeito`**; o motor só isola com `ml_isolate`, que exige modo `isolate` e portão de qualidade aprovado no próprio modelo. O modelo nunca rebaixa um alerta de regra.
- **Seção `[ml]`** (`enabled`, `mode = off | shadow | alert | isolate`; padrão `shadow`) e registro do modo sombra em `/var/log/mandacaru/ml-shadow.jsonl`.
- **Comandos `mandacaru ml status | avaliar | sombra`**.
- Telemetria (opt-in) leva `model_id` e nota quando o caso veio do classificador.
- No SUPRA (i5-9300H): mediana de 12,7 ms e p99 de 101 ms por programa analisado.

## 0.5.0

Auditoria de CVEs e telemetria opt-in, sem rede no serviço privilegiado.

- **`mandacaru vuln scan`**: cruza os pacotes do dpkg com o OSV.dev e a CISA KEV, calcula o CVSS 3.1 localmente e prioriza o que está carregado em processos (`CRITICAL_ACTIVE`). Entende avisos de distro (USN, DSA, `UBUNTU-CVE-*`): tira as CVEs de `upstream`/`related`, usa a prioridade do Ubuntu quando não há CVSS e descarta aviso que só repete CVEs já listadas. Detalhes em paralelo; falha de rede usa o cache antigo. Saída `2` se houver achado alto. Ubuntu, Debian e derivados (Mint, Pop!_OS, LMDE).
- **Timer diário** `mandacaru-vuln-scan.timer`, rodando como o usuário novo `_mandacaru-net` (sem capabilities, `ProtectSystem=strict`). A leitura do `/proc` roda antes, como root e sem rede (`vuln snapshot-running`). O relatório fica em `/var/lib/mandacaru/vuln_cache/last-scan.json` e o monitor transforma os achados altos novos em alertas `vuln.cve_local` (arquivo e socket), com resumo acima de 5.
- **`mandacaru telemetry`** (`status`, `review`, `approve`, `reject`, `flush`): fila local com aprovação manual. Cada arquivo isolado entra como relatório sanitizado (hash, tamanho, tipo, regras, MITRE; sem caminho, usuário ou IP interno). Destinos: MISP próprio (chave só em `/etc/mandacaru/secrets.env`) e Threat Hub. O envio roda como `_mandacaru-net` via spool (`export`/`send`/`import`), sem acesso à fila nem à quarentena. Timer `mandacaru-telemetry.timer`, desligado na instalação.
- Seções novas no config: `[vuln]` e `[telemetry]` (desligada por padrão). O `config.toml` passa a `root:_mandacaru-net 0640`.

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
