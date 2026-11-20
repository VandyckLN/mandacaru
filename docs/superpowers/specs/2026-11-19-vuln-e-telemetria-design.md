# Scanner de CVEs locais (OSV.dev/CVSS) e Telemetria Segura (MISP/MalwareBazaar) — design

Data: 2026-11-19 · Tamanho: nova frente arquitetural (v0.5.0)

## Intenção

Escalonar o Mandacaru de um monitor/EDR focado em execução local para um antivírus Linux moderno,
gratuito e completo, capaz de:

1. **Auditar vulnerabilidades locais (CVE/CVSS)** dos pacotes instalados no sistema operacional,
   priorizando o que tem exploração ativa (CISA KEV) e binários/bibliotecas realmente carregados em memória.
2. **Contribuir com inteligência de ameaças nacional e global** (MISP compatível com CSIRTs/CERT.br e
   MalwareBazaar via Threat Hub) sem comprometer a privacidade do usuário (LGPD by Design).

## Objetivos / não-objetivos

- **Objetivos:**
  - Zero dependências Python novas (apenas biblioteca padrão + `sqlite3` + `urllib`).
  - Separação estrita de privilégios: nenhum cliente HTTP/JSON roda no daemon privilegiado `mandacaru.service`.
    Os novos serviços executam como usuário sem privilégios `_mandacaru-net` com `ProtectHome=yes` e
    `CapabilityBoundingSet=` vazio.
  - Telemetria desligada por padrão (`level = "off"`) e aprovação manual habilitada (`require_approval = true`).
  - Nenhuma chave de API embutida no pacote `.deb` nem salva em `config.toml` no caso do MISP self-hosted.
- **Não-objetivos desta entrega:**
  - Bloqueio síncrono via `fanotify` ou reescrita do hot path em Rust (previstos para fase posterior).
  - Backend do Mandacaru Threat Hub (este repositório entrega o cliente/agente e o contrato de payload v1.0).

## Arquitetura

### 1. Módulo `src/mandacaru/vuln/`
- `inventory.py`: lê `/var/lib/dpkg/status` sem invocar subprocessos, resolve o campo `Source:`
  (exigido pelo OSV.dev para evitar falsos positivos/negativos em pacotes binários Debian/Ubuntu) e
  identifica pacotes com executáveis/bibliotecas ativamente mapeados em `/proc/<pid>/{exe,maps}`.
- `osv_client.py`: envia consultas em lote (`POST https://api.osv.dev/v1/querybatch`, até 500 pacotes por
  requisição) e persiste detalhes das vulnerabilidades em SQLite (`/var/lib/mandacaru/vuln_cache/osv.db`, TTL 24h).
- `kev_cache.py`: mantém cache SQLite local do catálogo CISA KEV; falhas de rede caem silenciosamente no cache.
- `scorer.py`: implementa o cálculo oficial de Base Score **CVSS v3.1** (sem libs externas) e classifica:
  - `CRITICAL_ACTIVE`: CVSS >= 7.0 (ou presente no CISA KEV) **e** pacote ativo em `/proc`.
  - `HIGH`: CVSS >= 7.0 (ou KEV), sem execução ativa detectada.
  - `MEDIUM` / `LOW`: abaixo do limiar de alerta imediato.
- `cli.py`: subcomando `mandacaru vuln scan` com saída humana, `--json` e `--emit-alerts`.

### 2. Módulo `src/mandacaru/telemetry/`
- `sanitizer.py`:
  - `is_sample_allowed()`: bloqueia extensões pessoais (`.pdf`, `.docx`, `.env`, `.pem`, `.key`, etc.),
    symlinks e arquivos acima do limite configurado; aceita apenas executáveis ELF (`\x7fELF`) ou scripts (`#!`).
  - `sanitize_text()`: substitui `/home/<usuario>` por `/home/$USER` e redige tokens Bearer, chaves AWS,
    senhas em flags e credenciais em URLs.
  - `is_public_ip()`: filtra IPs RFC 1918, loopback e link-local antes de incluir IOCs de rede.
- `outbox.py`: fila SQLite local (`/var/lib/mandacaru/telemetry/outbox.db`) deduplicada por `sha256`
  com ciclo de vida `PENDING -> APPROVED -> SENT | FAILED` (ou `REJECTED`).
- `mappers.py`: gera payloads nativos de **MISP Event** (`/events/add`) com tags `tlp:clear`/`tlp:green`
  e galáxia `misp-galaxy:mitre-attack-pattern`, além de metadados normalizados para MalwareBazaar.
- `dispatcher.py`: envia somente itens `APPROVED` quando `telemetry.level != "off"`.
  - Modo comunitário: envia para o endpoint do Mandacaru Threat Hub (sem API key global no agente).
  - Modo self-hosted: envia para MISP privado usando chave lida exclusivamente de `MANDACARU_MISP_API_KEY`
    (via `/etc/mandacaru/secrets.env`), com `HTTPRedirectHandler` que remove cabeçalhos sensíveis em redirects.
- `cli.py`: subcomandos `mandacaru telemetry status|review|approve|reject|flush`.

## Empacotamento Debian (`debian/`)

- `debian/mandacaru.mandacaru-vuln-scan.service` + `.timer`: auditoria diária (`RandomizedDelaySec=1h`,
  `OnBootSec=10min`) sob `_mandacaru-net`.
- `debian/mandacaru.mandacaru-telemetry.service`: instalado desabilitado (`--no-enable --no-start`)
  para respeitar o modelo estritamente opt-in.
- `debian/mandacaru.postinst`: cria o usuário de sistema `_mandacaru-net` antes do `#DEBHELPER#`.
