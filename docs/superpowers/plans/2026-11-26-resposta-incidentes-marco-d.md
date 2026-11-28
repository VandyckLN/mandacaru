# Resposta a incidentes — Marco (d): serviço "Proteção avançada" (MandacaruGuard) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Backend em Python puro (sem Qt) do serviço Windows `MandacaruGuard`, que roda como SYSTEM e executa só uma lista fechada de ações privilegiadas pedidas pela janela sem privilégio, mais o cliente IPC que a janela usa.

**Architecture:** Três módulos. `guard_protocol.py` define o enquadramento (uma linha JSON por pedido e por resposta, no máximo 64 KiB) e valida cada pedido contra um esquema fechado. `guard_service.py` tem a política de caminhos, as ações (com backends injetáveis para processos, arquivos, registro e comandos) e, só no Windows, o servidor de *named pipe* via `ctypes` e o anfitrião do SCM. `guard_client.py` traz o `GuardClient`, que fala com o pipe e confere que do outro lado está o serviço instalado. A lógica de decisão roda em Linux com falsos; o que toca o Windows real roda no CI `windows.yml`.

**Tech Stack:** Python 3.10–3.13, só biblioteca padrão (`ctypes`, `winreg`, `subprocess`, `json`, `threading`, `logging`). Reaproveita `incident_proc` (processos via kernel32) e os auxiliares de `incident_persist`. Sem pywin32.

**Spec:** [docs/superpowers/specs/2026-11-26-resposta-a-incidentes-design.md](../specs/2026-11-26-resposta-a-incidentes-design.md) — seções "Restrições", "7. Serviço opcional Proteção avançada", anti-objetivos e a linha **Marco (d)** da divisão de trabalho.

## Global Constraints

- Fronteira: `windows/src/mandacaru_win/guard_*.py`, `windows/tests/test_guard_*.py` e este plano. **Não tocar** em `app.py`, `incident_ui.py` nem `installer.iss` (Antigravity).
- Nenhum módulo `guard_*.py` importa `PySide6`.
- Anti-objetivo central da spec: o serviço **não pode virar vetor de escalação de privilégio**. Daí:
  - só as ações `ping`, `terminate_process`, `quarantine_file`, `quarantine_restore`, `firewall_block`, `firewall_unblock`, `persistence_remove`, `persistence_restore`; qualquer outra coisa, chave a mais ou tipo errado → recusa;
  - **nada** sob `%SystemRoot%`, `%ProgramFiles%\Windows Defender`, `%ProgramFiles%\WindowsApps`, `%ProgramData%\Microsoft\Windows Defender` nem na pasta do próprio Guard pode ser encerrado, posto em quarentena, bloqueado ou desativado;
  - toda decisão sobre arquivo usa o **caminho final do handle aberto** (`GetFinalPathNameByHandleW`), e apagar/criar usa o **mesmo handle**: uma junção trocada no meio do caminho não redireciona o SYSTEM para outro arquivo;
  - o serviço nunca lê conteúdo de arquivo fora do necessário para conferir o SHA-256 e copiar para a quarentena, e nunca abre conexão de rede.
- Pipe `\\.\pipe\MandacaruGuard`: SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)` (usuários interativos leem e escrevem, **sem** `FILE_CREATE_PIPE_INSTANCE`), `FILE_FLAG_FIRST_PIPE_INSTANCE` (ninguém sequestra o nome antes do serviço) e `PIPE_REJECT_REMOTE_CLIENTS`.
- Cliente conferido pelo PID (`GetNamedPipeClientProcessId`): o executável precisa estar na lista `clientes` de `guard.json`, na pasta do serviço (gravada pelo instalador elevado).
- O serviço só inicia se a própria pasta estiver sob `%ProgramFiles%`/`%ProgramW6432%` (pasta só de administradores). **Requisito para o instalador (Antigravity):** instalar o Guard em `{commonpf}\Mandacaru Guard\`, nunca na pasta por usuário do app.
- Regras de firewall: nome exatamente `Mandacaru-[0-9a-f]{8,32}`; ao desinstalar, `guard_service.py remover-regras` apaga todas as `Mandacaru-*`.
- Serviços do Windows são **parados e desativados** (`start= disabled`), nunca apagados; o Desfazer devolve o tipo de início anterior.
- Toda ação é registrada em `guard.log` na pasta do serviço (ação, PID do cliente, resultado), sem conteúdo de arquivo.
- Testes sem rede e sem administrador; os que tocam o Windows real usam `skipif(sys.platform != "win32")`.
- Ao fim de cada tarefa: `cd windows && pytest -q` verde e `ruff check .` limpo; no fim, `mandacaru dev . --sem-rede` sai com 0.
- Commits sem `Co-Authored-By` (regra do dono).

## Review Focus

1. **Junção trocada entre validar e agir** (pasta do usuário vira junção para `C:\Windows\System32`) → a quarentena confere o caminho final do handle e apaga pelo handle; nada fora do caminho pedido é tocado (Tarefa 2, com backend falso que muda o caminho final).
2. **Pedido forjado por cliente não autorizado** (outro executável, ou o mesmo usuário via PowerShell) → recusado antes de interpretar o JSON (Tarefas 3 e 4).
3. **Pedido gigante, JSON malformado, chave extra, PID booleano** → recusa com erro, sem exceção no servidor (Tarefa 1).
4. **Desfazer de quarentena num caminho que agora passa por junção** → o arquivo criado é conferido pelo caminho final e apagado se caiu em outro lugar (Tarefa 2).
5. **Alvo legítimo do sistema** (`svchost.exe`, serviço com binário em `System32`, tarefa em `\Microsoft\`) → recusa, mesmo com SHA-256 correto (Tarefa 2).

---

### Task 1: Protocolo fechado (`guard_protocol.py`)

**Produces:** `MAX_MENSAGEM = 64 * 1024`; `class GuardError(Exception)`; `codificar(obj: dict) -> bytes` (JSON compacto + `\n`); `decodificar(linha: bytes) -> dict` (recusa > 64 KiB, UTF-8 inválido, não-objeto); `validar_pedido(d: dict) -> tuple[str, dict]` (devolve `(acao, params)`); `resposta_ok(**dados) -> dict` / `resposta_erro(msg) -> dict`; `caminho_valido(s) -> bool` (absoluto com letra de unidade, ≤ 32767, sem `"`, controles, `*?<>|`, sem `\\?\`); `REGRA_RE = re.compile(r"Mandacaru-[0-9a-f]{8,32}")`; `SHA_RE`; `TIPOS_PERSISTENCIA = ("hklm_run", "hklm_runonce", "startup_all", "schtask", "service")`.

Esquema (chaves exatas, nenhuma a mais): `ping {}`; `terminate_process {pid:int>4 (bool não), exe:caminho, sha256}`; `quarantine_file {caminho, sha256}`; `quarantine_restore {id: 32 hex}`; `firewall_block {regra, exe}`; `firewall_unblock {regra}`; `persistence_remove {tipo, nome, valor:str}` (para `startup_all`, `valor` é o SHA-256 do arquivo; para `schtask` e `service`, o nome basta e `valor` é `""`); `persistence_restore {backup: dict}`.

- [ ] Testes: ida e volta; `> 64 KiB`, bytes inválidos, lista no lugar de objeto; ação desconhecida; chave extra; `pid=True`, `pid=4`; caminho relativo, UNC, com aspas ou `\\?\`; regra `Mandacaru-XYZ`/`Outra-abcd1234`; tipo de persistência fora da lista. Run → FAIL; implementar; Run → PASS + ruff. Commit `feat(windows): protocolo fechado do MandacaruGuard`.

---

### Task 2: Política e ações (`guard_service.py`, parte pura)

**Produces:**
- `class Ambiente(system_root, program_files: tuple[str, ...], program_data, pasta_guard)` + `Ambiente.atual()`; `proibido(caminho_final: str, amb) -> bool` (`ntpath.normcase`, prefixo com fronteira).
- `class Arquivos(Protocol)`: `abrir(caminho) -> ArquivoAberto` com `caminho_final: str`, `ler() -> Iterator[bytes]`, `apagar() -> None`, `fechar()`; `criar_novo(caminho) -> ArquivoAberto` (falha se existir) com `escrever(b)`, `caminho_final`, `apagar()`.
- `class Comandos(Protocol)`: `run(args, timeout) -> (rc, saida)` (reaproveita `incident_persist._run_oem`).
- `class AcoesGuard(amb, *, processos, arquivos, registro, run, pasta_quarentena, pasta_inicializar_global)` com um método por ação, cada um devolvendo `dict` de resposta e nunca levantando exceção:
  - `terminate_process`: recusa alvo proibido; usa `incident_proc.encerrar_arvore` (PID + caminho + SHA-256 + hora de criação);
  - `quarantine_file`: abre, recusa se `caminho_final` difere do pedido (link/junção) ou é proibido, confere o SHA-256 ao copiar embaralhado (XOR de `quarantine.py`) para `pasta_quarentena/<id>.bin` + `.json`, apaga **pelo handle**; devolve `id`;
  - `quarantine_restore`: cria o original com `criar_novo`, confere `caminho_final` (diferente → apaga o criado e recusa), escreve, confere SHA-256;
  - `firewall_block`: exe existente, não proibido, regra ainda inexistente → `netsh advfirewall firewall add rule name=<regra> dir=out action=block program=<exe> enable=yes`; `firewall_unblock`: só `Mandacaru-*` → `delete rule name=<regra>`; `remover_todas_regras()` para a desinstalação;
  - `persistence_remove` / `persistence_restore` para `hklm_run`/`hklm_runonce` (valor exato, como no c.1), `startup_all` (arquivo da Inicializar global, conferido pelo SHA-256, backup embaralhado ≤ 1 MiB), `schtask` (recusa `\Microsoft\…`; backup = XML), `service` (recusa binário proibido ou driver; backup = `Start` anterior lido em `HKLM\SYSTEM\CurrentControlSet\Services\<nome>`; remove = `sc stop` + `sc config start= disabled`; restaura = `sc config start= <anterior>`).
- `class Despachante(acoes, *, log)`: `tratar(linha: bytes, cliente_pid: int) -> bytes` (decodifica, valida, chama a ação, registra no log, codifica; erro inesperado vira `resposta_erro("Erro interno do serviço.")`).

- [ ] Testes com falsos: um teste por regra acima, incluindo os itens 1, 4 e 5 do Review Focus, regra duplicada, `sc` falhando, backup adulterado e log sem conteúdo de arquivo. Run → FAIL; implementar; Run → PASS + ruff. Commit `feat(windows): ações e política do MandacaruGuard`.

---

### Task 3: Windows real — pipe, cliente conferido, arquivos por handle e SCM (`guard_service.py`, parte `win32`)

**Produces:** `SDDL_PIPE`, `NOME_PIPE = r"\\.\pipe\MandacaruGuard"`; `ArquivosWindows` (`CreateFileW` com `FILE_FLAG_OPEN_REPARSE_POINT`, `GetFinalPathNameByHandleW`, `SetFileInformationByHandle(FileDispositionInfo)`); `RegistroHKLM`; `class ServidorPipe(nome, despachante, verificar_cliente, *, max_conexoes=4)` com `servir()` e `parar()` (instância por conexão em thread; leitura limitada a `MAX_MENSAGEM`); `verificador_de_clientes(permitidos: list[str]) -> Callable[[int], bool]`; `carregar_config(pasta) -> list[str]`; `pasta_protegida(pasta, amb) -> bool`; `executar_servico()` (SCM via `StartServiceCtrlDispatcherW`/`RegisterServiceCtrlHandlerExW`/`SetServiceStatus`); `main(argv)` com `servico` e `remover-regras`.

- [ ] Testes: `pasta_protegida` e `carregar_config` em Linux (config ausente/corrompida → nenhum cliente); só no Windows: ida e volta de `ping` por um pipe de teste numa thread, cliente recusado quando o verificador nega, `ArquivosWindows` com caminho final e apagar por handle. Run → FAIL; implementar; Run → PASS + ruff. Commit `feat(windows): named pipe com ACL e serviço MandacaruGuard`.

---

### Task 4: Cliente IPC (`guard_client.py`)

**Produces:** `class GuardClient(*, nome=NOME_PIPE, transporte=None, timeout=10.0)` com `chamar(acao, **params) -> dict` (valida o pedido localmente com `validar_pedido`, levanta `GuardError` com a mensagem do serviço), `disponivel() -> bool` (`ping` sem levantar); transporte Windows abre o pipe, confere pelo `GetNamedPipeServerProcessId` que o servidor roda um executável sob `%ProgramFiles%` e troca uma linha.

- [ ] Testes com transporte falso (resposta ok, erro, resposta malformada, serviço ausente → `disponivel() is False`, pedido inválido nem sai); só no Windows: cliente real contra o `ServidorPipe` de teste. Run → FAIL; implementar; Run → PASS + ruff. Commit `feat(windows): cliente IPC do MandacaruGuard`.
- [ ] Verificação final: `cd windows && pytest -q`, `ruff check .`, `mandacaru dev . --sem-rede` → 0; teste de que nenhum `guard_*.py` puxa `PySide6`.
- [ ] Verificação manual no Windows (dono), depois do instalador do Antigravity: instalar com Proteção avançada; `GuardClient().disponivel()` como usuário comum; PowerShell abrindo o pipe é recusado; bloquear e desbloquear um `.exe` de teste; desinstalar apaga as regras `Mandacaru-*`.
