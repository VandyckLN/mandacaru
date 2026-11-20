"""Caracteristicas numericas do conteudo do arquivo, o que o modelo enxerga.

Uma so fonte da verdade: o treino (tools/treino) importa este mesmo modulo. Tudo vem do conteudo, nunca do nome
ou do caminho. O custo e limitado por janelas fixas de leitura; o tempo e conferido entre as etapas.
"""
from __future__ import annotations

import math
import re
import time
from collections import Counter

from .elf import SHT_NOBITS, parse_elf
from .kind import SCRIPT_KINDS

FEATURE_VERSION = 1

HEAD_HIST = 64 * 1024              # histograma/entropia de cabeca
TEXT_WINDOW = 1024 * 1024          # strings e indicadores
SECTION_SAMPLE = 16 * 1024         # amostra de entropia por secao (16 KB bastam para estimar ate 8 bits)
SECTION_TOTAL = 128 * 1024         # amostra de entropia somando todas as secoes (teto do spec: 512 KB)
MAX_STRINGS = 200_000
COUNT_CAP = 1000

INDICATORS: dict[str, tuple[bytes, ...]] = {
    "mineracao": (b"stratum+tcp", b"stratum+ssl", b"xmrig", b"cryptonight", b"randomx", b"nicehash", b"monero"),
    "persistencia": (b"crontab", b"/etc/cron", b"/etc/systemd/system", b"systemctl enable", b"/etc/rc.local",
                     b".bashrc", b".profile", b"authorized_keys", b"/etc/init.d"),
    "credenciais": (b"/etc/shadow", b"/etc/passwd", b"id_rsa", b".ssh/", b".aws/credentials", b".docker/config.json",
                    b"wallet.dat"),
    "antianalise": (b"tracerpid", b"ld_preload", b"/etc/ld.so.preload", b"ptrace_traceme"),
    "download": (b"wget ", b"curl ", b"tftp ", b"ftpget", b"busybox", b"urllib", b"requests.get", b"fetch("),
    "execucao": (b"chmod +x", b"chmod 777", b"/bin/sh -c", b"sh -c ", b"nohup", b"setsid", b"disown"),
    "sabotagem": (b"iptables -f", b"setenforce 0", b"ufw disable", b"pkill", b"killall", b"kill -9",
                  b"systemctl stop"),
    "autoapagamento": (b"/proc/self/exe", b"shred ", b"rm -f $0"),
    "esconderijo": (b"/tmp/.", b"/dev/shm/.", b"/var/tmp/.", b"histfile", b"history -c", b"/dev/null 2>&1"),
    "resgate": (b"your files have been encrypted", b"seus arquivos foram criptografados", b".onion", b"bitcoin",
                b"decrypt"),
    "shell_reverso": (b"/dev/tcp/", b"nc -e", b"ncat -e", b"mkfifo", b"pty.spawn", b"dup2"),
    "prompt_injection": (b"ignore previous instructions", b"ignore all previous", b"disregard previous",
                         b"you are now", b"system prompt"),
}

COMMON_NAMES: tuple[str, ...] = tuple(f"ind_{f}" for f in INDICATORS) + ("ip_literais", "urls", "user_agent")

ELF_FEATURE_NAMES: tuple[str, ...] = (
    "tamanho_log2", "entropia_cabeca", "entropia_max_secao", "classe64", "big_endian", "tipo_dyn", "arch_x86_64",
    "arch_arm", "arch_mips", "arch_outra", "n_secoes", "n_segmentos", "sem_tabela_secoes", "dinamico",
    "segmento_wx", "entrada_fora_text", "entrada_ultima_secao", "sobra_pos_estruturas_log2", "upx",
    "secoes_anomalas", "tem_symtab", "n_importacoes", "imp_rede", "imp_processo", "imp_privilegio", "imp_arquivo",
    "imp_sinal", "n_strings_log2", "strings_tam_medio",
) + COMMON_NAMES

_IMPORT_GROUPS: dict[str, frozenset[str]] = {
    "imp_rede": frozenset({"socket", "connect", "bind", "listen", "accept", "send", "sendto", "recv", "recvfrom",
                           "gethostbyname", "getaddrinfo"}),
    "imp_processo": frozenset({"execve", "execl", "execlp", "execv", "execvp", "fork", "vfork", "clone", "system",
                               "popen"}),
    "imp_privilegio": frozenset({"setuid", "setgid", "setresuid", "setreuid", "capset", "prctl", "ptrace"}),
    "imp_arquivo": frozenset({"unlink", "chmod", "fchmod", "rename", "remove", "opendir", "readdir"}),
    "imp_sinal": frozenset({"kill", "signal", "sigaction"}),
}

_STANDARD_SECTION_PREFIXES = (
    ".text", ".data", ".bss", ".rodata", ".init", ".fini", ".plt", ".got", ".dyn", ".rel", ".rela", ".note",
    ".eh_frame", ".gcc_except_table", ".comment", ".debug", ".symtab", ".strtab", ".shstrtab", ".interp", ".hash",
    ".gnu", ".ctors", ".dtors", ".jcr", ".tbss", ".tdata", ".init_array", ".fini_array", ".preinit_array", ".go",
    ".noptr", ".typelink", ".itablink", ".gopclntab", ".gosymtab", ".ARM", ".MIPS", ".mips", ".sbss", ".sdata",
    ".reginfo", ".tm_clone_table", ".stapsdt",
)

_RUNS = re.compile(rb"[\x20-\x7e]{4,}")       # trechos legiveis; "strings" sao os de 6 ou mais
_IPV4 = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")

PT_LOAD, PF_X, PF_W, SHF_ALLOC = 1, 1, 2, 2


class ExtractionBudgetExceeded(Exception):
    """A extracao passou do orcamento de tempo; o modelo nao opina sobre este arquivo."""


class _Clock:
    def __init__(self, budget_s: float) -> None:
        self.start = time.perf_counter()
        self.budget_s = budget_s

    def check(self) -> None:
        if time.perf_counter() - self.start > self.budget_s:
            raise ExtractionBudgetExceeded(f"extracao passou de {self.budget_s * 1000:.0f} ms")


def log2p(x: float) -> float:
    return math.log2(1 + max(0.0, x))


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def printable_runs(data: bytes) -> list[bytes]:
    """Trechos legiveis (4+ bytes) do primeiro 1 MB, no maximo MAX_STRINGS."""
    return _RUNS.findall(data[:TEXT_WINDOW])[:MAX_STRINGS]


def common_features(lower: bytes, runs: list[bytes]) -> list[float]:
    """Indicadores (padroes distintos por familia) nos trechos legiveis, IPs dentro deles, URLs e User-Agent.

    Os indicadores sao procurados so no texto legivel ja extraido, e nao no arquivo bruto: 75 buscas sobre 1 MB
    custavam ~60 ms num binario grande.
    """
    blob = b"\n".join(runs).lower()
    values: list[float] = [float(sum(1 for p in pats if p in blob)) for pats in INDICATORS.values()]
    strings = [r for r in runs if len(r) >= 6]
    ips = 0
    for s in strings:
        if b"." in s and _IPV4.search(s):
            ips += 1
            if ips >= COUNT_CAP:
                break
    values.append(float(ips))
    values.append(float(min(COUNT_CAP, lower.count(b"http://") + lower.count(b"https://"))))
    values.append(float(min(COUNT_CAP, lower.count(b"mozilla/"))))
    return values


def extract_elf(data: bytes, *, budget_s: float = 0.25) -> list[float]:
    clock = _Clock(budget_s)
    info = parse_elf(data)
    clock.check()

    structural = [0.0] * 24                      # de classe64 ate imp_sinal
    max_section_entropy = 0.0
    if info is not None:
        sampled = 0
        for s in info.sections:
            if sampled >= SECTION_TOTAL:
                break
            if s.type == SHT_NOBITS or s.size <= 0 or not 0 <= s.offset < len(data):
                continue
            take = min(SECTION_SAMPLE, s.size, SECTION_TOTAL - sampled)
            chunk = data[s.offset:s.offset + take]
            sampled += len(chunk)
            max_section_entropy = max(max_section_entropy, entropy(chunk))
        clock.check()

        names = [s.name for s in info.sections]
        text = next((s for s in info.sections if s.name == ".text"), None)
        allocated = [s for s in info.sections if s.flags & SHF_ALLOC and s.size > 0]
        last_alloc = max(allocated, key=lambda s: s.addr, default=None)
        imports = set(info.dyn_imports)
        machine = info.machine
        structural = [
            float(info.is64),
            float(info.big_endian),
            float(info.e_type == 3),
            float(machine == 62),
            float(machine in (40, 183)),
            float(machine == 8),
            float(machine not in (62, 40, 183, 8)),
            float(len(info.sections)),
            float(len(info.segments)),
            float(not info.has_section_table),
            float(info.has_interp),
            float(any(g.type == PT_LOAD and g.flags & PF_W and g.flags & PF_X for g in info.segments)),
            float(text is not None and not text.addr <= info.entry < text.addr + text.size),
            float(last_alloc is not None and last_alloc.addr <= info.entry < last_alloc.addr + last_alloc.size),
            log2p(len(data) - info.end_of_structures),
            float(b"UPX!" in data or any(n in ("UPX0", "UPX1", "UPX2") for n in names)),
            float(sum(1 for n in names if n and not n.startswith(_STANDARD_SECTION_PREFIXES))),
            float(info.has_symtab),
            float(len(info.dyn_imports)),
            *(float(len(imports & group)) for group in _IMPORT_GROUPS.values()),
        ]

    head_entropy = entropy(data[:HEAD_HIST])
    clock.check()
    runs = printable_runs(data)
    strings = [r for r in runs if len(r) >= 6]
    clock.check()
    lower = data[:TEXT_WINDOW].lower()
    common = common_features(lower, runs)
    clock.check()

    mean_len = sum(map(len, strings)) / len(strings) if strings else 0.0
    values = [log2p(len(data)), head_entropy, max_section_entropy, *structural,
              log2p(len(strings)), mean_len, *common]
    assert len(values) == len(ELF_FEATURE_NAMES)
    return values


SCRIPT_FEATURE_NAMES: tuple[str, ...] = tuple(f"tipo_{k}" for k in SCRIPT_KINDS) + (
    "tem_shebang", "tamanho_log2", "linhas_log2", "maior_linha_log2", "entropia", "nao_alnum", "blocos_b64",
    "maior_b64_log2", "blocos_hex", "escapes_hex", "char_codes", "exec_dinamico", "decodificacao", "baixa_e_executa",
) + COMMON_NAMES

FAMILY: dict[str, str] = {"elf": "elf", **{k: "script" for k in SCRIPT_KINDS}}

_B64 = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")
_HEX = re.compile(rb"[0-9a-fA-F]{64,}")
_HEX_ESCAPE = re.compile(rb"\\x[0-9a-fA-F]{2}")
_ALNUM_OR_SPACE = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \t\r\n")
_EXEC_DYNAMIC = (b"eval(", b"exec(", b"compile(", b"new function(", b"source <(", b"create_function(", b"assert($")
_DECODE = (b"base64 -d", b"base64 --decode", b"b64decode", b"atob(", b"fromcharcode", b"zlib", b"marshal.loads",
           b"gzinflate", b"str_rot13", b"bytes.fromhex", b"xxd -r")
_RUN_AFTER_DOWNLOAD = (b"| sh", b"| bash", b"|sh", b"|bash", b"chmod +x", b"exec(", b"eval(", b"os.system",
                       b"subprocess", b"child_process", b"popen")
_B64_CAP = 10_000
_ESCAPE_CAP = 100_000


def _count_capped(pattern: re.Pattern[bytes], text: bytes, cap: int) -> tuple[int, int]:
    """(quantidade, maior tamanho), parando no teto."""
    n = longest = 0
    for m in pattern.finditer(text):
        n += 1
        longest = max(longest, m.end() - m.start())
        if n >= cap:
            break
    return n, longest


def extract_script(kind: str, data: bytes, *, budget_s: float = 0.25) -> list[float]:
    if kind not in SCRIPT_KINDS:
        raise ValueError(f"tipo de script desconhecido: {kind!r}")
    clock = _Clock(budget_s)
    text = data[:TEXT_WINDOW]
    lower = text.lower()
    head = data[:HEAD_HIST]
    lines = text.split(b"\n")
    non_alnum = sum(1 for b in head if b not in _ALNUM_OR_SPACE) / len(head) if head else 0.0
    clock.check()

    b64_n, b64_max = _count_capped(_B64, text, _B64_CAP)
    hex_n, _ = _count_capped(_HEX, text, _B64_CAP)
    esc_n, _ = _count_capped(_HEX_ESCAPE, text, _ESCAPE_CAP)
    clock.check()

    downloads = any(p in lower for p in INDICATORS["download"])
    values = [float(kind == k) for k in SCRIPT_KINDS] + [
        float(data.startswith(b"#!")),
        log2p(len(data)),
        log2p(len(lines)),
        log2p(max(map(len, lines))),
        entropy(head),
        non_alnum,
        float(b64_n),
        log2p(b64_max),
        float(hex_n),
        float(esc_n),
        float(min(COUNT_CAP, lower.count(b"fromcharcode") + lower.count(b"chr("))),
        float(sum(1 for p in _EXEC_DYNAMIC if p in lower)),
        float(sum(1 for p in _DECODE if p in lower)),
        float(downloads and any(p in lower for p in _RUN_AFTER_DOWNLOAD)),
    ]
    runs = printable_runs(text)
    clock.check()
    values += common_features(lower, runs)
    clock.check()
    return values


def extract(kind: str, data: bytes, *, budget_s: float = 0.25) -> list[float]:
    if kind == "elf":
        return extract_elf(data, budget_s=budget_s)
    if kind in SCRIPT_KINDS:
        return extract_script(kind, data, budget_s=budget_s)
    raise ValueError(f"tipo nao suportado: {kind!r}")
