"""Tipo do arquivo pelo conteudo (nunca pelo nome): ELF executavel ou um dos scripts suportados."""
from __future__ import annotations

import re

KINDS: tuple[str, ...] = ("elf", "sh", "python", "perl", "js", "php")
SCRIPT_KINDS: tuple[str, ...] = KINDS[1:]

_ELF_RUNNABLE = (2, 3)  # ET_EXEC, ET_DYN; ET_REL (.o) e ET_CORE nao executam
_SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "ash", "busybox"}
_HEAD = 4096
_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}

# marcadores de conteudo para script sem shebang, na ordem em que sao testados
_MARKERS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("php", re.compile(rb"<\?php")),
    ("python", re.compile(rb"(?m)^(?:import [\w.]+|from [\w.]+ import |def \w+\()")),
    ("js", re.compile(rb"require\(|module\.exports|=> \{")),
    ("perl", re.compile(rb"use strict;|my \$")),
    ("sh", re.compile(rb"(?m)^\s*(?:fi|then|esac)\b|\$\(")),
)


def _from_shebang(line: bytes) -> str | None:
    tokens = line[2:].split()
    if not tokens:
        return None
    interp = tokens[0].rsplit(b"/", 1)[-1]
    if interp == b"env":
        rest = [t for t in tokens[1:] if not t.startswith(b"-")]
        if not rest:
            return None
        interp = rest[0].rsplit(b"/", 1)[-1]
    name = interp.decode("ascii", "replace")
    if name in _SHELLS:
        return "sh"
    if name.startswith("python"):
        return "python"
    if name == "perl":
        return "perl"
    if name in ("node", "nodejs"):
        return "js"
    if name.startswith("php"):
        return "php"
    return None


def _is_text(head: bytes) -> bool:
    if not head or b"\0" in head:
        return False
    return sum(b in _PRINTABLE for b in head) >= 0.9 * len(head)


def detect_kind(data: bytes) -> str | None:
    """"elf", um de SCRIPT_KINDS ou None (nao suportado)."""
    if data.startswith(b"\x7fELF"):
        if len(data) < 18:
            return None
        order = "big" if data[5] == 2 else "little"
        return "elf" if int.from_bytes(data[16:18], order) in _ELF_RUNNABLE else None
    if data.startswith(b"#!"):
        return _from_shebang(data[:256].split(b"\n", 1)[0])
    head = data[:_HEAD]
    if not _is_text(head):
        return None
    for kind, marker in _MARKERS:
        if marker.search(head):
            return kind
    return None
