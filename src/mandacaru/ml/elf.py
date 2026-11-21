"""Leitor de ELF em Python puro para o classificador.

Roda dentro do monitor (root) sobre arquivos hostis: nada do arquivo e confiado. Toda leitura confere limites,
contagens sao limitadas e uma estrutura que nao cabe e ignorada (o resto continua). Nunca levanta.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

MAX_SECTIONS = 4096
MAX_IMPORTS = 50_000
_MAX_SEGMENTS = 4096
_MAX_NAME = 64
_MAX_SYMNAME = 256
SHT_SYMTAB, SHT_STRTAB, SHT_NOBITS, SHT_DYNSYM = 2, 3, 8, 11
PT_INTERP = 3


@dataclass(frozen=True)
class Section:
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int


@dataclass(frozen=True)
class Segment:
    type: int
    flags: int
    offset: int
    filesz: int


@dataclass(frozen=True)
class ElfInfo:
    is64: bool
    big_endian: bool
    e_type: int
    machine: int
    entry: int
    sections: tuple[Section, ...]
    segments: tuple[Segment, ...]
    has_section_table: bool
    has_interp: bool
    has_symtab: bool
    dyn_imports: tuple[str, ...]
    end_of_structures: int


def _unpack(fmt: struct.Struct, data: bytes, off: int) -> tuple | None:
    if off < 0 or off + fmt.size > len(data):
        return None
    return fmt.unpack_from(data, off)


def _cstr(data: bytes, off: int, limit: int) -> str:
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\0", off, off + limit)
    raw = data[off:end] if end != -1 else data[off:off + limit]
    return raw.decode("ascii", "replace")


def _table_count(declared: int, off: int, entsize: int, total: int, cap: int) -> int:
    if off <= 0 or entsize <= 0 or off >= total:
        return 0
    return max(0, min(declared, cap, (total - off) // entsize))


def parse_elf(data: bytes) -> ElfInfo | None:
    if len(data) < 52 or not data.startswith(b"\x7fELF") or data[4] not in (1, 2) or data[5] not in (1, 2):
        return None
    is64 = data[4] == 2
    e = ">" if data[5] == 2 else "<"
    hdr = struct.Struct(e + ("HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH"))
    head = _unpack(hdr, data, 16)
    if head is None:
        return None
    e_type, machine, _ver, entry, phoff, shoff, _flags, _ehsize, phentsize, phnum, shentsize, shnum, shstrndx = head
    n = len(data)
    end = 64 if is64 else 52

    ph_fmt = struct.Struct(e + ("IIQQQQQQ" if is64 else "IIIIIIII"))
    segments: list[Segment] = []
    if phentsize >= ph_fmt.size:
        for i in range(_table_count(phnum, phoff, phentsize, n, _MAX_SEGMENTS)):
            row = _unpack(ph_fmt, data, phoff + i * phentsize)
            if row is None:
                break
            if is64:
                p_type, p_flags, p_off, _va, _pa, p_filesz = row[:6]
            else:
                p_type, p_off, _va, _pa, p_filesz, _memsz, p_flags = row[:7]
            segments.append(Segment(p_type, p_flags, p_off, p_filesz))
            end = max(end, phoff + (i + 1) * phentsize)

    sh_fmt = struct.Struct(e + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII"))
    raw_secs: list[tuple] = []
    if shentsize >= sh_fmt.size:
        for i in range(_table_count(shnum, shoff, shentsize, n, MAX_SECTIONS)):
            row = _unpack(sh_fmt, data, shoff + i * shentsize)
            if row is None:
                break
            raw_secs.append(row)
        if raw_secs:
            end = max(end, shoff + len(raw_secs) * shentsize)
    has_table = bool(raw_secs)

    names_off = None
    if 0 <= shstrndx < len(raw_secs):
        names_off = raw_secs[shstrndx][4]
    sections: list[Section] = []
    for name_i, s_type, s_flags, s_addr, s_off, s_size, *_rest in raw_secs:
        name = _cstr(data, names_off + name_i, _MAX_NAME) if names_off is not None else ""
        sections.append(Section(name, s_type, s_flags, s_addr, s_off, s_size))
        if s_type != SHT_NOBITS and 0 <= s_off <= n:
            end = max(end, min(n, s_off + s_size))

    # o teto vale para simbolos EXAMINADOS (spec 8), somando todas as secoes DYNSYM; secoes repetidas (mesmo
    # deslocamento e tamanho) sao lidas uma vez so, senao N secoes sobrepostas multiplicariam o custo
    imports: list[str] = []
    examined = 0
    seen: set[tuple[int, int]] = set()
    sym_fmt = struct.Struct(e + ("IBBHQQ" if is64 else "IIIBBH"))
    for row in raw_secs:
        if row[1] != SHT_DYNSYM or examined >= MAX_IMPORTS:
            continue
        s_off, s_size, link, entsize = row[4], row[5], row[6], row[9]
        if (s_off, s_size) in seen:
            continue
        seen.add((s_off, s_size))
        entsize = entsize if entsize >= sym_fmt.size else sym_fmt.size
        if not 0 <= link < len(raw_secs) or raw_secs[link][1] != SHT_STRTAB:
            continue
        str_off = raw_secs[link][4]
        count = min(s_size // entsize, MAX_IMPORTS - examined, max(0, (n - s_off) // entsize))
        examined += count
        for k in range(1, count):                       # o simbolo 0 e sempre nulo
            sym = _unpack(sym_fmt, data, s_off + k * entsize)
            if sym is None:
                break
            st_name, st_shndx = (sym[0], sym[3]) if is64 else (sym[0], sym[5])
            if st_shndx == 0 and st_name:
                nm = _cstr(data, str_off + st_name, _MAX_SYMNAME)
                if nm:
                    imports.append(nm)

    return ElfInfo(
        is64=is64,
        big_endian=e == ">",
        e_type=e_type,
        machine=machine,
        entry=entry,
        sections=tuple(sections),
        segments=tuple(segments),
        has_section_table=has_table,
        has_interp=any(s.type == PT_INTERP for s in segments),
        has_symtab=any(s.type == SHT_SYMTAB for s in sections),
        dyn_imports=tuple(imports),
        end_of_structures=end,
    )
