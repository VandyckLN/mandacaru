"""Leitor de ELF: entende cabecalhos validos e nunca levanta com arquivo truncado ou hostil."""
from ml_elf import make_elf

from mandacaru.ml.elf import MAX_SECTIONS, parse_elf

TEXT = (".text", 1, 0x6, 0x401000, b"\x90" * 64)


def test_elf_basico():
    info = parse_elf(make_elf(sections=[TEXT], segments=[(1, 5), (3, 4)], dynsyms=["socket", "execve"]))
    assert info.is64 and not info.big_endian and info.e_type == 2 and info.machine == 62
    assert [s.name for s in info.sections][:2] == ["", ".text"]
    assert info.has_interp is True                        # PT_INTERP = 3
    assert set(info.dyn_imports) == {"socket", "execve"}
    assert info.has_section_table and not info.has_symtab


def test_elf_32_big_endian_mips():
    info = parse_elf(make_elf(is64=False, big_endian=True, machine=8, sections=[TEXT], dynsyms=["fork"]))
    assert not info.is64 and info.big_endian and info.machine == 8
    assert info.dyn_imports == ("fork",)


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
