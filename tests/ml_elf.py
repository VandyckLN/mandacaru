"""Montador de ELF minimos para testes: nada executavel, so cabecalhos e secoes com bytes inofensivos."""
import struct


def _strtab(names):
    blob, offs = b"\0", []
    for n in names:
        offs.append(len(blob))
        blob += n.encode() + b"\0"
    return blob, offs


def make_elf(*, is64=True, big_endian=False, e_type=2, machine=62, entry=0x401000, sections=(), segments=(),
             dynsyms=(), shnum_override=None, shoff_override=None) -> bytes:
    """`sections`: (nome, sh_type, flags, addr, conteudo); `segments`: (p_type, p_flags)."""
    e = ">" if big_endian else "<"
    ehsize, phentsize, shentsize = (64, 56, 64) if is64 else (52, 32, 40)
    secs = [(n, t, f, a, bytes(c), 0, 0) for n, t, f, a, c in sections]   # + link, entsize
    if dynsyms:
        dynstr, offs = _strtab(dynsyms)
        sym = struct.Struct(e + ("IBBHQQ" if is64 else "IIIBBH"))
        rows = [b"\0" * sym.size]
        for off in offs:
            rows.append(sym.pack(off, 0x12, 0, 0, 0, 0) if is64 else sym.pack(off, 0, 0, 0x12, 0, 0))
        dynstr_index = len(secs) + 1
        secs.append((".dynstr", 3, 2, 0, dynstr, 0, 0))
        secs.append((".dynsym", 11, 2, 0, b"".join(rows), dynstr_index, sym.size))
    shstr, name_offs = _strtab([s[0] for s in secs] + [".shstrtab"])
    secs.append((".shstrtab", 3, 0, 0, shstr, 0, 0))

    phoff = ehsize if segments else 0
    pos = ehsize + phentsize * len(segments)
    body, placed = b"", []
    for s in secs:
        placed.append(pos + len(body))
        body += s[4]
    shoff = pos + len(body)

    ph = b""
    for p_type, p_flags in segments:
        if is64:
            ph += struct.pack(e + "IIQQQQQQ", p_type, p_flags, 0, 0x400000, 0x400000, ehsize, ehsize, 0x1000)
        else:
            ph += struct.pack(e + "IIIIIIII", p_type, 0, 0x400000, 0x400000, ehsize, ehsize, p_flags, 0x1000)
    sh = b"\0" * shentsize
    for (_name, t, f, a, c, link, ent), off, noff in zip(secs, placed, name_offs, strict=True):
        if is64:
            sh += struct.pack(e + "IIQQQQIIQQ", noff, t, f, a, off, len(c), link, 0, 1, ent)
        else:
            sh += struct.pack(e + "IIIIIIIIII", noff, t, f, a, off, len(c), link, 0, 1, ent)
    shnum = len(secs) + 1 if shnum_override is None else shnum_override
    shoff_hdr = shoff if shoff_override is None else shoff_override
    ident = b"\x7fELF" + bytes([2 if is64 else 1, 2 if big_endian else 1, 1]) + b"\0" * 9
    if is64:
        hdr = struct.pack(e + "HHIQQQIHHHHHH", e_type, machine, 1, entry, phoff, shoff_hdr, 0, ehsize, phentsize,
                          len(segments), shentsize, shnum, len(secs))
    else:
        hdr = struct.pack(e + "HHIIIIIHHHHHH", e_type, machine, 1, entry, phoff, shoff_hdr, 0, ehsize, phentsize,
                          len(segments), shentsize, shnum, len(secs))
    return ident + hdr + ph + body + sh
