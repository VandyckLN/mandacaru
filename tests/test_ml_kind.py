"""Tipo do arquivo pelo conteudo: so ELF executavel e scripts entram no classificador."""
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
