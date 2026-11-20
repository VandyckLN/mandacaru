"""Casos hostis levantados na revisao final: cada teste reproduz um achado."""
import os
import random
import struct
import time

from mandacaru.ml.features import extract_elf, extract_script
from mandacaru.ml.kind import detect_kind


def _elf_com_dynsym_sobrepostas(n_secoes: int, n_simbolos: int) -> bytes:
    """ELF64 com uma regiao de simbolos (st_shndx != 0, nada e importado) e N secoes DYNSYM apontando para ela."""
    sym = struct.pack("<IBBHQQ", 1, 0x12, 0, 1, 0, 0) * n_simbolos     # st_shndx = 1
    strtab = b"\0nome\0"
    data_off = 64
    sym_off, str_off = data_off, data_off + len(sym)
    shoff = str_off + len(strtab)
    shdrs = b"\0" * 64
    shdrs += struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, str_off, len(strtab), 0, 0, 1, 0)          # 1: STRTAB
    for _ in range(n_secoes):
        shdrs += struct.pack("<IIQQQQIIQQ", 0, 11, 2, 0, sym_off, len(sym), 1, 0, 8, 24)        # DYNSYM
    hdr = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, shoff, 0, 64, 56, 0, 64, n_secoes + 2, 0)
    return b"\x7fELF\x02\x01\x01" + b"\0" * 9 + hdr + sym + strtab + shdrs


def test_dynsym_sobrepostas_nao_prendem_o_motor():
    data = _elf_com_dynsym_sobrepostas(n_secoes=64, n_simbolos=50_000)
    t = time.perf_counter()
    extract_elf(data, budget_s=99)
    assert time.perf_counter() - t < 0.25


def test_detect_kind_linear_com_muitas_linhas_vazias():
    t = time.perf_counter()
    for _ in range(10):
        detect_kind(b"\n" * 4096 + b"x")
    assert (time.perf_counter() - t) / 10 < 0.02


def test_um_a_tres_bytes_nunca_tem_tipo():
    for data in (b"fi", b"$(", b"$(x", b"<?p"):
        assert detect_kind(data) is None


def _js_minificado(n: int) -> bytes:
    rnd = random.Random(3)
    nomes, pontuacao = [b"a", b"b", b"c", b"_0", b"e1"], [b"=", b"(", b")", b";", b",", b".", b"{", b"}"]
    out = bytearray()
    while len(out) < n:
        out += rnd.choice(nomes) + rnd.choice(pontuacao)
    return bytes(out[:n])


def test_js_minificado_de_1mb_dentro_do_orcamento():
    data = _js_minificado(1024 * 1024)
    t = time.perf_counter()
    extract_script("js", data)                      # nao pode estourar o orcamento de 250 ms
    assert time.perf_counter() - t < 0.25


def test_regex_adversarial_de_1mb_abaixo_de_200ms():
    for bloco in (b"A" * 39 + b"!", b"a" * 63 + b"!"):
        data = bloco * (1024 * 1024 // len(bloco))
        t = time.perf_counter()
        extract_script("sh", data)
        assert time.perf_counter() - t < 0.2


def test_shadow_writer_sobrevive_a_rotacao(tmp_path):
    import json

    from mandacaru.cli import shadow_writer
    p = tmp_path / "ml-shadow.jsonl"
    w = shadow_writer(str(p))
    w({"n": 1})
    os.rename(p, tmp_path / "ml-shadow.jsonl.1")    # o logrotate renomeia (e depois compacta)
    w({"n": 2})
    assert [json.loads(x)["n"] for x in p.read_text().splitlines()] == [2]


def test_motivo_nunca_contradiz_o_arquivo():
    import json

    from ml_model import model_dict, stump

    from mandacaru.ml.explain import top_reasons
    from mandacaru.ml.features import ELF_FEATURE_NAMES
    from mandacaru.ml.model import parse_model
    i_sym, i_upx, i_rede = (ELF_FEATURE_NAMES.index(n) for n in ("tem_symtab", "upx", "imp_rede"))
    # caminhos em que o valor "errado" empurra a nota para cima
    trees = [stump(i_sym, 0.5, -1.0, 2.0), stump(i_upx, 0.5, 2.0, -1.0), stump(i_rede, 0.5, 2.0, -1.0)]
    m = parse_model(json.dumps(model_dict(trees=trees)).encode())
    x = [0.0] * len(ELF_FEATURE_NAMES)
    x[i_sym] = 1.0                                   # TEM simbolos, nao e compactado, nao usa rede
    assert top_reasons(m, x, k=5) == []
