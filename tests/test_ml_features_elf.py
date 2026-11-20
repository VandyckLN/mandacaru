"""Caracteristicas de ELF: amostras inofensivas montadas a mao que imitam tecnicas de malware."""
import os
import random
import time

import pytest
from ml_elf import make_elf

from mandacaru.ml.features import ELF_FEATURE_NAMES, ExtractionBudgetExceeded, extract_elf

TEXT = (".text", 1, 0x6, 0x401000, b"\x90" * 256)


def feat(data):
    return dict(zip(ELF_FEATURE_NAMES, extract_elf(data), strict=True))


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
    rnd = os.urandom(200_000)
    f = feat(make_elf(sections=[("UPX0", 8, 0x6, 0x400000, b""), ("UPX1", 1, 0x6, 0x500000, rnd)],
                      segments=[(1, 7)]))
    assert f["upx"] == 1 and f["entropia_max_secao"] > 7.5 and f["segmento_wx"] == 1
    assert f["secoes_anomalas"] == 2 and f["tem_symtab"] == 0


def test_ips_so_dentro_das_strings():
    f = feat(make_elf(sections=[TEXT, (".rodata", 1, 2, 0x402000, b"conecta 203.0.113.9 agora\x00")]))
    assert f["ip_literais"] == 1


def test_orcamento_estourado():
    with pytest.raises(ExtractionBudgetExceeded):
        extract_elf(make_elf(sections=[TEXT]), budget_s=0.0)


def test_entradas_aleatorias_nunca_levantam():
    rnd = random.Random(7)
    for _ in range(2000):
        data = b"\x7fELF" + bytes(rnd.getrandbits(8) for _ in range(rnd.randrange(0, 4096)))
        assert len(extract_elf(data)) == len(ELF_FEATURE_NAMES)


def test_pior_caso_limitado():
    big = make_elf(sections=[(f".s{i}", 1, 2, 0x400000 + i * 0x10000, os.urandom(60_000)) for i in range(60)])
    t = time.perf_counter()
    extract_elf(big)
    assert time.perf_counter() - t < 0.25
