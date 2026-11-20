"""Coleta no MalwareBazaar: HTTP falso, so bytes inofensivos."""
import hashlib
import json
import urllib.error
import zipfile

import pytest

pytest.importorskip("pyzipper")
from helpers import zip_aes

from tools.treino import baixar
from tools.treino.baixar import coletar
from tools.treino.corpus import Corpus

AMOSTRAS = {hashlib.sha256(f"amostra {i}".encode()).hexdigest(): f"amostra {i}".encode() for i in range(6)}


def http_falso(limite_depois=None):
    chamadas = []
    def http(url, cab, campos):
        chamadas.append(campos)
        assert cab["Auth-Key"] == "segredo"
        if campos["query"] == "get_file_type":
            data = [{"sha256_hash": s, "signature": "FamA" if i < 4 else None, "reporter": "r1",
                     "first_seen": f"2026-11-0{i + 1} 00:00:00", "file_type": campos["file_type"]}
                    for i, s in enumerate(AMOSTRAS)] if campos["file_type"] == "elf" else []
            return 200, json.dumps({"query_status": "ok" if data else "no_results", "data": data}).encode()
        n = sum(1 for c in chamadas if c["query"] == "get_file")
        if limite_depois is not None and n > limite_depois:
            return 200, json.dumps({"query_status": "daily_limit_reached"}).encode()
        s = campos["sha256_hash"]
        return 200, zip_aes(s, AMOSTRAS[s])
    return http, chamadas


def test_coleta_com_tetos_e_sem_repetir(tmp_path):
    c = Corpus(tmp_path / "c")
    http, _ = http_falso()
    r = coletar(c, chave="segredo", http=http, cota=10, max_por_familia=3)
    assert r.baixados == 5 and r.parou is None                    # 3 da FamA + 2 sem familia
    http2, chamadas2 = http_falso()
    assert coletar(c, chave="segredo", http=http2, cota=10, max_por_familia=3).baixados == 0
    assert not [x for x in chamadas2 if x["query"] == "get_file"]  # nada baixado de novo


def test_catalogo_historico_filtra_por_data_e_familia(tmp_path):
    cat = tmp_path / "full.csv.zip"
    linhas = ['# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name",'
              '"file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"\n']
    shas = list(AMOSTRAS)
    linhas.append(f'"2025-01-01 00:00:00","{shas[0]}","","","r1","a","elf","","FamA","","","","",""\n')
    linhas.append(f'"2026-06-01 00:00:00","{shas[1]}","","","r1","b","elf","","FamA","","","","",""\n')
    linhas.append(f'"2026-07-01 00:00:00","{shas[2]}","","","r2","c","sh","","n/a","","","","",""\n')
    with zipfile.ZipFile(cat, "w") as z:
        z.writestr("full.csv", "".join(linhas))
    c = Corpus(tmp_path / "c")
    http, chamadas = http_falso()
    r = coletar(c, chave="segredo", http=http, catalogo=cat, desde="2026-01-01", cota=10)
    baixados = [x["sha256_hash"] for x in chamadas if x["query"] == "get_file"]
    assert r.baixados == 2 and set(baixados) == {shas[1], shas[2]}


def test_limite_diario_para_e_guarda_o_progresso(tmp_path):
    c = Corpus(tmp_path / "c")
    http, _ = http_falso(limite_depois=2)
    r = coletar(c, chave="segredo", http=http, cota=10)
    assert r.baixados == 2 and r.parou == "daily_limit_reached" and len(c.entries()) == 2


def test_http_padrao_recusa_redirect_para_nao_vazar_chave():
    handler = baixar._NoRedirectHandler()
    with pytest.raises(urllib.error.HTTPError):
        handler.redirect_request(None, None, 302, "Found", {}, "https://evil.invalid/")


def test_chave_nunca_aparece(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("MB_AUTH_KEY", raising=False)
    assert baixar.main(["--corpus", str(tmp_path / "c")]) == 1
    monkeypatch.setenv("MB_AUTH_KEY", "segredo")
    monkeypatch.setattr(baixar, "_http_padrao", http_falso()[0])
    baixar.main(["--corpus", str(tmp_path / "c"), "--cota", "1"])
    saida = capsys.readouterr()
    assert "segredo" not in saida.out + saida.err
