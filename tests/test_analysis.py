import json
import socket

import pytest

from mandacaru.analysis import (
    AnalysisResult,
    SourceResult,
    _default_http,
    _default_resolver,
    analyze,
    upload_virustotal,
)
from mandacaru.config import Config

H = "ab" * 32


class Http:
    """Http falso: mapeia trecho da URL para (status, corpo) ou excecao."""

    def __init__(self, routes=None):
        self.routes = routes or {}
        self.requests = []

    def __call__(self, req, timeout):
        self.requests.append(req)
        for frag, resp in self.routes.items():
            if frag in req.full_url:
                if isinstance(resp, Exception):
                    raise resp
                status, body = resp
                return status, json.dumps(body).encode() if not isinstance(body, bytes) else body
        return 404, b"{}"


def resolver_com(ips):
    return lambda name: ips


def nxdomain(name):
    raise socket.gaierror(-2, "nxdomain")


def cfg(**kw):
    return Config(**kw)


def nunca(name):
    raise AssertionError("resolver nao deveria ser chamado")


def test_cymru_achou_e_malicioso():
    r = analyze("id1", H, cfg(), resolver_com(["127.0.0.2"]), Http())
    assert r.sources["cymru"].status == "achou"
    assert r.verdict == "malicioso"
    assert "Team Cymru" in r.summary


def test_so_circl_achou_e_legitimo_conhecido():
    http = Http({"hashlookup.circl.lu": (200, {"FileName": "ls"})})
    r = analyze("id1", H, cfg(), nxdomain, http)
    assert r.sources["circl"].status == "achou"
    assert r.sources["circl"].detail == "ls"
    assert r.verdict == "legitimo_conhecido"


def test_ninguem_achou_e_desconhecido():
    r = analyze("id1", H, cfg(), nxdomain, Http())
    assert r.verdict == "desconhecido"
    assert r.summary == "Desconhecido: nenhuma fonte conhece este arquivo"


def test_malware_vence_circl():
    http = Http({"hashlookup.circl.lu": (200, {"FileName": "x"})})
    r = analyze("id1", H, cfg(), resolver_com(["127.0.0.2"]), http)
    assert r.verdict == "malicioso"


def test_cymru_desligado_nem_consulta():
    r = analyze("id1", H, cfg(cymru=False), nunca, Http())
    assert r.sources["cymru"].status == "desligada"


def test_chaves_ausentes_marcam_desligada():
    r = analyze("id1", H, cfg(), nxdomain, Http())
    assert r.sources["malwarebazaar"].status == "desligada"
    assert r.sources["virustotal"].status == "desligada"


def test_fonte_com_timeout_nao_impede_as_outras():
    stats = {"malicious": 3, "harmless": 7}
    http = Http({"hashlookup.circl.lu": TimeoutError("lento"),
                 "virustotal": (200, {"data": {"attributes": {"last_analysis_stats": stats}}})})
    r = analyze("id1", H, cfg(virustotal_key="K"), nxdomain, http)
    assert r.sources["circl"].status == "erro"
    assert r.sources["virustotal"].status == "achou"
    assert r.verdict == "malicioso"


def test_todas_com_erro_avisa_analise_limitada():
    def boom(name):
        raise OSError("sem rede")

    http = Http({"circl": OSError("sem rede")})
    r = analyze("id1", H, cfg(), boom, http)
    assert r.verdict == "desconhecido"
    assert r.summary == "Desconhecido: analise limitada, sem resposta das fontes"


def test_virustotal_resume_deteccoes():
    stats = {"malicious": 54, "suspicious": 1, "undetected": 10, "harmless": 5}
    http = Http({"virustotal": (200, {"data": {"attributes": {"last_analysis_stats": stats}}})})
    r = analyze("id1", H, cfg(virustotal_key="K"), nxdomain, http)
    assert r.sources["virustotal"].detail == "54/70 detectam"
    assert "VirusTotal 54/70 detectam" in r.summary


def test_virustotal_sem_deteccao_nao_achou():
    stats = {"malicious": 0, "undetected": 10}
    http = Http({"virustotal": (200, {"data": {"attributes": {"last_analysis_stats": stats}}})})
    r = analyze("id1", H, cfg(virustotal_key="K"), nxdomain, http)
    assert r.sources["virustotal"].status == "nao_achou"
    assert r.verdict == "desconhecido"


def test_malwarebazaar_achou_e_nao_achou():
    http = Http({"mb-api": (200, {"query_status": "ok", "data": [{"signature": "Mirai"}]})})
    r = analyze("id1", H, cfg(malwarebazaar_key="K"), nxdomain, http)
    assert r.sources["malwarebazaar"].status == "achou"
    assert r.sources["malwarebazaar"].detail == "Mirai"
    http = Http({"mb-api": (200, {"query_status": "hash_not_found"})})
    r = analyze("id1", H, cfg(malwarebazaar_key="K"), nxdomain, http)
    assert r.sources["malwarebazaar"].status == "nao_achou"


def test_status_inesperado_vira_erro_sem_vazar_chave():
    http = Http({"virustotal": (500, b"x")})
    r = analyze("id1", H, cfg(virustotal_key="SEGREDO"), nxdomain, http)
    assert r.sources["virustotal"].status == "erro"
    assert "SEGREDO" not in json.dumps(r.to_dict())


def test_nome_da_consulta_cymru():
    vistos = []

    def res(name):
        vistos.append(name)
        return []

    analyze("id1", H, cfg(), res, Http())
    assert vistos == [f"{H[:32]}.{H[32:]}.hash.cymru.com"]


def test_headers_de_autenticacao():
    http = Http()
    analyze("id1", H, cfg(virustotal_key="VT", malwarebazaar_key="MB"), nxdomain, http)
    by_host = {r.full_url: r for r in http.requests}
    mb = next(r for u, r in by_host.items() if "mb-api" in u)
    vt = next(r for u, r in by_host.items() if "virustotal" in u)
    assert mb.get_header("Auth-key") == "MB"
    assert vt.get_header("X-apikey") == "VT"
    assert mb.data == f"query=get_info&hash={H}".encode()
    assert all(r.get_header("User-agent").startswith("mandacaru/") for r in http.requests)


@pytest.mark.parametrize("bad", ["", "AB" * 32, "ab" * 31, "../" + "a" * 61, "g" * 64])
def test_sha256_invalido_levanta(bad):
    with pytest.raises(ValueError):
        analyze("id1", bad, cfg(), nunca, Http())


def test_upload_recusa_mais_de_32mb():
    with pytest.raises(ValueError):
        upload_virustotal(b"x" * (32 * 1024 * 1024 + 1), "a.bin", "K", Http())


def test_upload_devolve_id_e_usa_multipart():
    http = Http({"/files": (200, {"data": {"id": "ANALISE123"}})})
    assert upload_virustotal(b"abc", "a.bin", "K", http) == "ANALISE123"
    req = http.requests[0]
    assert req.get_method() == "POST"
    assert req.get_header("X-apikey") == "K"
    assert req.get_header("Content-type").startswith("multipart/form-data; boundary=")
    assert b'name="file"' in req.data and b"abc" in req.data


def test_upload_status_ruim_levanta_sem_chave():
    http = Http({"/files": (403, b"no")})
    with pytest.raises(RuntimeError) as e:
        upload_virustotal(b"abc", "a.bin", "SEGREDO", http)
    assert "403" in str(e.value) and "SEGREDO" not in str(e.value)


def test_to_dict_segue_o_contrato():
    r = AnalysisResult("id1", "desconhecido", {"cymru": SourceResult("nao_achou")}, "ok")
    d = r.to_dict()
    assert set(d) == {"v", "id", "verdict", "sources", "summary"}
    assert d["v"] == 1 and d["id"] == "id1"
    assert d["sources"] == {"cymru": {"status": "nao_achou", "detail": ""}}


def test_padroes_sao_chamaveis():
    assert callable(_default_http) and callable(_default_resolver)
