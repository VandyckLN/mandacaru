"""Consulta de bibliotecas no OSV.dev e no CISA KEV (com HTTP falso)."""
from __future__ import annotations

import json
import time
from pathlib import Path

from mandacaru.events import Severity
from mandacaru.projeto.dependencias import verificar_dependencias, versao_corrigida
from mandacaru.projeto.lockfiles import Dependencia
from mandacaru.vuln import KevCache, OsvClient

CVSS_HIGH = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H"


def _dep(nome="lodash", versao="4.17.15", eco="npm", origem="package-lock.json"):
    return Dependencia(eco, nome, versao, origem)


def _lodash_vuln():
    return {
        "id": "GHSA-x",
        "aliases": ["CVE-2020-8203"],
        "severity": [{"type": "CVSS_V3", "score": CVSS_HIGH}],
        "affected": [
            {"package": {"ecosystem": "npm", "name": "lodash"},
             "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.19"}]},
                        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]},
            {"package": {"ecosystem": "npm", "name": "outro"},
             "ranges": [{"type": "SEMVER", "events": [{"fixed": "9.9.9"}]}]},
        ],
    }


def _osv(tmp_path: Path, detalhes: dict, bodies: list | None = None, erro: bool = False):
    def fake(req, timeout):
        if erro:
            raise OSError("sem rede")
        if req.full_url.endswith("/v1/querybatch"):
            corpo = json.loads(req.data.decode())
            if bodies is not None:
                bodies.append(req.data.decode())
            res = []
            for q in corpo["queries"]:
                ids = detalhes.get(q["package"]["name"], [])
                res.append({"vulns": [{"id": d["id"]} for d in ids]})
            return 200, json.dumps({"results": res}).encode()
        vid = req.full_url.rsplit("/", 1)[1]
        for lista in detalhes.values():
            for d in lista:
                if d["id"] == vid:
                    return 200, json.dumps(d).encode()
        return 404, b"{}"

    return OsvClient(cache_db=tmp_path / "osv.db", http=fake)


def _kev(tmp_path: Path, cves=()):
    def fake(req, timeout):
        return 200, json.dumps({"vulnerabilities": [{"cveID": c} for c in cves]}).encode()

    return KevCache(cache_db=tmp_path / "kev.db", http=fake)


def test_malicioso_e_critical(tmp_path):
    osv = _osv(tmp_path, {"evil-pkg": [{"id": "MAL-2024-1234"}]})
    r = verificar_dependencias([_dep("evil-pkg", "1.0.0")], 0, osv, _kev(tmp_path))
    assert [(a.regra, a.severidade) for a in r.achados] == [("projeto.dep.malicioso", Severity.CRITICAL)]
    assert "não instale" in r.achados[0].explicacao
    assert r.achados[0].mitre == ("T1195.002",)
    assert r.verificadas == 1 and r.erro is None


def test_vulneravel_com_versao_corrigida(tmp_path):
    osv = _osv(tmp_path, {"lodash": [_lodash_vuln()]})
    r = verificar_dependencias([_dep()], 0, osv, _kev(tmp_path))
    assert [(a.regra, a.severidade) for a in r.achados] == [("projeto.dep.vulneravel", Severity.HIGH)]
    assert "corrigida na versão 4.17.21" in r.achados[0].explicacao
    assert "CVE-2020-8203" in r.achados[0].explicacao
    assert r.achados[0].caminho == "package-lock.json" and r.achados[0].linha is None


def test_kev_vira_critical(tmp_path):
    osv = _osv(tmp_path, {"lodash": [_lodash_vuln()]})
    r = verificar_dependencias([_dep()], 0, osv, _kev(tmp_path, ["CVE-2020-8203"]))
    assert r.achados[0].severidade == Severity.CRITICAL
    assert "já explorada (CISA KEV)" in r.achados[0].explicacao


def test_kev_falha_cai_para_vazio(tmp_path):
    def quebra(req, timeout):
        raise OSError("x")

    kev = KevCache(cache_db=tmp_path / "kev.db", http=quebra)
    osv = _osv(tmp_path, {"lodash": [_lodash_vuln()]})
    r = verificar_dependencias([_dep()], 0, osv, kev)
    assert r.erro is None and r.achados[0].severidade == Severity.HIGH


def test_sem_rede():
    r = verificar_dependencias([_dep()], 2, None, None)
    assert "--sem-rede" in r.erro and r.achados == [] and r.sem_versao == 2


def test_falha_de_rede(tmp_path):
    r = verificar_dependencias([_dep()], 0, _osv(tmp_path, {}, erro=True), _kev(tmp_path))
    assert "sem conexão com o OSV.dev" in r.erro and r.achados == []


def test_dedup_por_versao(tmp_path):
    osv = _osv(tmp_path, {"lodash": [_lodash_vuln()]})
    deps = [_dep(origem="a/package-lock.json"), _dep(origem="b/yarn.lock")]
    r = verificar_dependencias(deps, 0, osv, _kev(tmp_path))
    assert len(r.achados) == 1 and r.verificadas == 1
    assert r.achados[0].caminho == "a/package-lock.json"
    assert "também em b/yarn.lock" in r.achados[0].explicacao


def test_mcp_sem_versao_so_malicioso(tmp_path):
    osv = _osv(tmp_path, {"lodash": [_lodash_vuln()]})
    assert verificar_dependencias([_dep(versao="")], 0, osv, _kev(tmp_path)).achados == []
    osv2 = _osv(tmp_path, {"evil": [{"id": "MAL-1"}]})
    r = verificar_dependencias([_dep("evil", "")], 0, osv2, _kev(tmp_path))
    assert [a.severidade for a in r.achados] == [Severity.CRITICAL]


def test_privacidade_so_ecossistema_nome_versao(tmp_path):
    bodies: list[str] = []
    osv = _osv(tmp_path, {"lodash": [_lodash_vuln()]}, bodies)
    verificar_dependencias([_dep(origem="segredo/package-lock.json")], 0, osv, _kev(tmp_path))
    assert bodies and all("segredo" not in b and "origem" not in b for b in bodies)


def test_malicioso_mesmo_com_vulneravel_gera_um_achado(tmp_path):
    osv = _osv(tmp_path, {"lodash": [_lodash_vuln(), {"id": "MAL-9"}]})
    r = verificar_dependencias([_dep()], 0, osv, _kev(tmp_path))
    assert [a.regra for a in r.achados] == ["projeto.dep.malicioso"]
    assert "MAL-9" in r.achados[0].explicacao


def test_detalhes_faltando(tmp_path):
    osv = _osv(tmp_path, {"lodash": [_lodash_vuln()]})
    orig = osv.http

    def http(req, timeout):
        if "/v1/vulns/" in req.full_url:
            return 500, b""
        return orig(req, timeout)

    osv.http = http
    r = verificar_dependencias([_dep()], 0, osv, _kev(tmp_path))
    assert r.detalhes_faltando == 1 and r.achados == []


def test_ao_consultar_recebe_pacotes_unicos(tmp_path):
    vistos = []
    deps = [_dep(origem="a"), _dep(origem="b"), _dep("x", "1.0.0")]
    verificar_dependencias(deps, 0, _osv(tmp_path, {}), _kev(tmp_path), vistos.append)
    assert vistos == [2]


def test_versao_corrigida_robusta():
    v = [{"affected": [
        {"package": {"ecosystem": "PyPI", "name": "my-pkg"},
         "ranges": [{"events": [{"fixed": "1.2.10"}, {"fixed": "1.2.9"}, {"fixed": "abc"}, {"fixed": 7}]}]},
        "lixo", {"package": [], "ranges": 3}, {"package": {"ecosystem": "PyPI", "name": ["x"]}},
    ]}, "lixo", {"affected": "x"}]
    assert versao_corrigida(v, "PyPI", "my-pkg") == "1.2.10"
    assert versao_corrigida(v, "npm", "my-pkg") is None
    assert versao_corrigida([], "npm", "a") is None


def test_versao_corrigida_pypi_normaliza_nome():
    v = [{"affected": [{"package": {"ecosystem": "PyPI", "name": "My_Pkg"},
                        "ranges": [{"events": [{"fixed": "2.0"}]}]}]}]
    assert versao_corrigida(v, "PyPI", "my-pkg") == "2.0"


def test_versao_corrigida_tempo_hostil():
    fixed = "1." + "9" * 5000
    v = [{"affected": [{"package": {"ecosystem": "npm", "name": "a"},
                        "ranges": [{"events": [{"fixed": fixed}] * 200}]}]}]
    t = time.time()
    versao_corrigida(v, "npm", "a")
    assert time.time() - t < 1
