"""Testes do scanner local de vulnerabilidades (dpkg, OSV.dev, CISA KEV e CVSS v3.1)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from mandacaru.config import ConfigError, load_config
from mandacaru.events import Severity
from mandacaru.vuln.cli import cmd_vuln, run_vuln_scan
from mandacaru.vuln.inventory import (
    InstalledPackage,
    detect_ecosystem,
    find_running_packages,
    load_running_snapshot,
    parse_dpkg_status,
    write_running_snapshot,
)
from mandacaru.vuln.kev_cache import KevCache, name_key, normalize_name, product_keys
from mandacaru.vuln.osv_client import OsvClient
from mandacaru.vuln.scorer import classify_finding, finding_to_alert, parse_cvss31_base_score


def test_detect_ecosystem_debian_e_ubuntu(tmp_path: Path) -> None:
    deb = tmp_path / "os-release-deb"
    deb.write_text('ID=debian\nVERSION_ID="12"\n', encoding="utf-8")
    assert detect_ecosystem(deb) == "Debian:12"

    ubu = tmp_path / "os-release-ubu"
    ubu.write_text('ID=ubuntu\nVERSION_ID="24.04"\n', encoding="utf-8")
    assert detect_ecosystem(ubu) == "Ubuntu:24.04"


def test_parse_dpkg_resolve_source_e_deduplica(tmp_path: Path) -> None:
    status = tmp_path / "status"
    status.write_text(
        "Package: libssl3\n"
        "Status: install ok installed\n"
        "Source: openssl (3.0.11-1~deb12u2)\n"
        "Version: 3.0.11-1~deb12u2+b1\n\n"
        "Package: openssl\n"
        "Status: install ok installed\n"
        "Version: 3.0.11-1~deb12u2\n\n"
        "Package: removido\n"
        "Status: deinstall ok config-files\n"
        "Version: 1.0\n",
        encoding="utf-8",
    )
    pkgs = parse_dpkg_status(status_path=status, ecosystem="Debian:12")
    assert len(pkgs) == 1
    assert pkgs[0].binaries == ("libssl3", "openssl")
    assert pkgs[0].source_name == "openssl"
    assert pkgs[0].version == "3.0.11-1~deb12u2"
    assert pkgs[0].ecosystem == "Debian:12"


def test_cvss31_base_score_e_classificacao() -> None:
    vec_crit = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert parse_cvss31_base_score(vec_crit) == 9.8

    vec_med = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"
    assert parse_cvss31_base_score(vec_med) == 5.4

    assert parse_cvss31_base_score("CVSS:2.0/AV:N") is None

    vuln = {
        "id": "DSA-5555-1",
        "aliases": ["CVE-2026-9999"],
        "summary": "Buffer overflow em OpenSSL",
        "severity": [{"type": "CVSS_V3", "score": vec_crit}],
    }
    active = classify_finding(vuln, "openssl", "3.0.11", kev_cves=set(), running_packages={"openssl"})
    assert active.priority == "CRITICAL_ACTIVE"
    assert active.cvss_score == 9.8

    alert = finding_to_alert(active)
    assert alert.severity == Severity.CRITICAL
    assert alert.rule == "vuln.cve_local"
    assert "CVE-2026-9999" in alert.summary

    inactive = classify_finding(vuln, "openssl", "3.0.11", kev_cves=set(), running_packages=set())
    assert inactive.priority == "HIGH"


def test_osv_client_usa_cache_sqlite_para_detalhes(tmp_path: Path) -> None:
    calls: list[str] = []

    def fake_http(req, timeout):
        calls.append(req.full_url)
        if req.full_url.endswith("/v1/querybatch"):
            return 200, json.dumps({"results": [{"vulns": [{"id": "DSA-1000-1"}]}]}).encode()
        if req.full_url.endswith("/v1/vulns/DSA-1000-1"):
            payload = {
                "id": "DSA-1000-1",
                "aliases": ["CVE-2026-1000"],
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
            }
            return 200, json.dumps(payload).encode()
        return 404, b"{}"

    status = tmp_path / "status"
    status.write_text("Package: curl\nStatus: install ok installed\nVersion: 7.88.1\n", encoding="utf-8")
    pkgs = parse_dpkg_status(status, ecosystem="Debian:12")

    client = OsvClient(cache_db=tmp_path / "osv.db", http=fake_http)
    first = client.query_packages(pkgs)
    second = client.query_packages(pkgs)

    assert len(first[pkgs[0]]) == 1
    assert len(second[pkgs[0]]) == 1
    assert sum(1 for u in calls if u.endswith("/v1/vulns/DSA-1000-1")) == 1


def test_kev_cache_e_fluxo_completo_run_vuln_scan(tmp_path: Path) -> None:
    def fake_kev_http(req, timeout):
        body = {"vulnerabilities": [{"cveID": "CVE-2026-4242"}]}
        return 200, json.dumps(body).encode()

    def fake_osv_http(req, timeout):
        if req.full_url.endswith("/v1/querybatch"):
            return 200, json.dumps({"results": [{"vulns": [{"id": "OSV-4242"}]}]}).encode()
        return 200, json.dumps(
            {
                "id": "OSV-4242",
                "aliases": ["CVE-2026-4242"],
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"}],
            }
        ).encode()

    status = tmp_path / "status"
    status.write_text("Package: openssh-server\nStatus: install ok installed\nSource: openssh\nVersion: 9.2\n",
                      encoding="utf-8")
    osv = OsvClient(cache_db=tmp_path / "osv.db", http=fake_osv_http)
    kev = KevCache(cache_db=tmp_path / "kev.db", http=fake_kev_http)

    findings = run_vuln_scan(
        status_path=status,
        ecosystem="Debian:12",
        cache_dir=tmp_path,
        correlate_running=False,
        osv_client=osv,
        kev_cache=kev,
    )
    assert len(findings) == 1
    assert findings[0].in_kev is True
    assert findings[0].priority == "HIGH"


def test_derivados_do_ubuntu_usam_a_versao_base(tmp_path: Path) -> None:
    mint = tmp_path / "mint"
    mint.write_text('ID=linuxmint\nID_LIKE="ubuntu debian"\nVERSION_ID="21.3"\nUBUNTU_CODENAME=jammy\n')
    assert detect_ecosystem(mint) == "Ubuntu:22.04"

    pop = tmp_path / "pop"
    pop.write_text('ID=pop\nID_LIKE="ubuntu debian"\nVERSION_ID="24.04"\nUBUNTU_CODENAME=noble\n')
    assert detect_ecosystem(pop) == "Ubuntu:24.04"

    kali = tmp_path / "kali"
    kali.write_text('ID=kali\nID_LIKE=debian\nVERSION_ID="2026.1"\n')
    assert detect_ecosystem(kali) == "Debian"

    lmde = tmp_path / "lmde"
    lmde.write_text('ID=linuxmint\nID_LIKE=debian\nVERSION_ID="6"\nDEBIAN_CODENAME=bookworm\n')
    assert detect_ecosystem(lmde) == "Debian:12"


def _fake_proc(tmp_path: Path, mapped: list[str]) -> Path:
    proc = tmp_path / "proc"
    pid = proc / "123"
    pid.mkdir(parents=True)
    (pid / "maps").write_text("".join(f"7f00-7f01 r-xp 00000000 08:01 1 {m}\n" for m in mapped))
    (proc / "self").mkdir()
    return proc


def test_biblioteca_carregada_marca_a_fonte_inteira_como_ativa(tmp_path: Path) -> None:
    # libssl3 e openssl vem da mesma fonte; so a lib esta carregada
    pkg = InstalledPackage("openssl", "openssl", "3.0.11", "Debian:12", binaries=("openssl", "libssl3"))
    info = tmp_path / "info"
    info.mkdir()
    (info / "openssl.list").write_text("/usr/bin/openssl\n")
    (info / "libssl3:amd64.list").write_text("/lib/x86_64-linux-gnu/libssl.so.3\n")  # .list pre-usrmerge
    proc = _fake_proc(tmp_path, ["/usr/lib/x86_64-linux-gnu/libssl.so.3"])
    assert find_running_packages([pkg], proc_root=proc, dpkg_info_dir=info) == {"openssl"}


def test_snapshot_de_processos_ida_e_volta_sem_seguir_symlink(tmp_path: Path) -> None:
    alvo = tmp_path / "nao-tocar"
    alvo.write_text("original")
    snap = tmp_path / "running.json"
    snap.symlink_to(alvo)                 # plantado pelo usuario sem privilegio
    write_running_snapshot({"openssl", "curl"}, snap)
    assert alvo.read_text() == "original"
    assert not snap.is_symlink()
    assert load_running_snapshot(snap) == {"curl", "openssl"}


def test_scan_usa_snapshot_em_vez_do_proc(tmp_path: Path) -> None:
    def fake_osv_http(req, timeout):
        if req.full_url.endswith("/v1/querybatch"):
            return 200, json.dumps({"results": [{"vulns": [{"id": "OSV-1"}]}]}).encode()
        return 200, json.dumps({"id": "OSV-1", "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}).encode()

    status = tmp_path / "status"
    status.write_text("Package: curl\nStatus: install ok installed\nVersion: 7.88.1\n")
    found = run_vuln_scan(status_path=status, ecosystem="Debian:12", cache_dir=tmp_path, kev_enabled=False,
                          osv_client=OsvClient(cache_db=tmp_path / "osv.db", http=fake_osv_http),
                          running={"curl"})
    assert found[0].priority == "CRITICAL_ACTIVE"


def test_falha_num_detalhe_usa_cache_vencido_e_nao_aborta(tmp_path: Path) -> None:
    def make_http(fail: set[str]):
        def fake(req, timeout):
            if req.full_url.endswith("/v1/querybatch"):
                return 200, json.dumps({"results": [{"vulns": [{"id": "A-1"}, {"id": "B-2"}, {"id": "C-3"}]}]}).encode()
            vid = req.full_url.rsplit("/", 1)[1]
            if vid in fail:
                return 503, b""
            return 200, json.dumps({"id": vid}).encode()
        return fake

    status = tmp_path / "status"
    status.write_text("Package: curl\nStatus: install ok installed\nVersion: 7.88.1\n")
    pkgs = parse_dpkg_status(status, ecosystem="Debian:12")
    OsvClient(cache_db=tmp_path / "osv.db", http=make_http(set())).query_packages(pkgs[:1])  # aquece o cache

    client = OsvClient(cache_db=tmp_path / "osv.db", ttl_hours=0, http=make_http({"A-1", "B-2"}))
    import sqlite3
    with sqlite3.connect(tmp_path / "osv.db") as conn:
        conn.execute("DELETE FROM vuln_cache WHERE vuln_id = 'B-2'")   # B-2 sem cache nenhum
    got = client.query_packages(pkgs)[pkgs[0]]
    assert sorted(v["id"] for v in got) == ["A-1", "C-3"]          # A-1 do cache vencido, C-3 da rede
    assert len(client.errors) == 1 and client.errors[0].startswith("B-2")


def _vuln_args(tmp_path: Path, **kw):
    import argparse
    base = dict(config=str(tmp_path / "c.toml"), vcmd="scan", status_file=str(tmp_path / "status"),
                ecosystem="Debian:12", cache_dir=str(tmp_path), as_json=False, emit_alerts=False,
                no_kev=True, no_running=True, running_file=None, alerts_file=None, report=None)
    base.update(kw)
    return argparse.Namespace(**base)


def test_cli_report_grava_resultado_e_snapshot_honra_config(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "c.toml").write_text("[vuln]\ncorrelate_running_procs = false\n")
    (tmp_path / "status").write_text("Package: curl\nStatus: install ok installed\nVersion: 7.88.1\n")

    def fake_osv_http(req, timeout):
        return 200, json.dumps({"results": [{}]}).encode()

    monkeypatch.setattr("mandacaru.vuln.cli.OsvClient", lambda **kw: OsvClient(**kw, http=fake_osv_http))
    report = tmp_path / "last-scan.json"
    assert cmd_vuln(_vuln_args(tmp_path, report=str(report))) == 0
    assert json.loads(report.read_text()) == []

    out = tmp_path / "running.json"
    assert cmd_vuln(_vuln_args(tmp_path, vcmd="snapshot-running", output=str(out))) == 0
    assert load_running_snapshot(out) == set()   # correlacao desligada: nao le o /proc


def test_config_recusa_vuln_mode_removido(tmp_path: Path) -> None:
    p = tmp_path / "c.toml"
    p.write_text('[vuln]\nmode = "offline_dump"\n')
    with pytest.raises(ConfigError):
        load_config(p)


def _report(path: Path, findings: list[dict]) -> None:
    path.write_text(json.dumps(findings))


def _f(vid: str, prio: str = "HIGH", pkg: str = "openssl", cvss: float = 8.1) -> dict:
    return {"vuln_id": vid, "cve_ids": [f"CVE-2026-{vid}"], "package": pkg, "version": "1.0",
            "cvss_score": cvss, "in_kev": False, "is_running": prio == "CRITICAL_ACTIVE", "priority": prio,
            "summary": ""}


def test_publicador_alerta_so_o_que_e_novo_e_alto(tmp_path: Path) -> None:
    import os

    from mandacaru.vuln.publish import VulnReportPublisher

    got: list = []
    rep = tmp_path / "last-scan.json"
    pub = VulnReportPublisher(got.append, report=rep, seen_path=tmp_path / "seen.json")
    assert pub.poll() == 0                                   # sem relatorio ainda

    _report(rep, [_f("1"), _f("2", "CRITICAL_ACTIVE", cvss=9.8), _f("3", "MEDIUM", cvss=5.0)])
    assert pub.poll() == 2
    assert [a.severity for a in got] == [Severity.CRITICAL, Severity.HIGH]   # ativo primeiro; MEDIUM fora
    assert all(a.rule == "vuln.cve_local" for a in got)
    assert pub.poll() == 0                                   # arquivo nao mudou

    got.clear()
    _report(rep, [_f("1"), _f("2", "CRITICAL_ACTIVE", cvss=9.8), _f("4")])
    os.utime(rep, ns=(1, 1))
    assert pub.poll() == 1 and "CVE-2026-4" in got[0].summary

    # um monitor reiniciado nao repete o que ja foi alertado
    got.clear()
    assert VulnReportPublisher(got.append, report=rep, seen_path=tmp_path / "seen.json").poll() == 0


def test_publicador_resume_rajadas_e_ignora_lixo(tmp_path: Path) -> None:
    from mandacaru.vuln.publish import MAX_INDIVIDUAL, VulnReportPublisher

    got: list = []
    rep = tmp_path / "last-scan.json"
    _report(rep, [_f(str(i), pkg=f"p{i}") for i in range(MAX_INDIVIDUAL + 7)] + ["lixo", {"vuln_id": "x"}])
    VulnReportPublisher(got.append, report=rep, seen_path=tmp_path / "seen.json").poll()
    assert len(got) == MAX_INDIVIDUAL + 1
    assert got[-1].rule == "vuln.cve_local_resumo" and got[-1].evidence["count"] == 7


def test_publicador_nao_segue_symlink(tmp_path: Path) -> None:
    from mandacaru.vuln.publish import VulnReportPublisher

    real = tmp_path / "real.json"
    _report(real, [_f("1")])
    rep = tmp_path / "last-scan.json"
    rep.symlink_to(real)
    got: list = []
    assert VulnReportPublisher(got.append, report=rep, seen_path=tmp_path / "seen.json").poll() == 0


def test_avisos_de_distro_sem_cvss() -> None:
    from mandacaru.vuln.scorer import drop_redundant_advisories

    ubu = classify_finding({"id": "UBUNTU-CVE-2026-1", "upstream": ["CVE-2026-1"],
                            "severity": [{"type": "Ubuntu", "score": "high"}]}, "openssl", "1", set(), set())
    assert ubu.cve_ids == ("CVE-2026-1",) and ubu.priority == "HIGH" and ubu.cvss_score == 0.0
    med = classify_finding({"id": "UBUNTU-CVE-2026-2", "severity": [{"type": "Ubuntu", "score": "medium"}]},
                           "openssl", "1", set(), set())
    assert med.priority == "MEDIUM"

    # USN que so repete CVEs ja listadas sai; o que traz CVE nova fica, como atualizacao pendente
    dup = classify_finding({"id": "USN-1-1", "related": ["UBUNTU-CVE-2026-1"]}, "openssl", "1", set(), set())
    new = classify_finding({"id": "USN-2-1", "related": ["UBUNTU-CVE-2026-9"]}, "openssl", "1", {"CVE-2026-9"},
                           set())
    assert dup.cve_ids == ("CVE-2026-1",)
    assert new.in_kev is True and new.priority == "HIGH"   # CVE do aviso cruza com o KEV
    kept = drop_redundant_advisories([ubu, dup, new])
    assert [f.vuln_id for f in kept] == ["UBUNTU-CVE-2026-1", "USN-2-1"]
    assert classify_finding({"id": "USN-3-1"}, "x", "1", set(), set()).priority == "MEDIUM"

    alert = finding_to_alert(ubu)
    assert "sem CVSS" in alert.summary and alert.severity == Severity.HIGH


_KEV_FULL = {"vulnerabilities": [
    {"cveID": "CVE-2025-0411", "vendorProject": "7-Zip", "product": "7-Zip", "dateAdded": "2025-02-06"},
    {"cveID": "cve-2024-9680", "vendorProject": "Mozilla", "product": "Firefox and Thunderbird",
     "dateAdded": "2024-10-15"},
    {"cveID": "CVE-2023-38831", "vendorProject": "RARLAB", "product": "WinRAR", "dateAdded": "2023-08-24"},
]}


def _kev_http(calls: list):
    def fake(req, timeout):
        calls.append(req.full_url)
        return 200, json.dumps(_KEV_FULL).encode()
    return fake


def test_normalize_name_tira_versao_arquitetura_e_sufixos() -> None:
    assert normalize_name("7-Zip 23.01 (x64)") == "7 zip" and name_key("7zip") == "7zip"
    assert normalize_name("Mozilla Firefox (x64 pt-BR)") == "mozilla firefox"
    assert normalize_name("Zoom Video Communications, Inc.") == "zoom video communications"
    assert normalize_name("WinRAR 6.24 64-bit") == "winrar"
    assert product_keys("Firefox and Thunderbird") == ["firefoxandthunderbird", "firefox", "thunderbird"]


def test_kev_cache_guarda_fabricante_produto_e_consulta_por_produto(tmp_path: Path) -> None:
    calls: list = []
    kev = KevCache(cache_db=tmp_path / "kev.db", http=_kev_http(calls))
    assert kev.get_cves() == {"CVE-2025-0411", "CVE-2024-9680", "CVE-2023-38831"}
    e = {x.cve_id: x for x in kev.entries()}
    assert e["CVE-2025-0411"].vendor_project == "7-Zip" and e["CVE-2025-0411"].date_added == "2025-02-06"
    assert [x.cve_id for x in kev.find_by_product("7zip")] == ["CVE-2025-0411"]          # sem pontuacao
    assert [x.cve_id for x in kev.find_by_product("7-Zip 23.01 (x64)")] == ["CVE-2025-0411"]
    assert [x.cve_id for x in kev.find_by_product("Thunderbird")] == ["CVE-2024-9680"]   # alternativa "and"
    assert [x.cve_id for x in kev.find_by_product("WinRAR", vendor="RARLab Inc.")] == ["CVE-2023-38831"]
    assert kev.find_by_product("WinRAR", vendor="Outro") == []
    assert kev.find_by_product("") == []
    assert len(calls) == 1  # cache fresco: nada de rede de novo


def test_kev_cache_migra_banco_antigo_sem_quebrar_get_cves(tmp_path: Path) -> None:
    import sqlite3
    from datetime import datetime, timezone

    db = tmp_path / "kev.db"
    with sqlite3.connect(db) as conn:  # esquema da versao anterior: so os IDs
        conn.execute("CREATE TABLE kev_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("CREATE TABLE kev_cves (cve_id TEXT PRIMARY KEY)")
        conn.execute("INSERT INTO kev_cves VALUES ('CVE-2020-0001')")
        conn.execute("INSERT INTO kev_meta VALUES ('fetched_at', ?)", (datetime.now(timezone.utc).isoformat(),))

    def sem_rede(req, timeout):
        raise OSError("offline")

    kev = KevCache(cache_db=db, http=sem_rede)
    assert kev.get_cves() == {"CVE-2020-0001"}         # Linux: igual a antes, sem rede
    assert kev.entries() == []                         # sem rede, sem fabricante/produto ainda
    calls: list = []
    kev = KevCache(cache_db=db, http=_kev_http(calls))
    assert kev.get_cves() == {"CVE-2020-0001"}         # cache ainda fresco para os IDs
    assert calls == []
    assert len(kev.entries()) == 3 and len(calls) == 1  # esquema antigo forca o refresh
    assert kev.entries(offline_only=True) and len(calls) == 1
