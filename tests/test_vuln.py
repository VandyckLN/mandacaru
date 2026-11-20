"""Testes do scanner local de vulnerabilidades (dpkg, OSV.dev, CISA KEV e CVSS v3.1)."""
from __future__ import annotations

import json
from pathlib import Path

from mandacaru.events import Severity
from mandacaru.vuln.cli import run_vuln_scan
from mandacaru.vuln.inventory import detect_ecosystem, parse_dpkg_status
from mandacaru.vuln.kev_cache import KevCache
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
