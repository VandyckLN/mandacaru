import json
import urllib.parse

import pytest
from mandacaru_win import updates as up
from mandacaru_win.updates import (
    ALTA,
    DESATUALIZADO,
    EXPLORADA,
    EXPLORADA_PRODUTO,
    MEDIA,
    SEM_CVE,
    SUSPEITA,
    NvdClient,
    Program,
    RateLimiter,
    UpdateService,
    WingetUnavailable,
    parse_winget_upgrade,
    valid_winget_id,
)

from mandacaru.vuln.kev_cache import KevCache

WINGET_EN = (
    "   - \r   \\ \r   | \r"
    "\x1b[2K   ██████████████████████████████  1.00 MB / 1.00 MB\r\n"
    "Name                                  Id                         Version      Available  Source\n"
    "-----------------------------------------------------------------------------------------------\n"
    "7-Zip 22.01 (x64)                     7zip.7zip                  22.01        24.08      winget\n"
    "Mozilla Firefox (x64 pt-BR)           Mozilla.Firefox            118.0.2      133.0      winget\n"
    "Google Chrome                         Google.Chrome              < 120.0      131.0.6778 winget\n"
    "Programa com nome muito compriment…   Fabricante.ProgramaLongoD… 1.0          2.0        winget\n"
    "Adobe Acrobat Reader DC (64-bit)      Adobe.Acrobat.Reader.64-bit 23.006.20320 24.005.20320 winget\n"
    "Microsoft Windows Desktop Runtime     Microsoft.DotNet.DesktopRuntime.8 8.0.1 8.0.11 winget\n"
    "Programa Qualquer                     Fulano.Programa            Unknown      3.1        winget\n"
    "7 upgrades available.\n"
    "\n"
    "The following packages have an upgrade available, but require explicit targeting for upgrade:\n"
    "Name     Id            Version Available Source\n"
    "-----------------------------------------------\n"
    "Notepad++ Notepad++.Notepad++ 8.5 8.7.1 winget\n"
)

# Cabeçalho em outro idioma e nome com largura dupla: nada disso é usado na leitura.
WINGET_PT = (
    "Nome            ID                Versão  Disponível  Origem\n"
    "----------------------------------------------------------------\n"
    "微信 WeChat     Tencent.WeChat    3.9.1   3.9.12      winget\n"
    "1 atualizações disponíveis.\n"
)

KEV = {"vulnerabilities": [
    {"cveID": "CVE-2025-0411", "vendorProject": "7-Zip", "product": "7-Zip", "dateAdded": "2025-02-06"},
    {"cveID": "CVE-2024-9680", "vendorProject": "Mozilla", "product": "Firefox and Thunderbird",
     "dateAdded": "2024-10-15"},
    {"cveID": "CVE-2024-7971", "vendorProject": "Google", "product": "Chromium V8", "dateAdded": "2024-08-26"},
    {"cveID": "CVE-2023-21674", "vendorProject": "Microsoft", "product": "Windows", "dateAdded": "2023-01-10"},
    {"cveID": "CVE-2023-21608", "vendorProject": "Adobe", "product": "Acrobat", "dateAdded": "2023-10-10"},
]}


class FakeRun:
    def __init__(self, responses):
        self.responses = responses  # lista de (rc, texto) ou exceção, consumida na ordem
        self.calls = []

    def __call__(self, args, timeout):
        self.calls.append(list(args))
        r = self.responses.pop(0)
        if isinstance(r, BaseException):
            raise r
        return r


class FakeHttp:
    def __init__(self, nvd=None, kev=KEV, online=True):
        self.urls = []
        self.nvd = nvd or {}
        self.kev = kev
        self.online = online

    def __call__(self, req, timeout):
        url = req.full_url
        self.urls.append(url)
        if not self.online:
            raise OSError("sem rede")
        if "cisa.gov" in url:
            return 200, json.dumps(self.kev).encode()
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        if "/cpes/" in url:
            prods = self.nvd.get(("cpe", q["keywordSearch"][0]), [])
            return 200, json.dumps({"products": [{"cpe": {"cpeName": n}} for n in prods]}).encode()
        key = q["virtualMatchString"][0]
        vulns = self.nvd.get(("cve", key), [])
        return 200, json.dumps({"totalResults": len(vulns), "vulnerabilities": vulns}).encode()


def nvd_cve(cid, score=None, kev=False):
    cve = {"id": cid, "metrics": {}}
    if score is not None:
        cve["metrics"]["cvssMetricV31"] = [{"type": "Primary", "cvssData": {"baseScore": score}}]
    if kev:
        cve["cisaExploitAdd"] = "2024-01-01"
    return {"cve": cve}


class Clock:
    def __init__(self):
        self.t = 1000.0
        self.slept = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s
        self.slept += s


def make_service(tmp_path, run, http, *, is_windows=False, which=lambda: r"C:\wa\winget.exe"):
    clock = Clock()
    nvd = NvdClient(tmp_path / "nvd.db", http=http, limiter=RateLimiter(clock=clock, sleep=clock.sleep))
    svc = UpdateService(tmp_path, run=run, http=http, which=which, is_windows=is_windows,
                        kev=KevCache(cache_db=tmp_path / "kev.db", http=http), nvd=nvd, ps="ps.exe")
    svc.clock = clock
    return svc


def by_id(result):
    return {a.program.id: a for a in result.items}


# ---------- leitura do winget ----------
def test_parse_winget_text_reads_from_the_right_and_skips_cut_lines():
    progs, skipped = parse_winget_upgrade(WINGET_EN)
    ids = [p.id for p in progs]
    assert ids == ["7zip.7zip", "Mozilla.Firefox", "Google.Chrome", "Adobe.Acrobat.Reader.64-bit",
                   "Microsoft.DotNet.DesktopRuntime.8", "Fulano.Programa", "Notepad++.Notepad++"]
    assert skipped == 1
    seven = progs[0]
    assert (seven.name, seven.installed, seven.available, seven.source) == ("7-Zip 22.01 (x64)", "22.01", "24.08",
                                                                            "winget")
    assert progs[2].installed == "< 120.0" and progs[5].installed == "Unknown"


def test_parse_winget_text_is_language_and_width_independent():
    progs, skipped = parse_winget_upgrade(WINGET_PT)
    assert [(p.name, p.id, p.installed, p.available) for p in progs] == [
        ("微信 WeChat", "Tencent.WeChat", "3.9.1", "3.9.12")]
    assert skipped == 0
    assert parse_winget_upgrade("Nenhuma atualização disponível.\n") == ([], 0)


def test_list_prefers_powershell_module_and_falls_back_to_winget(tmp_path):
    ps_json = json.dumps([{"Name": "7-Zip", "Id": "7zip.7zip", "Installed": "22.01", "Available": "24.08",
                           "Source": "winget"}, {"Name": "x", "Id": "-ruim", "Installed": "1", "Available": "2"}])
    run = FakeRun([(0, ps_json)])
    svc = make_service(tmp_path, run, FakeHttp(), is_windows=True)
    progs, method, _ = svc.list_upgrades()
    assert method == "Microsoft.WinGet.Client" and [p.id for p in progs] == ["7zip.7zip"]
    assert run.calls[0][0] == "ps.exe" and "-NonInteractive" in run.calls[0]

    run = FakeRun([(3, ""), (0, WINGET_EN)])  # 3 = módulo ausente
    svc = make_service(tmp_path, run, FakeHttp(), is_windows=True)
    progs, method, notes = svc.list_upgrades()
    assert method == "winget upgrade" and len(progs) == 7 and "1 programa(s)" in notes[0]
    assert run.calls[1] == [r"C:\wa\winget.exe", "upgrade", "--include-unknown", "--accept-source-agreements",
                            "--disable-interactivity"]


def test_without_winget_raises_and_nothing_runs(tmp_path):
    run = FakeRun([])
    svc = make_service(tmp_path, run, FakeHttp(), which=lambda: None)
    with pytest.raises(WingetUnavailable):
        svc.quick()
    run = FakeRun([FileNotFoundError("winget")])
    with pytest.raises(WingetUnavailable):
        make_service(tmp_path, run, FakeHttp()).list_upgrades()


def test_find_winget_uses_windowsapps_alias(tmp_path, monkeypatch):
    alias = tmp_path / "Microsoft" / "WindowsApps" / "winget.exe"
    alias.parent.mkdir(parents=True)
    alias.write_bytes(b"")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert up.find_winget() == str(alias)


# ---------- rápida ----------
def test_quick_marks_kev_products_and_suspects(tmp_path):
    http = FakeHttp()
    svc = make_service(tmp_path, FakeRun([(0, WINGET_EN)]), http)
    res = svc.quick()
    a = by_id(res)
    assert not res.complete and res.windows is None
    for pid in ("7zip.7zip", "Mozilla.Firefox", "Google.Chrome"):
        assert a[pid].risk == EXPLORADA_PRODUTO and a[pid].preselected, pid
    assert "atualizar é a correção recomendada" in a["7zip.7zip"].detail
    assert a["7zip.7zip"].kev_cves == ("CVE-2025-0411",)
    assert a["Adobe.Acrobat.Reader.64-bit"].risk == SUSPEITA and not a["Adobe.Acrobat.Reader.64-bit"].preselected
    assert a["Microsoft.DotNet.DesktopRuntime.8"].risk == DESATUALIZADO  # "Windows" no nome não basta
    assert a["Fulano.Programa"].risk == DESATUALIZADO and not a["Fulano.Programa"].preselected
    assert res.items[0].risk == EXPLORADA_PRODUTO and res.items[-1].risk == DESATUALIZADO  # pior primeiro
    assert not any("nvd.nist.gov" in u for u in http.urls)  # rápida não consulta a NVD


def test_quick_uses_kev_cache_when_offline(tmp_path):
    make_service(tmp_path, FakeRun([(0, WINGET_EN)]), FakeHttp()).quick()   # enche o cache
    db = tmp_path / "kev.db"
    import sqlite3
    with sqlite3.connect(db) as conn:  # cache vencido + sem rede
        conn.execute("UPDATE kev_meta SET value = '2000-01-01T00:00:00+00:00' WHERE key = 'fetched_at'")
    res = make_service(tmp_path, FakeRun([(0, WINGET_EN)]), FakeHttp(online=False)).quick()
    assert by_id(res)["7zip.7zip"].risk == EXPLORADA_PRODUTO


# ---------- completa ----------
NVD = {
    ("cpe", "7-Zip"): ["cpe:2.3:a:7-zip:7-zip:22.01:*:*:*:*:*:*:*", "cpe:2.3:a:7-zip:7-zip:23.01:*:*:*:*:*:*:*"],
    ("cpe", "Mozilla Firefox"): ["cpe:2.3:a:mozilla:firefox:118.0:*:*:*:*:*:*:*",
                                 "cpe:2.3:a:mozilla:firefox_esr:115.0:*:*:*:*:*:*:*"],
    ("cpe", "Programa Qualquer"): ["cpe:2.3:a:outro:coisa_diferente:1.0:*:*:*:*:*:*:*"],
    ("cpe", "Notepad++"): ["cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:8.5:*:*:*:*:*:*:*"],
    ("cve", "cpe:2.3:a:7-zip:7-zip:22.01:*:*:*:*:*:*:*"): [nvd_cve("CVE-2025-0411", 7.0, kev=True)],
    ("cve", "cpe:2.3:a:mozilla:firefox:118.0.2:*:*:*:*:*:*:*"): [nvd_cve("CVE-2023-1", 8.8),
                                                                 nvd_cve("CVE-2023-2", 5.0)],
    ("cve", "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:8.5:*:*:*:*:*:*:*"): [nvd_cve("CVE-2023-3", 5.5),
                                                                             nvd_cve("CVE-2023-4")],
}

WINGET_SMALL = (
    "Name Id Version Available Source\n"
    "------------------------------------------\n"
    "7-Zip 22.01 (x64) 7zip.7zip 22.01 24.08 winget\n"
    "Mozilla Firefox (x64 pt-BR) Mozilla.Firefox 118.0.2 133.0 winget\n"
    "Programa Qualquer Fulano.Programa Unknown 3.1 winget\n"
    "Notepad++ Notepad++.Notepad++ 8.5 8.7.1 winget\n"
    "WinMerge WinMerge.WinMerge 2.16 2.16.44 winget\n"
)


def test_complete_queries_nvd_with_cache_and_rate_limit(tmp_path):
    http = FakeHttp(nvd=NVD)
    svc = make_service(tmp_path, FakeRun([(0, WINGET_SMALL)]), http)
    res = svc.complete()
    a = by_id(res)
    assert res.complete and not res.interrupted
    assert a["7zip.7zip"].risk == EXPLORADA and a["7zip.7zip"].kev_cves == ("CVE-2025-0411",)
    ff = a["Mozilla.Firefox"]
    assert ff.risk == EXPLORADA_PRODUTO and ff.worst_cvss == 8.8 and ff.cves == ("CVE-2023-1", "CVE-2023-2")
    np = a["Notepad++.Notepad++"]
    assert np.risk == MEDIA and not np.preselected and "2 CVE(s)" in np.detail  # uma sem nota ainda
    assert a["Fulano.Programa"].risk == DESATUALIZADO   # CPE não parecido: não chuta
    assert "não identificado" in a["WinMerge.WinMerge"].detail
    assert res.windows is not None and not res.windows.available  # fora do Windows
    nvd_calls = [u for u in http.urls if "nvd.nist.gov" in u]
    assert len(nvd_calls) == 7           # 4 CPE + 3 CVE (versão "Unknown" não vai para a NVD)
    assert svc.clock.slept >= 30.0       # 5 por 30 s: a sexta esperou
    assert "keywordSearch=7-Zip&" in nvd_calls[0]

    # segunda vez: tudo do cache (24 h), nada de rede para a NVD
    http2 = FakeHttp(nvd=NVD)
    svc2 = make_service(tmp_path, FakeRun([(0, WINGET_SMALL)]), http2)
    assert by_id(svc2.complete())["Mozilla.Firefox"].worst_cvss == 8.8
    assert not any("nvd.nist.gov" in u for u in http2.urls)

    # a rápida reaproveita o cache da completa (casamento forte por versão)
    quick = by_id(make_service(tmp_path, FakeRun([(0, WINGET_SMALL)]), FakeHttp(online=False)).quick())
    assert quick["7zip.7zip"].risk == EXPLORADA and quick["Notepad++.Notepad++"].risk == MEDIA


def test_complete_high_and_no_cve(tmp_path):
    nvd = {("cpe", "WinMerge"): ["cpe:2.3:a:winmerge:winmerge:2.16:*:*:*:*:*:*:*"],
           ("cve", "cpe:2.3:a:winmerge:winmerge:2.16:*:*:*:*:*:*:*"): [nvd_cve("CVE-2024-9", 9.1)],
           ("cpe", "Programa Qualquer"): ["cpe:2.3:a:fulano:programa:3.0:*:*:*:*:*:*:*"]}
    text = WINGET_SMALL.replace("Unknown", "3.0")
    a = by_id(make_service(tmp_path, FakeRun([(0, text)]), FakeHttp(nvd=nvd, kev={"vulnerabilities": []})).complete())
    assert a["WinMerge.WinMerge"].risk == ALTA and a["WinMerge.WinMerge"].preselected
    assert a["Fulano.Programa"].risk == SEM_CVE and not a["Fulano.Programa"].preselected


def test_complete_survives_nvd_errors_and_can_stop(tmp_path):
    class Down(FakeHttp):
        def __call__(self, req, timeout):
            if "nvd.nist.gov" in req.full_url:
                self.urls.append(req.full_url)
                return 503, b"{}"
            return super().__call__(req, timeout)

    http = Down()
    res = make_service(tmp_path, FakeRun([(0, WINGET_SMALL)]), http).complete()
    assert len(res.items) == 5 and any("NVD não respondeu" in n for n in res.notes)
    assert len([u for u in http.urls if "nvd" in u]) == 3  # para depois de 3 falhas seguidas

    flag = {"stop": False}
    calls = []

    def run(args, timeout):
        calls.append(args)
        return 0, WINGET_SMALL

    svc = make_service(tmp_path / "b", run, FakeHttp(nvd=NVD))
    svc.nvd.limiter = RateLimiter(max_calls=1, period=30, clock=lambda: 0.0, sleep=lambda s: flag.update(stop=True))
    res = svc.complete(should_stop=lambda: flag["stop"])
    assert res.interrupted and res.windows is None and len(res.items) == 5


def test_rate_limiter_waits_for_the_window():
    clock = Clock()
    rl = RateLimiter(max_calls=5, period=30, clock=clock, sleep=clock.sleep)
    for _ in range(5):
        rl.wait()
    assert clock.slept == 0
    rl.wait()
    assert clock.slept == pytest.approx(30.0)


# ---------- Windows Update ----------
def test_windows_update_read_only_and_unavailable_off_windows(tmp_path):
    svc = make_service(tmp_path, FakeRun([]), FakeHttp())
    assert svc.windows_updates().available is False
    data = json.dumps([{"Title": "Driver X", "Security": False},
                       {"Title": "Atualização cumulativa KB5040442", "Security": True}])
    run = FakeRun([(0, data)])
    svc = make_service(tmp_path, run, FakeHttp(), is_windows=True)
    wu = svc.windows_updates()
    assert (wu.available, wu.total, wu.security) == (True, 2, 1) and wu.titles[0].startswith("Atualização")
    script = run.calls[0][-1]
    assert "Microsoft.Update.Session" in script
    assert not any(w in script for w in ("CreateUpdateInstaller", "CreateUpdateDownloader", ".Install(",
                                         ".Download("))  # só leitura
    assert '"' not in script
    run = FakeRun([OSError("sem powershell")])
    assert make_service(tmp_path, run, FakeHttp(), is_windows=True).windows_updates().available is False


# ---------- aplicar ----------
def test_apply_one_by_one_with_exact_args_and_results(tmp_path):
    progs = [Program("7-Zip", "7zip.7zip", "22.01", "24.08", "winget"),
             Program("Firefox", "Mozilla.Firefox", "1", "2", "winget"),
             Program("Ruim", "--source=x", "1", "2"),
             Program("Store", "9NBLGGH4NNS1", "1", "2", "msstore"),
             Program("Antigo", "Fulano.X", "1", "2", "")]
    run = FakeRun([(0, ""), (0x8A150101, ""), (-1978335189, ""), (5, "")])
    got = []
    res = make_service(tmp_path, run, FakeHttp()).apply(progs, on_result=got.append)
    assert got == res and [r.status for r in res] == ["ok", "fechar", "invalido", "ja_atualizado", "falhou"]
    assert [r.success for r in res] == [True, False, False, True, False]
    assert run.calls[0] == [r"C:\wa\winget.exe", "upgrade", "--id", "7zip.7zip", "--exact", "--silent",
                            "--accept-package-agreements", "--accept-source-agreements", "--source", "winget"]
    assert len(run.calls) == 4 and all("--source=x" not in c for c in run.calls)
    assert "--source" not in run.calls[3]
    assert "0x00000005" in res[4].message


def test_apply_stops_between_items(tmp_path):
    progs = [Program("A", "A.A", "1", "2"), Program("B", "B.B", "1", "2")]
    run = FakeRun([(0, ""), (0, "")])
    stop = iter([False, True])
    res = make_service(tmp_path, run, FakeHttp()).apply(progs, should_stop=lambda: next(stop))
    assert [r.id for r in res] == ["A.A"] and len(run.calls) == 1


@pytest.mark.parametrize("value,ok", [("7zip.7zip", True), ("Notepad++.Notepad++", True), ("9NBLGGH4NNS1", True),
                                      ("-x", False), ("a b", False), ("a;b", False), ("a&b", False), ("", False),
                                      ("a" * 200, False), ("x\n", False)])
def test_valid_winget_id(value, ok):
    assert valid_winget_id(value) is ok
