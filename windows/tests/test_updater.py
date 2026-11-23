import hashlib
import io
import json
import socket
import urllib.error

import pytest
from mandacaru_win import __version__, updater
from mandacaru_win.updater import (
    CHECK_INTERVAL,
    DOWNLOAD_PREFIX,
    SNOOZE,
    Update,
    UpdateError,
    check,
    download,
    install_command,
    is_newer,
    parse_version,
    pick_update,
    run_installer,
    snooze,
)

SETUP = b"MZ" + b"instalador falso " * 1000
DIGEST = hashlib.sha256(SETUP).hexdigest()


def release(tag="v9.0.0", digest=f"sha256:{DIGEST}", name=None, **extra):
    version = tag.lstrip("v")
    asset = {"name": name or f"Mandacaru-{version}-setup.exe", "size": len(SETUP),
             "browser_download_url": f"{DOWNLOAD_PREFIX}{tag}/Mandacaru-{version}-setup.exe"}
    if digest is not None:
        asset["digest"] = digest
    return {"tag_name": tag, "draft": False, "prerelease": False,
            "assets": [{"name": "outro.zip"}, asset], **extra}


class FakeHttp:
    """Mesmo contrato de urlopen(req, timeout=...): devolve BytesIO por URL."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, req, timeout):
        self.calls.append((req.full_url, dict(req.header_items()), timeout))
        body = self.routes[req.full_url]
        if isinstance(body, BaseException):
            raise body
        return io.BytesIO(body if isinstance(body, bytes) else json.dumps(body).encode())


def api(rel):
    return FakeHttp({updater.RELEASES_URL: rel})


def clock(t):
    return lambda: t


# ---------- versões ----------
@pytest.mark.parametrize("text,expected", [
    ("v0.6.1", (0, 6, 1)), ("0.7", (0, 7)), ("0.7.0", (0, 7)), ("1.10.0", (1, 10)),
    ("v1.0.0-rc1", None), ("0.7.0b1", None), ("1.0.0.dev0", None), ("latest", None), (None, None),
])
def test_parse_version(text, expected):
    assert parse_version(text) == expected


def test_is_newer_numeric_not_textual():
    assert is_newer("0.10.0", "0.9.9")                    # texto diria o contrário
    assert is_newer("v1.0", "0.6.1")
    assert not is_newer("0.6.1", "0.6.1") and not is_newer("0.6.1.0", "0.6.1")
    assert not is_newer("0.6.0", "0.6.1")
    assert not is_newer("v9.0.0-rc1", "0.6.1")             # pre-release ignorada


# ---------- escolha da release ----------
def test_pick_update_newer_with_asset():
    u = pick_update(release("v0.10.0"), "0.9.0")
    assert u == Update("0.10.0", "0.9.0", f"{DOWNLOAD_PREFIX}v0.10.0/Mandacaru-0.10.0-setup.exe",
                       DIGEST, len(SETUP), "Mandacaru-0.10.0-setup.exe")


@pytest.mark.parametrize("rel", [
    release("v0.6.1"),                                     # igual
    release("v0.5.9"),                                     # menor
    release("v9.0.0-rc1"),                                 # sufixo
    release("v9.0.0", prerelease=True),
    release("v9.0.0", draft=True),
    release("v9.0.0", name="Mandacaru-setup.exe"),         # sem o asset esperado
    {"tag_name": "v9.0.0", "assets": []},
    release("v9.0.0", digest=None),                        # sem digest
    release("v9.0.0", digest="md5:abc"),
    {"tag_name": 9},
    "lixo",
])
def test_pick_update_nothing_to_do(rel):
    assert pick_update(rel, "0.6.1") is None


def test_pick_update_rejects_foreign_download_url():
    rel = release()
    rel["assets"][1]["browser_download_url"] = "https://exemplo.invalido/Mandacaru-9.0.0-setup.exe"
    assert pick_update(rel, "0.6.1") is None


# ---------- consulta ----------
def test_check_sends_user_agent_and_short_timeout(tmp_path):
    http = api(release())
    res = check(tmp_path, "0.6.1", http=http, now=clock(1000.0))
    assert res.reason == "disponivel" and res.update.version == "9.0.0"
    url, headers, timeout = http.calls[0]
    assert url == updater.RELEASES_URL and timeout <= 10
    assert headers["User-agent"] == f"mandacaru/{__version__}"


@pytest.mark.parametrize("exc", [
    urllib.error.URLError("sem rede"), socket.timeout("demorou"), ConnectionResetError(),
    urllib.error.HTTPError(updater.RELEASES_URL, 403, "rate limit", {}, io.BytesIO(b"")),
])
def test_network_failure_is_silent_and_not_stamped(tmp_path, exc):
    res = check(tmp_path, "0.6.1", http=FakeHttp({updater.RELEASES_URL: exc}), now=clock(1000.0))
    assert res.update is None and res.reason == "falha"
    assert not (tmp_path / "update.json").exists()        # tenta de novo na próxima abertura


def test_invalid_json_is_silent(tmp_path):
    res = check(tmp_path, "0.6.1", http=FakeHttp({updater.RELEASES_URL: b"<html>"}), now=clock(1.0))
    assert res.update is None and res.reason == "falha"


def test_up_to_date(tmp_path):
    res = check(tmp_path, "0.6.1", http=api(release("v0.6.1")), now=clock(1000.0))
    assert res.update is None and res.reason == "em_dia"
    assert json.loads((tmp_path / "update.json").read_text())["ultima_verificacao"] == 1000.0


def test_check_at_most_once_per_24h_keeps_banner_from_cache(tmp_path):
    check(tmp_path, "0.6.1", http=api(release()), now=clock(1000.0))
    quiet = FakeHttp({})                                   # qualquer consulta daria KeyError
    res = check(tmp_path, "0.6.1", http=quiet, now=clock(1000.0 + CHECK_INTERVAL - 1))
    assert quiet.calls == [] and res.update and res.update.version == "9.0.0"
    http = api(release("v9.1.0"))
    res = check(tmp_path, "0.6.1", http=http, now=clock(1000.0 + CHECK_INTERVAL))
    assert len(http.calls) == 1 and res.update.version == "9.1.0"


def test_cached_update_dropped_after_updating(tmp_path):
    check(tmp_path, "0.6.1", http=api(release()), now=clock(1000.0))
    res = check(tmp_path, "9.0.0", http=FakeHttp({}), now=clock(2000.0))
    assert res.update is None and res.reason == "recente"


def test_force_ignores_stamp(tmp_path):
    check(tmp_path, "0.6.1", http=api(release("v0.6.1")), now=clock(1000.0))
    http = api(release())
    res = check(tmp_path, "0.6.1", http=http, now=clock(1001.0), force=True)
    assert len(http.calls) == 1 and res.update.version == "9.0.0"


def test_corrupt_state_file_is_ignored(tmp_path):
    (tmp_path / "update.json").write_text("{quebrado")
    res = check(tmp_path, "0.6.1", http=api(release()), now=clock(1000.0))
    assert res.update is not None


def test_clock_going_back_does_not_block_check_forever(tmp_path):
    check(tmp_path, "0.6.1", http=api(release("v0.6.1")), now=clock(10 * CHECK_INTERVAL))
    http = api(release())
    assert check(tmp_path, "0.6.1", http=http, now=clock(1000.0)).update and http.calls


# ---------- "Depois" ----------
def test_later_snoozes_7_days(tmp_path):
    t0 = 1000.0
    check(tmp_path, "0.6.1", http=api(release()), now=clock(t0))
    snooze(tmp_path, "9.0.0", now=clock(t0))
    for dt in (60.0, CHECK_INTERVAL + 1, SNOOZE - 1):
        res = check(tmp_path, "0.6.1", http=api(release()), now=clock(t0 + dt))
        assert res.update is None and res.reason == "adiado"
    res = check(tmp_path, "0.6.1", http=api(release()), now=clock(t0 + SNOOZE + 1))
    assert res.update and res.update.version == "9.0.0"


def test_later_ends_when_newer_version_appears(tmp_path):
    check(tmp_path, "0.6.1", http=api(release()), now=clock(1000.0))
    snooze(tmp_path, "9.0.0", now=clock(1000.0))
    res = check(tmp_path, "0.6.1", http=api(release("v9.0.1")), now=clock(1000.0 + CHECK_INTERVAL + 1))
    assert res.update and res.update.version == "9.0.1"


def test_manual_check_ignores_snooze(tmp_path):
    check(tmp_path, "0.6.1", http=api(release()), now=clock(1000.0))
    snooze(tmp_path, "9.0.0", now=clock(1000.0))
    res = check(tmp_path, "0.6.1", http=api(release()), now=clock(1001.0), force=True)
    assert res.update and res.update.version == "9.0.0"


# ---------- download ----------
def _update(body=SETUP, sha=DIGEST, size=None):
    u = pick_update(release(), "0.6.1")
    return Update(u.version, u.current, u.url, sha, size if size is not None else len(body), u.name), \
        FakeHttp({u.url: body})


def test_download_verifies_sha256(tmp_path):
    u, http = _update()
    seen = []
    p = download(u, tmp_path, http=http, on_progress=lambda g, t: seen.append((g, t)), chunk=4096)
    assert p == tmp_path / "updates" / "Mandacaru-9.0.0-setup.exe" and p.read_bytes() == SETUP
    assert seen[-1] == (len(SETUP), len(SETUP)) and len(seen) > 1
    assert list((tmp_path / "updates").iterdir()) == [p]


def test_download_with_wrong_digest_deletes_and_refuses(tmp_path):
    u, http = _update(sha="0" * 64)
    with pytest.raises(UpdateError, match="não confere"):
        download(u, tmp_path, http=http)
    assert list((tmp_path / "updates").iterdir()) == []


def test_download_without_digest_refuses_before_downloading(tmp_path):
    u, http = _update(sha="")
    with pytest.raises(UpdateError, match="hash"):
        download(u, tmp_path, http=http)
    assert http.calls == []


def test_download_bigger_than_published_is_refused(tmp_path):
    u, http = _update(body=SETUP + b"extra", size=len(SETUP))
    with pytest.raises(UpdateError):
        download(u, tmp_path, http=http)
    assert list((tmp_path / "updates").iterdir()) == []


def test_download_network_failure_raises_update_error(tmp_path):
    u, _ = _update()
    with pytest.raises(UpdateError, match="baixar"):
        download(u, tmp_path, http=FakeHttp({u.url: urllib.error.URLError("caiu")}))
    assert list((tmp_path / "updates").iterdir()) == []


def test_download_cancel_and_old_installers_removed(tmp_path):
    (tmp_path / "updates").mkdir()
    (tmp_path / "updates" / "Mandacaru-0.6.0-setup.exe").write_bytes(b"velho")
    (tmp_path / "updates" / "instalacao.log").write_text("log")
    u, http = _update()
    with pytest.raises(UpdateError, match="cancelado"):
        download(u, tmp_path, http=http, should_stop=lambda: True)
    assert [p.name for p in (tmp_path / "updates").iterdir()] == ["instalacao.log"]


def test_download_rejects_foreign_url(tmp_path):
    u, http = _update()
    bad = Update(u.version, u.current, "https://exemplo.invalido/x.exe", u.sha256, u.size, u.name)
    with pytest.raises(UpdateError):
        download(bad, tmp_path, http=http)
    assert http.calls == []


# ---------- instalação ----------
def test_install_command_is_silent_and_reopens(tmp_path):
    setup = tmp_path / "Mandacaru-9.0.0-setup.exe"
    cmd = install_command(setup)
    assert cmd[0] == str(setup)
    assert {"/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/ATUALIZACAO"} <= set(cmd[1:])


def test_run_installer_uses_injected_runner(tmp_path):
    setup = tmp_path / "Mandacaru-9.0.0-setup.exe"
    cmds = []
    run_installer(setup, runner=cmds.append)
    assert cmds[0][:4] == [str(setup), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"]
    assert cmds[0][-1] == f"/LOG={tmp_path / 'instalacao.log'}"

    def boom(cmd):
        raise OSError("bloqueado")
    with pytest.raises(UpdateError, match="bloqueado"):
        run_installer(setup, runner=boom)


def test_check_reports_friendly_error_detail(tmp_path):
    from mandacaru_win.updater import RELEASES_URL

    err403 = urllib.error.HTTPError(RELEASES_URL, 403, "Forbidden", {}, None)
    res403 = check(tmp_path, current="0.8.0", http=FakeHttp({RELEASES_URL: err403}), force=True)
    assert res403.reason == "falha" and "limite temporário" in res403.detail

    res_to = check(tmp_path, current="0.8.0", http=FakeHttp({RELEASES_URL: TimeoutError("timed out")}), force=True)
    assert res_to.reason == "falha" and "tempo esgotado" in res_to.detail
