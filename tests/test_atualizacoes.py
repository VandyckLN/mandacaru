"""Testes de `mandacaru atualizacoes`: parse de apt/Snap/Flatpak, risco pelo relatorio de CVEs e o `aplicar`."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from mandacaru.atualizacoes.cli import SISTEMA_INDISPONIVEL, Ambiente, cmd_atualizacoes, formatar_tabela
from mandacaru.atualizacoes.fontes import (
    DESCONHECIDO,
    NENHUM,
    Atualizacao,
    coletar,
    nome_valido,
    parse_apt,
    parse_flatpak,
    parse_snap,
)
from mandacaru.atualizacoes.risco import aplicar_riscos, fontes_dos_binarios, riscos_do_relatorio
from mandacaru.cli import build_parser
from mandacaru.vuln.scorer import ScoredVulnerability

# saidas reais (Ubuntu 24.04, LC_ALL=C); o aviso do apt vai para o stderr
APT_STDERR = "\nWARNING: apt does not have a stable CLI interface. Use with caution in scripts.\n\n"
APT_SAIDA = """Listing...
libssl3t64/noble-updates,noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]
openssl/noble-updates,noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]
libsystemd0/noble-updates 255.4-1ubuntu8.19 amd64 [upgradable from: 255.4-1ubuntu8.18]
libsystemd0/noble-updates 255.4-1ubuntu8.19 i386 [upgradable from: 255.4-1ubuntu8.18]
curl/noble-updates 8.5.0-2ubuntu10.7 amd64 [upgradable from: 8.5.0-2ubuntu10.6]
tzdata/noble-updates 2025b-0ubuntu0.24.04.1 all [upgradable from: 2025a-0ubuntu0.24.04]
"""
APT_VAZIO = "Listing...\n"
# apt 2.9+ escreve "Listing... Done"
APT_NOVO = "Listing... Done\nvim/questing 2:9.1.0967-1ubuntu5 amd64 [upgradable from: 2:9.1.0967-1ubuntu4]\n"

SNAP_REFRESH = """Name     Version        Rev    Size   Publisher     Notes
firefox  133.0.3-1      5600   264MB  mozilla**     -
snapd    2.66.1         23545  41MB   canonical**   snapd
"""
SNAP_LIST = """Name                       Version           Rev    Tracking         Publisher     Notes
bare                       1.0               5      latest/stable    canonical**   base
core22                     20241119          1722   latest/stable    canonical**   base
firefox                    132.0.2-1         5361   latest/stable/…  mozilla**     -
snapd                      2.65.3            23258  latest/stable    canonical**   snapd
"""
SNAP_NADA = "All snaps up to date.\n"

# flatpak sem terminal: sem cabecalho, colunas separadas por TAB; runtimes vem sem versao
FLATPAK_SIS_UPD = "org.mozilla.firefox\tstable\t133.0.3\norg.freedesktop.Platform.GL.default\t24.08\t\n"
FLATPAK_SIS_LIST = ("org.freedesktop.Platform.GL.default\t24.08\t\norg.mozilla.firefox\tstable\t132.0.2\n"
                    "org.gnome.Platform\t47\t\n")
FLATPAK_USR_UPD = "org.videolan.VLC\tstable\t3.0.21\n"
FLATPAK_USR_LIST = "org.videolan.VLC\tstable\t3.0.20\n"

DPKG_STATUS = """Package: libssl3t64
Status: install ok installed
Source: openssl
Version: 3.0.13-0ubuntu3.4

Package: openssl
Status: install ok installed
Version: 3.0.13-0ubuntu3.4

Package: libsystemd0
Status: install ok installed
Source: systemd
Version: 255.4-1ubuntu8.18

Package: curl
Status: install ok installed
Version: 8.5.0-2ubuntu10.6

Package: tzdata
Status: install ok installed
Version: 2025a-0ubuntu0.24.04
"""


def _achado(pkg: str, ver: str, prio: str, cves: tuple[str, ...], vid: str = "") -> dict:
    return ScoredVulnerability(vuln_id=vid or (cves[0] if cves else "USN-0000-1"), cve_ids=cves, package=pkg,
                               version=ver, cvss_score=7.5 if prio == "HIGH" else 5.0, in_kev=False,
                               is_running=False, priority=prio).to_dict()


# formato do last-scan.json do `vuln scan --report`
RELATORIO = [
    _achado("openssl", "3.0.13-0ubuntu3.4", "HIGH", ("CVE-2024-5535",)),
    _achado("openssl", "3.0.13-0ubuntu3.4", "MEDIUM", ("CVE-2024-6119", "CVE-2024-2511"), "USN-7018-1"),
    _achado("systemd", "255.4-1ubuntu8.10", "HIGH", ("CVE-2023-7008",)),  # versao antiga: relatorio velho
    _achado("tzdata", "2025a-0ubuntu0.24.04", "LOW", ()),
    {"lixo": True},
]


class FakeRunner:
    def __init__(self, respostas: dict[tuple[str, ...], tuple[int, str, str]]):
        self.respostas = respostas
        self.chamadas: list[list[str]] = []

    def __call__(self, argv: list[str]) -> tuple[int, str, str]:
        self.chamadas.append(list(argv))
        return self.respostas.get(tuple(argv), (0, "", ""))


def _resp_completas() -> dict:
    col = "--columns=application,branch,version"
    return {
        ("apt", "list", "--upgradable"): (0, APT_SAIDA, APT_STDERR),
        ("snap", "refresh", "--list"): (0, SNAP_REFRESH, ""),
        ("snap", "list"): (0, SNAP_LIST, ""),
        ("flatpak", "remote-ls", "--updates", "--system", col): (0, FLATPAK_SIS_UPD, ""),
        ("flatpak", "list", "--system", col): (0, FLATPAK_SIS_LIST, ""),
        ("flatpak", "remote-ls", "--updates", "--user", col): (0, FLATPAK_USR_UPD, ""),
        ("flatpak", "list", "--user", col): (0, FLATPAK_USR_LIST, ""),
    }


def _which(*existentes: str):
    return lambda cmd: f"/usr/bin/{cmd}" if cmd in existentes else None


@pytest.fixture
def base(tmp_path: Path):
    """Config vazia, dpkg/status, relatorio e pasta de listas do apt atualizada agora."""
    (tmp_path / "c.toml").write_text("")
    (tmp_path / "status").write_text(DPKG_STATUS)
    (tmp_path / "last-scan.json").write_text(json.dumps(RELATORIO))
    (tmp_path / "lists").mkdir()
    return tmp_path


def _args(base: Path, *resto: str):
    return build_parser().parse_args(["--config", str(base / "c.toml"), "atualizacoes", *resto,
                                      "--status-file", str(base / "status"),
                                      "--relatorio", str(base / "last-scan.json")])


def _amb(base: Path, runner=None, which=None, **kw) -> Ambiente:
    return Ambiente(runner=runner or FakeRunner(_resp_completas()),
                    which=which or _which("apt", "snap", "flatpak"),
                    apt_lists=base / "lists", **kw)


# ---- nomes ----

def test_regras_de_nome() -> None:
    assert nome_valido("apt", "libssl3t64") and nome_valido("apt", "g++-13") and nome_valido("apt", "php8.3-cli")
    assert not nome_valido("apt", "-oAPT::Get=x") and not nome_valido("apt", "Libssl") and not nome_valido("apt", "")
    assert not nome_valido("apt", "a b") and not nome_valido("apt", "a;rm")
    assert nome_valido("snap", "firefox") and nome_valido("snap", "core22") and nome_valido("snap", "firefox_beta")
    assert not nome_valido("snap", "123") and not nome_valido("snap", "a--b") and not nome_valido("snap", "-a")
    assert not nome_valido("snap", "Firefox") and not nome_valido("snap", "a" * 41)
    assert nome_valido("flatpak-usuario", "org.videolan.VLC") and nome_valido("flatpak", "org.videolan.VLC//stable")
    assert nome_valido("flatpak", "org.freedesktop.Platform.GL.default//24.08")
    assert not nome_valido("flatpak", "org.mozilla") and not nome_valido("flatpak", "--user.x.y")
    assert not nome_valido("flatpak", "org.1x.y") and not nome_valido("flatpak", "org.x.y//-b")
    assert not nome_valido("flatpak", "org.x.y//a/b") and not nome_valido("desconhecido", "x")


# ---- parse ----

def test_parse_apt_real_ignora_cabecalho_aviso_e_duplicata_multiarch() -> None:
    itens = parse_apt(APT_SAIDA + APT_STDERR)  # aviso misturado (2>&1) tambem nao vira item
    assert [i.nome for i in itens] == ["libssl3t64", "openssl", "libsystemd0", "curl", "tzdata"]
    assert itens[0] == Atualizacao("apt", "libssl3t64", "3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5")
    assert parse_apt(APT_VAZIO) == [] and parse_apt("") == []
    assert parse_apt(APT_NOVO) == [Atualizacao("apt", "vim", "2:9.1.0967-1ubuntu4", "2:9.1.0967-1ubuntu5")]
    assert parse_apt("Bad_Name/x 1.0 amd64 [upgradable from: 0.9]\n") == []


def test_parse_snap_com_versao_instalada() -> None:
    itens = parse_snap(SNAP_REFRESH, SNAP_LIST)
    assert itens == [Atualizacao("snap", "firefox", "132.0.2-1", "133.0.3-1"),
                     Atualizacao("snap", "snapd", "2.65.3", "2.66.1")]
    assert parse_snap("", "") == []
    assert parse_snap(SNAP_REFRESH, "")[0].instalada is None  # `snap list` falhou


def test_parse_flatpak_tab_e_runtime_sem_versao() -> None:
    itens = parse_flatpak(FLATPAK_SIS_UPD, FLATPAK_SIS_LIST, "flatpak-sistema")
    assert itens == [
        Atualizacao("flatpak-sistema", "org.mozilla.firefox//stable", "132.0.2", "133.0.3"),
        Atualizacao("flatpak-sistema", "org.freedesktop.Platform.GL.default//24.08", None, None),
    ]
    # cabecalho (se vier de um terminal) e lixo caem na regra de nome
    assert parse_flatpak("Application ID\tBranch\tVersion\nlixo\n\n", "", "flatpak-usuario") == []


def test_coletar_consulta_so_o_que_existe_e_com_lc_all_neutro() -> None:
    r = FakeRunner(_resp_completas())
    c = coletar(r, _which("apt"), Path("/nao/existe"))
    assert c.fontes == ["apt"] and c.erros == [] and c.apt_atualizado_em is None
    assert r.chamadas == [["apt", "list", "--upgradable"]]
    assert len(c.itens) == 5

    r = FakeRunner(_resp_completas())
    c = coletar(r, _which(), Path("/nao/existe"))
    assert c.fontes == [] and c.itens == [] and r.chamadas == []


def test_coletar_tudo_vazio_nao_pede_versoes_instaladas() -> None:
    col = "--columns=application,branch,version"
    r = FakeRunner({("apt", "list", "--upgradable"): (0, APT_VAZIO, APT_STDERR),
                    ("snap", "refresh", "--list"): (0, "", SNAP_NADA)})
    c = coletar(r, _which("apt", "snap", "flatpak"), Path("/nao/existe"))
    assert c.itens == [] and c.erros == []
    assert ["snap", "list"] not in r.chamadas
    assert ["flatpak", "list", "--user", col] not in r.chamadas


def test_coletar_erro_de_uma_fonte_nao_derruba_as_outras() -> None:
    resp = _resp_completas()
    resp[("snap", "refresh", "--list")] = (1, "", "error: cannot communicate with server: connection refused\n")
    resp[("apt", "list", "--upgradable")] = (100, "", APT_STDERR + "E: Could not open lock file\n")
    c = coletar(FakeRunner(resp), _which("apt", "snap", "flatpak"), Path("/nao/existe"))
    assert c.erros == ["apt: E: Could not open lock file",
                       "snap: error: cannot communicate with server: connection refused"]
    assert {i.gerenciador for i in c.itens} == {"flatpak-sistema", "flatpak-usuario"}


def test_executar_real_comando_ausente() -> None:
    from mandacaru.atualizacoes.fontes import executar
    rc, out, err = executar(["mandacaru-comando-que-nao-existe"])
    assert rc == 127 and out == "" and "nao encontrado" in err


# ---- risco ----

def test_risco_herda_pior_prioridade_do_fonte(base: Path) -> None:
    riscos = riscos_do_relatorio(base / "last-scan.json")
    ligacao = fontes_dos_binarios(base / "status")
    assert ligacao["libssl3t64"] == ("openssl", "3.0.13-0ubuntu3.4")
    itens = {(i.gerenciador, i.nome): i for i in aplicar_riscos(
        parse_apt(APT_SAIDA) + parse_snap(SNAP_REFRESH, SNAP_LIST), riscos, ligacao)}
    ssl = itens[("apt", "libssl3t64")]
    assert ssl.risco == "HIGH" and ssl.selecionado
    assert ssl.cves == ("CVE-2024-2511", "CVE-2024-5535", "CVE-2024-6119")
    assert itens[("apt", "openssl")].risco == "HIGH"
    assert itens[("apt", "libsystemd0")].risco == DESCONHECIDO  # achado de outra versao do fonte
    assert itens[("apt", "curl")].risco == NENHUM and not itens[("apt", "curl")].selecionado
    assert itens[("apt", "tzdata")].risco == "LOW" and itens[("apt", "tzdata")].cves == ("USN-0000-1",)
    assert itens[("snap", "firefox")].risco == DESCONHECIDO


def test_relatorio_que_nao_e_lista_e_symlink_sao_recusados(base: Path) -> None:
    (base / "ruim.json").write_text("{}")
    with pytest.raises(ValueError):
        riscos_do_relatorio(base / "ruim.json")
    os.symlink(base / "last-scan.json", base / "link.json")
    with pytest.raises(OSError):
        riscos_do_relatorio(base / "link.json")


# ---- listar ----

def test_listar_tabela_marca_alto_risco_e_sai_2(base: Path, capsys) -> None:
    rc = cmd_atualizacoes(_args(base, "listar"), _amb(base))
    out, err = capsys.readouterr()
    assert rc == 2
    linhas = out.splitlines()
    assert linhas[0].split() == ["GERENCIADOR", "NOME", "INSTALADA", "DISPONIVEL", "RISCO", "CVES"]
    assert linhas[1].startswith("*") and "libssl3t64" in linhas[1] and "CVE-2024-2511,CVE-2024-5535" in linhas[1]
    assert sum(1 for linha in linhas if linha.startswith("*")) == 2  # libssl3t64 e openssl
    assert "org.videolan.VLC//stable" in out and "3.0.20" in out
    assert "10 atualizacao(oes) pendente(s); 2 pre-selecionada(s)" in err
    assert "riscos do relatorio de" in err and "lista do apt de" in err


def test_listar_json_tem_os_campos_do_desenho(base: Path, capsys) -> None:
    rc = cmd_atualizacoes(_args(base, "listar", "--json"), _amb(base))
    dados = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert set(dados[0]) == {"gerenciador", "nome", "instalada", "disponivel", "risco", "cves", "selecionado"}
    assert dados[0] == {"gerenciador": "apt", "nome": "libssl3t64", "instalada": "3.0.13-0ubuntu3.4",
                        "disponivel": "3.0.13-0ubuntu3.5", "risco": "HIGH",
                        "cves": ["CVE-2024-2511", "CVE-2024-5535", "CVE-2024-6119"], "selecionado": True}
    runtime = next(d for d in dados if d["nome"].startswith("org.freedesktop"))
    assert runtime["gerenciador"] == "flatpak-sistema" and runtime["disponivel"] is None


def test_listar_sem_relatorio_avisa_e_nao_marca_nada(base: Path, capsys) -> None:
    (base / "last-scan.json").unlink()
    rc = cmd_atualizacoes(_args(base, "listar"), _amb(base))
    _, err = capsys.readouterr()
    assert rc == 0
    assert "rode com --completo para ver as falhas" in err


def test_listar_relatorio_sem_permissao_avisa(base: Path, capsys, monkeypatch) -> None:
    def negado(_):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr("mandacaru.atualizacoes.cli.riscos_do_relatorio", negado)
    assert cmd_atualizacoes(_args(base, "listar"), _amb(base)) == 0
    assert "sem permissao para ler" in capsys.readouterr().err


def test_listar_nada_pendente_sai_0(base: Path, capsys) -> None:
    r = FakeRunner({("apt", "list", "--upgradable"): (0, APT_VAZIO, APT_STDERR)})
    rc = cmd_atualizacoes(_args(base, "listar", "--json"), _amb(base, runner=r, which=_which("apt")))
    out, err = capsys.readouterr()
    assert rc == 0 and json.loads(out) == []
    assert "nenhuma atualizacao pendente." in err
    assert "relatorio" not in err  # sem item apt nao ha o que ligar ao relatorio


def test_listar_sem_gerenciador_e_fonte_com_erro_saem_1(base: Path, capsys) -> None:
    assert cmd_atualizacoes(_args(base, "listar"), _amb(base, which=_which())) == 1
    assert "nenhum gerenciador" in capsys.readouterr().err

    r = FakeRunner({("snap", "refresh", "--list"): (1, "", "error: cannot communicate with server\n")})
    assert cmd_atualizacoes(_args(base, "listar"), _amb(base, runner=r, which=_which("snap"))) == 1
    assert "consulta falhou: snap: error: cannot communicate with server" in capsys.readouterr().err


def test_listar_avisa_lista_do_apt_velha(base: Path, capsys) -> None:
    os.utime(base / "lists", (1_700_000_000, 1_700_000_000))
    cmd_atualizacoes(_args(base, "listar"), _amb(base, agora=lambda: 1_700_000_000 + 50 * 3600))
    err = capsys.readouterr().err
    assert "(ha 50 h)" in err and "sudo apt update" in err


def test_listar_completo_roda_o_scan_na_hora(base: Path, capsys) -> None:
    (base / "last-scan.json").unlink()  # o completo nao depende do relatorio
    chamadas = []

    def scan(**kw):
        chamadas.append(kw)
        return [ScoredVulnerability("CVE-2024-9143", ("CVE-2024-9143",), "curl", "8.5.0-2ubuntu10.6", 9.8,
                                    True, True, "CRITICAL_ACTIVE")]

    args = build_parser().parse_args(["--config", str(base / "c.toml"), "atualizacoes", "listar", "--completo",
                                      "--json", "--status-file", str(base / "status"),
                                      "--cache-dir", str(base / "cache")])
    rc = cmd_atualizacoes(args, _amb(base, scan=scan))
    dados = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert chamadas[0]["cache_dir"] == base / "cache" and chamadas[0]["status_path"] == base / "status"
    assert dados[0]["nome"] == "curl" and dados[0]["risco"] == "CRITICAL_ACTIVE"
    assert next(d for d in dados if d["nome"] == "libssl3t64")["risco"] == NENHUM


def test_listar_completo_sem_rede_lista_mesmo_assim_e_sai_1(base: Path, capsys) -> None:
    def scan(**kw):
        raise OSError("sem rede")

    rc = cmd_atualizacoes(_args(base, "listar", "--completo"), _amb(base, scan=scan))
    out, err = capsys.readouterr()
    assert rc == 1 and "libssl3t64" in out and "erro no scanner de vulnerabilidades: sem rede" in err


def test_tabela_resume_muitas_cves() -> None:
    item = Atualizacao("apt", "x", "1", "2", "HIGH", ("CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5"))
    assert formatar_tabela([item]).splitlines()[1].endswith("CVE-1,CVE-2,CVE-3 (+2)")


# ---- aplicar ----

def _aplicar(base: Path, *resto: str, **kw):
    rodados: list[list[str]] = []
    rc_flatpak = kw.pop("rc", 0)

    def rodar(argv):
        rodados.append(argv)
        return rc_flatpak

    amb = _amb(base, rodar=rodar, **kw)
    rc = cmd_atualizacoes(_args(base, "aplicar", *resto), amb)
    return rc, rodados


def test_aplicar_flatpak_do_usuario_com_sim(base: Path, capsys) -> None:
    rc, rodados = _aplicar(base, "org.videolan.VLC", "--sim")
    assert rc == 0
    assert rodados == [["flatpak", "update", "--user", "-y", "org.videolan.VLC//stable"]]
    assert "3.0.20 -> 3.0.21" in capsys.readouterr().out


@pytest.mark.parametrize("resposta,roda", [("s", True), ("SIM", True), ("n", False), ("", False)])
def test_aplicar_pede_confirmacao(base: Path, resposta: str, roda: bool) -> None:
    perguntas = []
    rc, rodados = _aplicar(base, "org.videolan.VLC//stable",
                           entrada=lambda p: perguntas.append(p) or resposta)
    assert rc == 0 and perguntas == ["Atualizar 1 item(ns)? [s/N] "]
    assert bool(rodados) is roda


def test_aplicar_sem_terminal_nao_atualiza(base: Path) -> None:
    def eof(_):
        raise EOFError
    rc, rodados = _aplicar(base, "org.videolan.VLC", entrada=eof)
    assert rc == 0 and rodados == []


def test_aplicar_recusa_pacotes_do_sistema(base: Path, capsys) -> None:
    for nomes in (["libssl3t64"], ["firefox"], ["org.mozilla.firefox"], ["org.videolan.VLC", "curl"]):
        rc, rodados = _aplicar(base, *nomes, "--sim")
        assert rc == 1 and rodados == []
        assert SISTEMA_INDISPONIVEL in capsys.readouterr().err


def test_aplicar_selecionados_cai_no_apt_e_recusa(base: Path, capsys) -> None:
    rc, rodados = _aplicar(base, "--selecionados", "--sim")
    err = capsys.readouterr().err
    assert rc == 1 and rodados == []
    assert "apt libssl3t64, apt openssl" in err and SISTEMA_INDISPONIVEL in err


def test_aplicar_selecionados_sem_nada_marcado_sai_0(base: Path, capsys) -> None:
    (base / "last-scan.json").write_text("[]")
    rc, rodados = _aplicar(base, "--selecionados")
    assert rc == 0 and rodados == [] and "nada a atualizar." in capsys.readouterr().err


def test_aplicar_nome_desconhecido_e_uso_errado(base: Path, capsys) -> None:
    rc, rodados = _aplicar(base, "org.evil.App;rm", "--sim")
    assert rc == 1 and rodados == [] and "nenhuma atualizacao pendente para: org.evil.App;rm" in capsys.readouterr().err
    assert _aplicar(base)[0] == 1
    assert _aplicar(base, "--selecionados", "org.videolan.VLC")[0] == 1


def test_aplicar_falha_do_flatpak_sai_1(base: Path, capsys) -> None:
    rc, rodados = _aplicar(base, "org.videolan.VLC", "--sim", rc=1)
    assert rc == 1 and len(rodados) == 1
    assert "flatpak update saiu com codigo 1" in capsys.readouterr().err
