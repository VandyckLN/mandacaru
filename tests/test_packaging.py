"""Empacotamento: config de exemplo valido, versoes coerentes, unit apontando para o config."""
import re
import struct
from pathlib import Path

import pytest

import mandacaru
from mandacaru.config import Config, load_config
from mandacaru.events import Severity

ROOT = Path(__file__).resolve().parent.parent
# Estes testes leem debian/ e packaging/, que nao existem no diretorio de build do pybuild:
# debian/rules os tira do dh_auto_test (ver test_build_do_deb_ignora_este_arquivo).


def test_config_de_exemplo_e_valido():
    cfg = load_config(ROOT / "packaging" / "config.toml")
    assert cfg == Config(ebpf=True, min_severity=Severity.LOW,
                         json_path="/var/log/mandacaru/alerts.jsonl",
                         socket_path="/run/mandacaru/alerts.sock",
                         rule_dirs=("/etc/mandacaru/rules.d",))
    assert "uso NAO comercial" in (ROOT / "packaging" / "config.toml").read_text()


def test_versao_do_changelog_debian_bate_com_o_pacote():
    first = (ROOT / "debian" / "changelog").read_text().splitlines()[0]
    assert re.match(r"mandacaru \(([^)]+)\)", first).group(1) == mandacaru.__version__


def test_unit_aponta_para_o_config_instalado():
    unit = (ROOT / "debian" / "mandacaru.service").read_text()
    assert "ExecStart=/usr/bin/mandacaru --config /etc/mandacaru/config.toml monitor" in unit


def test_nome_no_pypi_e_changelog_da_versao():
    tomllib = pytest.importorskip("tomllib")
    proj = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert proj["name"] == "mandacaru-edr"
    assert f"## {mandacaru.__version__}" in (ROOT / "CHANGELOG.md").read_text()


def test_build_do_deb_ignora_este_arquivo():
    rules = (ROOT / "debian" / "rules").read_text()
    assert "export PYBUILD_TEST_ARGS = --ignore=tests/test_packaging.py" in rules


def test_unit_protege_o_log_e_nao_reinicia_em_erro_de_config():
    unit = (ROOT / "debian" / "mandacaru.service").read_text()
    assert "LogsDirectoryMode=0750" in unit and "UMask=0027" in unit   # alertas trazem linhas de comando
    assert "RestartPreventExitStatus=1" in unit                        # saida 1 = erro de config: nao adianta reiniciar


def test_unit_cria_o_diretorio_do_socket():
    unit = (ROOT / "debian" / "mandacaru.service").read_text()
    assert "RuntimeDirectory=mandacaru" in unit and "RuntimeDirectoryMode=0755" in unit


def test_postinst_cria_o_grupo_antes_do_debhelper():
    post = (ROOT / "debian" / "mandacaru.postinst").read_text()
    assert "addgroup --system --quiet mandacaru" in post
    assert post.index("addgroup") < post.index("#DEBHELPER#")   # grupo existe antes de o servico subir


def test_control_depende_de_adduser():
    assert "adduser" in (ROOT / "debian" / "control").read_text().split("Package: mandacaru", 1)[1]


def test_icone_e_png_64_indexado_e_leve():
    png = (ROOT / "packaging" / "icons" / "64x64" / "mandacaru.png").read_bytes()
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    largura, altura, _, tipo_cor = struct.unpack(">IIBB", png[16:26])
    assert (largura, altura, tipo_cor) == (64, 64, 3)   # paleta: 1:1 no max-icon-size do mako
    assert b"tRNS" in png                                # fundo transparente
    assert len(png) <= 1024


def test_icone_vai_para_o_hicolor():
    install = (ROOT / "debian" / "mandacaru.install").read_text()
    assert "packaging/icons/64x64/mandacaru.png usr/share/icons/hicolor/64x64/apps/" in install


# --- quarentena (0.4.0) ---

ID_OK = "0123456789abcdef0123456789abcdef"
DECIDE = ROOT / "packaging" / "libexec" / "quarantine-decide"
RELEASE = ROOT / "packaging" / "libexec" / "quarantine-release"


def test_service_tem_state_directory_e_escrita_em_home():
    unit = (ROOT / "debian" / "mandacaru.service").read_text()
    assert "StateDirectory=mandacaru" in unit and "StateDirectoryMode=0755" in unit
    assert "ReadWritePaths=/home" in unit and "ProtectHome=read-only" in unit   # move arquivos de /home
    assert ("ExecStartPre=+/usr/bin/install -d -m 0750 -o root -g mandacaru /var/lib/mandacaru/quarantine"
            in unit)


def test_timer_de_limpeza_diario_persistente():
    timer = (ROOT / "debian" / "mandacaru.mandacaru-quarantine-clean.timer").read_text()
    assert "OnCalendar=daily" in timer and "Persistent=true" in timer
    assert "WantedBy=timers.target" in timer
    svc = (ROOT / "debian" / "mandacaru.mandacaru-quarantine-clean.service").read_text()
    assert "Type=oneshot" in svc
    assert "ExecStart=/usr/bin/mandacaru --config /etc/mandacaru/config.toml quarentena limpar" in svc
    assert "StateDirectory=mandacaru" in svc and "StateDirectoryMode=0755" in svc
    rules = (ROOT / "debian" / "rules").read_text()
    assert "dh_installsystemd --name=mandacaru-quarantine-clean" in rules


def _acoes_da_policy():
    import xml.etree.ElementTree as ET
    root = ET.parse(ROOT / "packaging" / "polkit" / "io.github.vandyckln.mandacaru.policy").getroot()
    return {a.get("id"): a for a in root.findall("action")}


def test_policy_release_exige_admin():
    acoes = _acoes_da_policy()
    assert set(acoes) == {"io.github.vandyckln.mandacaru.decide", "io.github.vandyckln.mandacaru.release"}
    for nome, aux in (("decide", "quarantine-decide"), ("release", "quarantine-release")):
        acao = acoes[f"io.github.vandyckln.mandacaru.{nome}"]
        for chave in ("allow_any", "allow_inactive", "allow_active"):
            assert acao.find(f"defaults/{chave}").text == "auth_admin"   # decide: so a regra libera o grupo
        exec_path = [a.text for a in acao.findall("annotate")
                     if a.get("key") == "org.freedesktop.policykit.exec.path"]
        assert exec_path == [f"/usr/libexec/mandacaru/{aux}"]


def test_regra_libera_so_decide_para_o_grupo():
    regra = (ROOT / "packaging" / "polkit" / "50-mandacaru.rules").read_text()
    assert 'subject.isInGroup("mandacaru")' in regra
    assert "subject.active" in regra and "subject.local" in regra
    assert "io.github.vandyckln.mandacaru.decide" in regra and "polkit.Result.YES" in regra
    assert "io.github.vandyckln.mandacaru.release" not in regra


def _roda(script, *args):
    import os
    import subprocess
    env = dict(os.environ, MANDACARU_BIN="echo")
    return subprocess.run(["sh", str(script), *args], capture_output=True, text=True, env=env)


@pytest.mark.parametrize("script,args,codigo", [
    (RELEASE, ("manter", ID_OK), 1),
    (RELEASE, ("analisar", ID_OK), 1),
    (DECIDE, ("confiar", ID_OK), 1),
    (DECIDE, ("apagar", ID_OK), 1),
    (DECIDE, ("limpar",), 1),
    (DECIDE, (), 1),
    (DECIDE, ("manter", ID_OK, "--json"), 1),
    (DECIDE, ("analisar", ID_OK, "--enviar"), 1),
    (RELEASE, ("confiar", ID_OK, "--json"), 1),
    (DECIDE, ("manter", "0123"), 3),
    (DECIDE, ("analisar", ID_OK.upper()), 3),
    (DECIDE, ("analisar", "../../etc/passwd"), 3),
    (RELEASE, ("apagar", ID_OK + "0"), 3),
    (RELEASE, ("confiar", ""), 3),
])
def test_auxiliares_aceitam_so_seus_subcomandos(script, args, codigo):
    r = _roda(script, *args)
    assert r.returncode == codigo
    assert r.stdout == ""                       # nao chegou a chamar o mandacaru
    if codigo == 1:
        assert "uso:" in r.stderr


@pytest.mark.parametrize("script,args", [
    (DECIDE, ("analisar", ID_OK, "--json")),
    (DECIDE, ("analisar", ID_OK)),
    (DECIDE, ("manter", ID_OK)),
    (RELEASE, ("confiar", ID_OK)),
    (RELEASE, ("apagar", ID_OK)),
])
def test_auxiliares_repassam_para_o_mandacaru(script, args):
    r = _roda(script, *args)
    assert r.returncode == 0
    assert r.stdout.split() == ["--config", "/etc/mandacaru/config.toml", "quarentena", *args]


def test_auxiliares_usam_o_binario_instalado_por_padrao():
    for script in (DECIDE, RELEASE):
        texto = script.read_text()
        assert texto.startswith("#!/bin/sh")
        assert "${MANDACARU_BIN:-/usr/bin/mandacaru}" in texto
        assert script.stat().st_mode & 0o755 == 0o755


def test_logrotate_guarda_decisoes_um_ano():
    texto = (ROOT / "debian" / "mandacaru.logrotate").read_text()
    assert "*.jsonl" not in texto                         # senao o decisions.jsonl rodaria duas vezes
    blocos = dict(re.findall(r"(\S+)\s*\{([^}]*)\}", texto))
    assert set(blocos) == {"/var/log/mandacaru/alerts.jsonl", "/var/log/mandacaru/decisions.jsonl"}
    assert "rotate 8" in blocos["/var/log/mandacaru/alerts.jsonl"]
    dec = blocos["/var/log/mandacaru/decisions.jsonl"].split()
    for diretiva in ("weekly", "compress", "copytruncate"):
        assert diretiva in dec
    assert dec[dec.index("rotate") + 1] == "52"


def test_install_leva_polkit_e_auxiliares():
    linhas = (ROOT / "debian" / "mandacaru.install").read_text().splitlines()
    assert "packaging/libexec/quarantine-decide usr/libexec/mandacaru/" in linhas
    assert "packaging/libexec/quarantine-release usr/libexec/mandacaru/" in linhas
    assert "packaging/polkit/io.github.vandyckln.mandacaru.policy usr/share/polkit-1/actions/" in linhas
    assert "packaging/polkit/50-mandacaru.rules usr/share/polkit-1/rules.d/" in linhas
    rules = (ROOT / "debian" / "rules").read_text()
    assert "chmod 0755 debian/mandacaru/usr/libexec/mandacaru/quarantine-" in rules
    assert "chmod 0640 debian/mandacaru/etc/mandacaru/config.toml" in rules


def test_depende_de_polkit():
    control = (ROOT / "debian" / "control").read_text().split("Package: mandacaru", 1)[1]
    assert "polkitd | policykit-1" in control
