"""Empacotamento: config de exemplo valido, versoes coerentes, unit apontando para o config."""
import re
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
