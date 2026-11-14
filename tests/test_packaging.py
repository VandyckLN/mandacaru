"""Empacotamento: config de exemplo valido, versoes coerentes, unit apontando para o config."""
import re
from pathlib import Path

import pytest

import mandacaru
from mandacaru.config import Config, load_config
from mandacaru.events import Severity

ROOT = Path(__file__).resolve().parent.parent
# o pybuild copia tests/ para um diretorio de build sem debian/ nem packaging/
pytestmark = pytest.mark.skipif(not (ROOT / "pyproject.toml").is_file(), reason="fora da arvore de fontes")


def test_config_de_exemplo_e_valido():
    cfg = load_config(ROOT / "packaging" / "config.toml")
    assert cfg == Config(ebpf=True, min_severity=Severity.LOW,
                         json_path="/var/log/mandacaru/alerts.jsonl",
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
