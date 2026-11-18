"""Carregador de configuracao: defaults, leitura completa e erros que citam a chave."""
import os

import pytest

from mandacaru.config import Config, ConfigError, load_config
from mandacaru.events import Severity


def write(tmp_path, text):
    p = tmp_path / "config.toml"
    p.write_text(text, encoding="utf-8")
    return p


def test_sem_arquivo_padrao_devolve_defaults(monkeypatch, tmp_path):
    monkeypatch.setattr("mandacaru.config.DEFAULT_PATH", str(tmp_path / "nao-existe.toml"))
    assert load_config() == Config()


def test_caminho_explicito_inexistente_e_erro(tmp_path):
    with pytest.raises(ConfigError, match="nao-existe.toml"):
        load_config(tmp_path / "nao-existe.toml")


def test_le_todas_as_chaves(tmp_path):
    cfg = load_config(write(tmp_path, '''
[monitor]
paths = ["/srv/uploads"]
ebpf = false
[alerts]
min_severity = "high"
json = "/var/log/mandacaru/alerts.jsonl"
[rules]
dirs = ["/etc/mandacaru/rules.d"]
[exclude]
paths = ["/home/*/.cache/*"]
'''))
    assert cfg == Config(watch_paths=("/srv/uploads",), ebpf=False, min_severity=Severity.HIGH,
                         json_path="/var/log/mandacaru/alerts.jsonl",
                         rule_dirs=("/etc/mandacaru/rules.d",), exclude=("/home/*/.cache/*",))


def test_arquivo_vazio_devolve_defaults(tmp_path):
    assert load_config(write(tmp_path, "")) == Config()


@pytest.mark.parametrize("text, trecho", [
    ('[alerts]\nmin_severty = "LOW"\n', "alerts.min_severty"),      # chave desconhecida
    ('[resposta]\nx = 1\n', "resposta"),                             # secao desconhecida
    ('[monitor]\npaths = "/tmp"\n', "monitor.paths"),                # tipo errado: str em vez de lista
    ('[monitor]\nebpf = "sim"\n', "monitor.ebpf"),                   # tipo errado: str em vez de bool
    ('[alerts]\nmin_severity = "URGENTE"\n', "alerts.min_severity"), # valor fora do enum
    ('[monitor\npaths = []\n', "TOML"),                              # sintaxe invalida
])
def test_config_invalido_cita_a_chave(tmp_path, text, trecho):
    with pytest.raises(ConfigError, match=trecho):
        load_config(write(tmp_path, text))


# --------------------------------------------------- socket de alertas (0.3.0)
def test_socket_preenche_socket_path(tmp_path):
    cfg = load_config(write(tmp_path, '[alerts]\nsocket = "/x"\n'))
    assert cfg.socket_path == "/x"


def test_socket_vazio_desliga(tmp_path):
    from mandacaru import cli
    cfg = load_config(write(tmp_path, '[alerts]\nsocket = ""\n'))
    assert cfg.socket_path == ""
    assert len(cli.build_sinks(cfg)[0]) == 1


def test_socket_com_tipo_errado_e_erro(tmp_path):
    with pytest.raises(ConfigError, match="alerts.socket: esperava um texto"):
        load_config(write(tmp_path, "[alerts]\nsocket = 1\n"))


def test_secoes_de_quarentena_e_analise(tmp_path):
    cfg = load_config(write(tmp_path, '''
[quarantine]
enabled = false
min_severity = "critical"
retention_days = 7
max_file_mb = 10
max_total_mb = 100
[analysis]
cymru = false
virustotal_key = "vt"
malwarebazaar_key = "mb"
'''))
    assert (cfg.quarantine, cfg.quarantine_min_severity, cfg.retention_days) == (False, Severity.CRITICAL, 7)
    assert (cfg.max_file_mb, cfg.max_total_mb) == (10, 100)
    assert (cfg.cymru, cfg.virustotal_key, cfg.malwarebazaar_key) == (False, "vt", "mb")


def test_padroes_da_quarentena():
    c = Config()
    assert (c.quarantine, c.quarantine_min_severity, c.retention_days, c.max_file_mb, c.max_total_mb, c.cymru) == \
        (True, Severity.HIGH, 30, 256, 2048, True)


@pytest.mark.parametrize("v", ["0", "-1", "true", '"30"', "1.5"])
def test_retention_days_invalido(tmp_path, v):
    with pytest.raises(ConfigError, match="quarantine.retention_days"):
        load_config(write(tmp_path, f"[quarantine]\nretention_days = {v}\n"))


def test_chave_desconhecida_em_analysis(tmp_path):
    with pytest.raises(ConfigError, match="analysis.vt"):
        load_config(write(tmp_path, '[analysis]\nvt = "x"\n'))


_root = pytest.mark.skipif(os.geteuid() == 0, reason="root ignora permissao de leitura")


@_root
def test_padrao_sem_permissao_usa_defaults_e_avisa(monkeypatch, tmp_path, capsys):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[analysis]\nvirustotal_key = "segredo"\n')
    cfg.chmod(0o000)   # 0640 root:root visto por usuario comum
    monkeypatch.setattr("mandacaru.config.DEFAULT_PATH", str(cfg))
    assert load_config() == Config()
    err = capsys.readouterr().err
    assert err == f"[mandacaru] aviso: sem permissao para ler {cfg}; usando configuracao padrao\n"


@_root
def test_config_explicito_sem_permissao_continua_erro(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[monitor]\nebpf = true\n")
    cfg.chmod(0o000)
    with pytest.raises(ConfigError, match="nao foi possivel ler"):
        load_config(cfg)


def test_padrao_com_toml_invalido_continua_erro(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[monitor\n")
    monkeypatch.setattr("mandacaru.config.DEFAULT_PATH", str(cfg))
    with pytest.raises(ConfigError, match="TOML invalido"):
        load_config()
