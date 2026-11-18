"""Carregador de configuracao: defaults, leitura completa e erros que citam a chave."""
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
