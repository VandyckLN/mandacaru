"""CLI: precedencia flag > arquivo > padrao, pastas padrao e erros com saida 1."""
import os

from mandacaru import cli
from mandacaru.events import Severity

EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def parse(argv):
    return cli.build_parser().parse_args(argv)


def cfgfile(tmp_path, text):
    p = tmp_path / "c.toml"
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_flag_vence_o_arquivo(tmp_path):
    c = cfgfile(tmp_path, '[alerts]\nmin_severity = "HIGH"\njson = "/a.jsonl"\n[rules]\ndirs = ["/r1"]\n')
    cfg = cli.effective_config(parse(["--config", c, "--min-severity", "LOW", "--json", "/b.jsonl",
                                      "--rules", "/r2", "scan", "."]))
    assert cfg.min_severity == Severity.LOW
    assert cfg.json_path == "/b.jsonl"
    assert cfg.rule_dirs == ("/r1", "/r2")


def test_arquivo_vale_quando_nao_ha_flag(tmp_path):
    c = cfgfile(tmp_path, '[alerts]\nmin_severity = "HIGH"\n[monitor]\npaths = ["/srv"]\nebpf = true\n')
    cfg = cli.effective_config(parse(["--config", c, "monitor"]))
    assert (cfg.min_severity, cfg.watch_paths, cfg.ebpf) == (Severity.HIGH, ("/srv",), True)
    cfg = cli.effective_config(parse(["--config", c, "monitor", "--no-ebpf", "/outro"]))
    assert (cfg.watch_paths, cfg.ebpf) == (("/outro",), False)


def test_json_e_excluido_automaticamente(tmp_path):
    out = tmp_path / "alerts.jsonl"
    cfg = cli.effective_config(parse(["--json", str(out), "scan", "."]))
    assert os.path.abspath(out) in cfg.exclude


def test_scan_nao_escaneia_o_proprio_jsonl(tmp_path):
    out = tmp_path / "alerts.jsonl"
    out.write_text(EICAR)          # um JSONL antigo cujo conteudo casaria com uma regra
    assert cli.main(["--json", str(out), "scan", str(tmp_path)]) == 0
    assert out.read_text() == EICAR   # nenhum alerta gravado: o proprio arquivo foi pulado


def test_root_vigia_home_de_cada_usuario(tmp_path):
    (tmp_path / "ana" / "Downloads").mkdir(parents=True)
    (tmp_path / "bia" / "Documentos").mkdir(parents=True)
    got = cli.default_watch_paths(euid=0, home_root=tmp_path)
    assert str(tmp_path / "ana" / "Downloads") in got
    assert str(tmp_path / "bia" / "Documentos") in got
    assert not any(p.startswith("/root") for p in got)


def test_config_invalido_sai_com_1_sem_traceback(tmp_path, capsys):
    c = cfgfile(tmp_path, '[alerts]\nmin_severty = "LOW"\n')
    assert cli.main(["--config", c, "scan", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "mandacaru: erro:" in err and "alerts.min_severty" in err and "Traceback" not in err


def test_json_nao_gravavel_sai_com_1(tmp_path, capsys):
    assert cli.main(["--json", str(tmp_path / "nao" / "existe" / "a.jsonl"), "scan", str(tmp_path)]) == 1
    assert "mandacaru: erro:" in capsys.readouterr().err
