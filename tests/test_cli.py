"""CLI: precedencia flag > arquivo > padrao, pastas padrao e erros com saida 1."""
import os
import queue

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


# ------------------------------------------------------ coletor de processos
class FakeCollector:
    def __init__(self, q):
        self.started = False

    def start(self):
        self.started = True

    def stop(self):
        pass


def test_ebpf_quebrado_cai_para_psutil(monkeypatch, capsys):
    def boom(q):
        raise RuntimeError("sem headers do kernel")
    monkeypatch.setattr(cli.ebpf, "available", lambda: True)
    monkeypatch.setattr(cli.ebpf, "ExecTracer", boom)
    monkeypatch.setattr(cli, "ProcessMonitor", FakeCollector)
    kind, stop = cli.start_process_collector(queue.Queue(), use_ebpf=True)
    assert kind == "psutil" and callable(stop)
    assert "eBPF indisponivel (sem headers do kernel)" in capsys.readouterr().err


def test_ebpf_desligado_nem_tenta(monkeypatch):
    def nao_devia(q):
        raise AssertionError("nao devia tentar eBPF")
    monkeypatch.setattr(cli.ebpf, "available", lambda: True)
    monkeypatch.setattr(cli.ebpf, "ExecTracer", nao_devia)
    monkeypatch.setattr(cli, "ProcessMonitor", FakeCollector)
    assert cli.start_process_collector(queue.Queue(), use_ebpf=False)[0] == "psutil"


def test_ebpf_funcionando_e_usado(monkeypatch):
    monkeypatch.setattr(cli.ebpf, "available", lambda: True)
    monkeypatch.setattr(cli.ebpf, "ExecTracer", FakeCollector)
    assert cli.start_process_collector(queue.Queue(), use_ebpf=True)[0] == "ebpf"


# ------------------------------------------------ achados da revisao final
def test_scan_ignora_json_do_arquivo_de_config(tmp_path, capsys):
    # o config do servico aponta para /var/log (so root grava); scan de usuario comum nao pode quebrar
    c = cfgfile(tmp_path, f'[alerts]\njson = "{tmp_path}/nao/existe/alerts.jsonl"\n')
    assert cli.effective_config(parse(["--config", c, "scan", "."])).json_path is None
    assert cli.effective_config(parse(["--config", c, "monitor"])).json_path is not None
    assert cli.main(["--config", c, "scan", str(tmp_path)]) == 0


def test_regra_yara_invalida_sai_com_1_citando_o_arquivo(tmp_path, capsys):
    (tmp_path / "quebrada.yar").write_text("rule x { condition: ")
    assert cli.main(["--rules", str(tmp_path), "scan", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "mandacaru: erro:" in err and "quebrada.yar" in err and "Traceback" not in err


def test_pasta_vigiada_inexistente_avisa_e_segue(tmp_path, capsys):
    ok = tmp_path / "ok"
    ok.mkdir()
    assert cli.resolve_watch_paths([str(ok), str(tmp_path / "typo")]) == [str(ok)]
    assert f"pasta vigiada nao existe: {tmp_path / 'typo'}" in capsys.readouterr().err


def test_nenhuma_pasta_vigiada_existente_e_erro(tmp_path):
    import pytest
    with pytest.raises(cli.CliError, match="nenhuma pasta"):
        cli.resolve_watch_paths([str(tmp_path / "typo")])


# ------------------------------------------------- socket de alertas (0.3.0)
def test_build_sinks_com_socket_cria_o_arquivo(short_dir, capsys):
    from mandacaru.config import Config
    p = os.path.join(short_dir, "a.sock")
    sinks, stops = cli.build_sinks(Config(socket_path=p))
    try:
        assert len(sinks) == 2 and os.path.exists(p)
        assert f"[mandacaru] alertas em tempo real: {p}" in capsys.readouterr().err
    finally:
        for s in stops:
            s()
    assert not os.path.exists(p)


def test_build_sinks_com_socket_impossivel_avisa_e_segue(short_dir, capsys):
    from mandacaru.config import Config
    sinks, stops = cli.build_sinks(Config(socket_path=os.path.join(short_dir, "nao", "a.sock")))
    assert len(sinks) == 1 and stops == []
    assert "[mandacaru] socket de alertas desligado:" in capsys.readouterr().err


def test_build_sinks_sem_socket():
    from mandacaru.config import Config
    sinks, stops = cli.build_sinks(Config())
    assert len(sinks) == 1 and stops == []


def test_jsonl_nao_perde_alerta_com_nome_utf8_invalido(tmp_path):
    from mandacaru.engine import Engine, jsonl_sink
    from mandacaru.events import Alert
    recebidos = []
    fh = cli.open_alert_log(str(tmp_path / "a.jsonl"))
    engine = Engine([jsonl_sink(fh), recebidos.append])
    nome = os.fsdecode(b"payload\xff.sh")
    engine.emit(Alert(rule="r", severity=Severity.HIGH, summary=nome, evidence={"path": "/tmp/" + nome}))
    fh.close()
    assert len(recebidos) == 1               # o sink seguinte ainda recebeu
    assert "payload" in (tmp_path / "a.jsonl").read_text(encoding="utf-8")
