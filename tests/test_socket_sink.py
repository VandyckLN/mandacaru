"""Socket de alertas: contrato JSON v1, permissao e nunca travar o motor."""
import json
import os
import socket
import stat
import threading
import time

import pytest

from mandacaru import alert_socket
from mandacaru.alert_socket import alert_line, socket_sink
from mandacaru.events import Alert, Severity


def mk(sev=Severity.HIGH, summary="Shell bash com conexao de rede ativa"):
    return Alert(rule="behavior.revshell", severity=sev, summary=summary,
                 evidence={"cmdline": ["bash", "-i"], "pid": 42}, mitre=["T1059"], ts=1794872689.2)


def connect(path):
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.settimeout(2)
    c.connect(path)
    time.sleep(0.1)  # a thread de accept registra o cliente
    return c


def readline(sock):
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(65536)
        assert chunk, "conexao fechada antes do fim da linha"
        buf += chunk
    return json.loads(buf)


@pytest.fixture
def path(short_dir):
    return os.path.join(short_dir, "a.sock")


@pytest.fixture
def sem_grupo(monkeypatch):
    monkeypatch.setattr(alert_socket, "_group_gid", lambda name: None)


def test_cliente_recebe_json_v1_sem_evidence(path, sem_grupo):
    sink, stop = socket_sink(path, Severity.LOW)
    try:
        c = connect(path)
        sink(mk())
        assert readline(c) == {"v": 1, "ts": 1794872689.2, "severity": "HIGH", "rule": "behavior.revshell",
                               "summary": "Shell bash com conexao de rede ativa", "mitre": ["T1059"]}
    finally:
        stop()


def test_resumo_com_acento_sai_em_utf8():
    line = alert_line(mk(summary="Ação suspeita: relatório.sh"))
    assert "Ação".encode() in line and b"\\u00e7" not in line
    assert line.endswith(b"\n") and line.count(b"\n") == 1


def test_abaixo_do_min_sev_nao_sai(path, sem_grupo):
    sink, stop = socket_sink(path, Severity.HIGH)
    try:
        c = connect(path)
        sink(mk(Severity.MEDIUM))
        sink(mk(Severity.HIGH))
        assert readline(c)["severity"] == "HIGH"
    finally:
        stop()


def test_dois_clientes_recebem_o_mesmo_alerta(path, sem_grupo):
    sink, stop = socket_sink(path, Severity.LOW)
    try:
        a, b = connect(path), connect(path)
        sink(mk())
        assert readline(a) == readline(b)
    finally:
        stop()


def test_cliente_que_nao_le_e_derrubado_sem_travar(path, sem_grupo):
    sink, stop = socket_sink(path, Severity.LOW)
    try:
        lento = connect(path)   # nunca le: o buffer do kernel (~200 KB) enche
        rapido = connect(path)
        linhas = []

        def ler():
            buf = b""
            rapido.settimeout(5)
            while len(linhas) < 50:
                chunk = rapido.recv(1 << 20)
                if not chunk:
                    return
                buf += chunk
                *prontas, buf = buf.split(b"\n")
                linhas.extend(prontas)
        t = threading.Thread(target=ler)
        t.start()
        pior = 0.0
        for _ in range(50):     # 50 x 16 KB = 800 KB, espacados como alertas reais
            t0 = time.monotonic()
            sink(mk(summary="x" * 16384))
            pior = max(pior, time.monotonic() - t0)
            time.sleep(0.002)
        assert pior < 0.1
        t.join(5)
        assert len(linhas) == 50
        lento.settimeout(2)
        try:
            while lento.recv(1 << 20):
                pass  # esvazia o que chegou antes de ser derrubado; recv vazio = fechado pelo servidor
        except ConnectionResetError:
            pass
    finally:
        stop()


def test_cliente_que_fecha_e_removido_sem_excecao(path, sem_grupo):
    sink, stop = socket_sink(path, Severity.LOW)
    try:
        c = connect(path)
        c.close()
        time.sleep(0.1)
        sink(mk())
        sink(mk())
    finally:
        stop()


def test_socket_velho_e_recriado(path, sem_grupo):
    velho = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    velho.bind(path)
    velho.close()
    assert stat.S_ISSOCK(os.stat(path).st_mode)
    sink, stop = socket_sink(path, Severity.LOW)
    try:
        c = connect(path)
        sink(mk())
        assert readline(c)["rule"] == "behavior.revshell"
    finally:
        stop()


def test_arquivo_comum_no_caminho_nao_e_apagado(path, sem_grupo):
    with open(path, "w") as fh:
        fh.write("x")
    with pytest.raises(OSError):
        socket_sink(path, Severity.LOW)
    with open(path) as fh:
        assert fh.read() == "x"


def test_pai_inexistente_levanta_oserror(short_dir, sem_grupo):
    with pytest.raises(OSError):
        socket_sink(os.path.join(short_dir, "nao", "a.sock"), Severity.LOW)


def test_sem_grupo_fica_0600_e_avisa(path, sem_grupo, capsys):
    _, stop = socket_sink(path, Severity.LOW)
    try:
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert "[mandacaru] grupo mandacaru ausente: socket so para root" in capsys.readouterr().err
    finally:
        stop()


def test_com_grupo_fica_0660_no_grupo(path, monkeypatch):
    monkeypatch.setattr(alert_socket, "_group_gid", lambda name: os.getgid())
    _, stop = socket_sink(path, Severity.LOW)
    try:
        st = os.stat(path)
        assert stat.S_IMODE(st.st_mode) == 0o660 and st.st_gid == os.getgid()
    finally:
        stop()


def test_chown_negado_cai_para_0600(path, monkeypatch, capsys):
    if os.geteuid() == 0 or 0 in os.getgroups():
        pytest.skip("precisa de um usuario comum fora do grupo root")
    monkeypatch.setattr(alert_socket, "_group_gid", lambda name: 0)
    _, stop = socket_sink(path, Severity.LOW)
    try:
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        err = capsys.readouterr().err
        assert "[mandacaru] sem permissao para dar o socket ao grupo mandacaru: socket so para root" in err
    finally:
        stop()


def test_stop_apaga_o_socket_e_encerra_rapido(path, sem_grupo):
    sink, stop = socket_sink(path, Severity.LOW)
    t0 = time.monotonic()
    stop()
    assert time.monotonic() - t0 < 1.0
    assert not os.path.exists(path)
    sink(mk())  # depois do stop: nao levanta
    stop()      # idempotente
