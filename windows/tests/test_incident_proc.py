"""Encerrar processos do usuário conferindo caminho e SHA-256."""
import subprocess
import sys

import pytest
from mandacaru_win.incident import sha256_arquivo
from mandacaru_win.incident_proc import ProcessoInfo, encerrar_arvore

EXE = r"C:\Users\ana\AppData\Local\Temp\mal.exe"
SHA = "a" * 64


class ProcessosFalsos:
    def __init__(self, procs, falha=()):
        self.vivos = {p.pid: p for p in procs}
        self.falha = set(falha)
        self.encerrados: list[int] = []

    def listar(self):
        return list(self.vivos.values())

    def info(self, pid):
        return self.vivos.get(pid)

    def encerrar(self, pid, criado):
        if pid in self.falha:
            raise OSError("Acesso negado")
        if self.vivos[pid].criado != criado:
            raise OSError("O processo mudou")
        self.vivos.pop(pid)
        self.encerrados.append(pid)


def _hash(sha=SHA):
    return lambda _p: sha


def _arvore():
    return ProcessosFalsos([
        ProcessoInfo(100, 1, EXE, 10.0),
        ProcessoInfo(101, 100, r"C:\Windows\System32\cmd.exe", 11.0),
        ProcessoInfo(102, 101, r"C:\x\filho.exe", 12.0),
        ProcessoInfo(200, 1, r"C:\Program Files\Editor\editor.exe", 5.0),
    ])


def test_encerra_alvo_e_descendentes():
    p = _arvore()
    r = encerrar_arvore(p, 100, EXE.lower(), SHA, hash_fn=_hash(), proprio_pid=999)
    assert r.recusa is None and r.falhas == []
    assert r.encerrados == [100, 101, 102] == p.encerrados
    assert 200 in p.vivos


def test_recusa_pid_reaproveitado():
    p = _arvore()
    r = encerrar_arvore(p, 200, EXE, SHA, hash_fn=_hash(), proprio_pid=999)
    assert r.recusa == "O número do processo agora pertence a outro programa; nada foi encerrado."
    assert p.encerrados == [] and r.encerrados == []


def test_recusa_exe_alterado():
    p = _arvore()
    r = encerrar_arvore(p, 100, EXE, SHA, hash_fn=_hash("b" * 64), proprio_pid=999)
    assert r.recusa == "O executável mudou desde a detecção; nada foi encerrado."
    assert p.encerrados == []


def test_recusa_exe_ilegivel():
    p = _arvore()
    r = encerrar_arvore(p, 100, EXE, SHA, hash_fn=lambda _p: None, proprio_pid=999)
    assert r.recusa == "O executável mudou desde a detecção; nada foi encerrado."


def test_recusa_processo_que_ja_terminou():
    r = encerrar_arvore(_arvore(), 555, EXE, SHA, hash_fn=_hash(), proprio_pid=999)
    assert r.recusa == "O processo já terminou."


@pytest.mark.parametrize("pid", [0, 4, 999])
def test_recusa_sistema_e_proprio(pid):
    p = ProcessosFalsos([ProcessoInfo(pid, 1, EXE, 1.0)])
    r = encerrar_arvore(p, pid, EXE, SHA, hash_fn=_hash(), proprio_pid=999)
    assert r.recusa == "Processo do sistema ou do próprio Mandacaru: não será encerrado."
    assert p.encerrados == []


def test_orfao_mais_antigo_nao_e_filho():
    p = ProcessosFalsos([
        ProcessoInfo(100, 1, EXE, 10.0),
        ProcessoInfo(300, 100, r"C:\x\orfao.exe", 3.0),     # pai original morreu; PID 100 foi reaproveitado
        ProcessoInfo(301, 100, r"C:\x\sem_data.exe", None),
    ])
    r = encerrar_arvore(p, 100, EXE, SHA, hash_fn=_hash(), proprio_pid=999)
    assert r.encerrados == [100]
    assert {300, 301} <= set(p.vivos)


def test_ciclo_de_ppid_termina():
    p = ProcessosFalsos([
        ProcessoInfo(100, 101, EXE, 10.0),
        ProcessoInfo(101, 100, r"C:\x\b.exe", 11.0),
    ])
    r = encerrar_arvore(p, 100, EXE, SHA, hash_fn=_hash(), proprio_pid=999)
    assert r.encerrados == [100, 101]


def test_falha_de_um_filho_nao_para_os_outros():
    p = _arvore()
    p.falha = {101}
    r = encerrar_arvore(p, 100, EXE, SHA, hash_fn=_hash(), proprio_pid=999)
    assert r.encerrados == [100, 102]
    assert r.falhas == [(101, "Acesso negado")]


def test_falha_no_alvo_vira_falha():
    p = _arvore()
    p.falha = {100}
    r = encerrar_arvore(p, 100, EXE, SHA, hash_fn=_hash(), proprio_pid=999)
    assert r.falhas[0] == (100, "Acesso negado") and r.recusa is None


@pytest.mark.skipif(sys.platform != "win32", reason="processos reais só no Windows")
def test_processos_windows_reais():
    import os

    from mandacaru_win.incident_proc import ProcessosWindows
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        backend = ProcessosWindows()
        info = backend.info(proc.pid)
        assert info is not None and os.path.normcase(info.exe) == os.path.normcase(sys.executable)
        assert any(p.pid == proc.pid for p in backend.listar())
        r = encerrar_arvore(backend, proc.pid, sys.executable, sha256_arquivo(sys.executable))
        assert r.recusa is None and proc.pid in r.encerrados
        assert proc.wait(10) is not None
    finally:
        if proc.poll() is None:
            proc.kill()
