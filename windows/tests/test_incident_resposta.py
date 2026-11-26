"""Fachada Resposta: toda ação passa por ela e fica registrada no incidente antes de agir."""
import os
import subprocess
import sys

import pytest
from mandacaru_win.incident import IncidentError, IncidentStore
from mandacaru_win.incident_persist import CHAVE_RUN, Entrada
from mandacaru_win.incident_proc import ProcessoInfo
from mandacaru_win.incident_resposta import Resposta

EXE = r"C:\Users\ana\AppData\Roaming\upd\svc.exe"
SHA = "a" * 64
ENTRADA = Entrada("hkcu_run", CHAVE_RUN, "Atualizador", f'"{EXE}"')
BACKUP = {"tipo": "hkcu_run", "chave": CHAVE_RUN, "nome": "Atualizador", "valor": f'"{EXE}"', "tipo_reg": 1}


class ProcessosFalsos:
    def __init__(self, exe=EXE):
        self.vivos = {100: ProcessoInfo(100, 1, str(exe), 10.0), 200: ProcessoInfo(200, 1, r"C:\x\editor.exe", 5.0)}

    def listar(self):
        return list(self.vivos.values())

    def info(self, pid):
        return self.vivos.get(pid)

    def encerrar(self, pid, criado):
        self.vivos.pop(pid)


class PersistenciaEspia:
    def __init__(self, store=None, inc_id=None, erro_backup=None, erro_restaurar=None):
        self.store, self.inc_id = store, inc_id
        self.erro_backup, self.erro_restaurar = erro_backup, erro_restaurar
        self.removidos, self.restaurados, self.vistos_no_disco, self.detectar_args = [], [], [], None

    def detectar(self, alvos, hashes=frozenset()):
        self.detectar_args = (list(alvos), set(hashes))
        return [ENTRADA]

    def backup(self, e):
        if self.erro_backup:
            raise IncidentError(self.erro_backup)
        return dict(BACKUP)

    def remover(self, backup):
        if self.store is not None:                       # o que já está gravado no disco neste momento
            self.vistos_no_disco.append(self.store.carregar(self.inc_id).acoes[-1])
        self.removidos.append(backup)

    def restaurar(self, backup):
        if self.erro_restaurar:
            raise IncidentError(self.erro_restaurar)
        self.restaurados.append(backup)


def _inc(tmp_path):
    store = IncidentStore(tmp_path / "incidents")
    inc = store.criar(origem="projeto", ameaca="projeto", pasta=r"C:\Users\ana\proj", achados=[
        {"regra": "hash.malicioso", "severidade": "CRITICAL", "caminho": EXE, "sha256": SHA},
        {"regra": "projeto.agente.injecao", "severidade": "HIGH", "caminho": "AGENTS.md"},
    ])
    return store, inc


def test_toda_acao_fica_registrada(tmp_path):
    store, inc = _inc(tmp_path)
    exe = tmp_path / "svc.exe"                         # o motor confere o SHA-256 do executável em disco
    exe.write_bytes(b"abc")
    sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    r = Resposta(store, inc, processos=ProcessosFalsos(exe),
                 persistencia=PersistenciaEspia(erro_backup="A entrada mudou desde a detecção; nada foi removido."))
    a1 = r.encerrar_processo(100, exe, sha)
    a2 = r.encerrar_processo(200, exe, sha, modo="automatica")
    a3 = r.remover_persistencia(ENTRADA)
    assert (a1.resultado, a2.resultado, a3.resultado) == ("concluida", "falhou", "falhou")
    acoes = store.carregar(inc.id).acoes
    assert [(a.tipo, a.fase, a.modo, a.resultado) for a in acoes] == [
        ("encerrar_processo", "conter", "guiada", "concluida"),
        ("encerrar_processo", "conter", "automatica", "falhou"),
        ("remover_persistencia", "neutralizar", "guiada", "falhou"),
    ]
    assert acoes[0].alvo["encerrados"] == [100] and acoes[0].alvo["pid"] == 100
    assert acoes[1].detalhe == "O número do processo agora pertence a outro programa; nada foi encerrado."
    assert acoes[2].detalhe == "A entrada mudou desde a detecção; nada foi removido." and acoes[2].backup is None


def test_encerrar_sem_backend_de_processos_falha_registrado(tmp_path):
    store, inc = _inc(tmp_path)
    a = Resposta(store, inc, processos=None, persistencia=PersistenciaEspia()).encerrar_processo(100, EXE, SHA)
    assert a.resultado == "falhou" and store.carregar(inc.id).acoes[0].resultado == "falhou"


def test_backup_gravado_antes_de_remover(tmp_path):
    store, inc = _inc(tmp_path)
    p = PersistenciaEspia(store, inc.id)
    a = Resposta(store, inc, processos=ProcessosFalsos(), persistencia=p).remover_persistencia(ENTRADA)
    [no_disco] = p.vistos_no_disco
    assert no_disco.resultado == "em_andamento" and no_disco.backup == BACKUP
    assert a.resultado == "concluida" and store.carregar(inc.id).acoes[0].resultado == "concluida"


def test_sem_gravar_nao_age(tmp_path):
    store, inc = _inc(tmp_path)

    class Quebrado(IncidentStore):
        def salvar(self, inc):
            raise IncidentError("Não foi possível gravar o registro do incidente: disco cheio")

    p = PersistenciaEspia()
    procs = ProcessosFalsos()
    r = Resposta(Quebrado(tmp_path / "incidents"), inc, processos=procs, persistencia=p)
    a = r.remover_persistencia(ENTRADA)
    b = r.encerrar_processo(100, EXE, SHA)
    assert p.removidos == [] and 100 in procs.vivos
    assert a.resultado == b.resultado == "falhou" and "disco cheio" in a.detalhe
    assert inc.acoes == []


def test_desfazer_restaura_e_marca(tmp_path):
    store, inc = _inc(tmp_path)
    p = PersistenciaEspia()
    r = Resposta(store, inc, processos=ProcessosFalsos(), persistencia=p)
    r.remover_persistencia(ENTRADA)
    d = r.desfazer(0)
    assert d.tipo == "desfazer" and d.resultado == "concluida" and d.alvo["indice"] == 0
    assert p.restaurados == [BACKUP]
    acoes = store.carregar(inc.id).acoes
    assert acoes[0].desfeita is True and acoes[1].tipo == "desfazer"


def test_desfazer_duas_vezes_recusa(tmp_path):
    store, inc = _inc(tmp_path)
    p = PersistenciaEspia()
    r = Resposta(store, inc, processos=ProcessosFalsos(), persistencia=p)
    r.remover_persistencia(ENTRADA)
    r.desfazer(0)
    d = r.desfazer(0)
    assert d.resultado == "falhou" and d.detalhe == "Esta ação já foi desfeita."
    assert len(p.restaurados) == 1


def test_desfazer_encerramento_ou_indice_invalido_recusa(tmp_path):
    store, inc = _inc(tmp_path)
    r = Resposta(store, inc, processos=ProcessosFalsos(), persistencia=PersistenciaEspia())
    r.encerrar_processo(100, EXE, SHA)
    assert r.desfazer(0).detalhe == "Esta ação não pode ser desfeita."
    assert r.desfazer(99).detalhe == "Esta ação não pode ser desfeita."
    assert r.desfazer(-1).detalhe == "Esta ação não pode ser desfeita."


def test_desfazer_que_falha_nao_marca(tmp_path):
    store, inc = _inc(tmp_path)
    p = PersistenciaEspia(erro_restaurar="Já existe outra entrada com esse nome; nada foi alterado.")
    r = Resposta(store, inc, processos=ProcessosFalsos(), persistencia=p)
    r.remover_persistencia(ENTRADA)
    d = r.desfazer(0)
    assert d.resultado == "falhou" and d.detalhe == "Já existe outra entrada com esse nome; nada foi alterado."
    assert store.carregar(inc.id).acoes[0].desfeita is False


def test_detectar_usa_caminhos_absolutos_e_pasta(tmp_path):
    store, inc = _inc(tmp_path)
    p = PersistenciaEspia()
    assert Resposta(store, inc, processos=None, persistencia=p).detectar_persistencia() == [ENTRADA]
    alvos, hashes = p.detectar_args
    assert alvos == [EXE, r"C:\Users\ana\proj"]          # "AGENTS.md" relativo casaria com qualquer texto
    assert hashes == {SHA}


@pytest.mark.parametrize("ampla", [
    r"C:\\", r"C:\Users", r"C:\Users\ana", r"C:\Users\ana\AppData",
    r"C:\Users\ana\AppData\Roaming", r"C:\Windows", r"C:\Program Files",
])
def test_pasta_ampla_nao_entra_em_alvos(tmp_path, ampla):
    store = IncidentStore(tmp_path / "incidents")
    inc = store.criar(origem="projeto", ameaca="projeto", pasta=ampla, achados=[
        {"regra": "projeto.agente.injecao", "severidade": "HIGH", "caminho": "AGENTS.md"},
    ])
    p = PersistenciaEspia()
    Resposta(store, inc, processos=None, persistencia=p).detectar_persistencia()
    alvos, _hashes = p.detectar_args
    assert alvos == []


def test_detectar_processos_por_caminho_pasta_e_hash(tmp_path):
    copia = tmp_path / "copia.exe"
    copia.write_bytes(b"abc")
    sha_copia = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    store = IncidentStore(tmp_path / "incidents")
    inc = store.criar(origem="projeto", ameaca="projeto", pasta=r"C:\Users\ana\proj", achados=[
        {"regra": "hash.malicioso", "severidade": "CRITICAL", "caminho": EXE, "sha256": sha_copia},
    ])
    procs = ProcessosFalsos()
    procs.vivos = {
        4: ProcessoInfo(4, 0, EXE, 1.0),
        os.getpid(): ProcessoInfo(os.getpid(), 1, EXE, 2.0),
        100: ProcessoInfo(100, 1, EXE, 10.0),
        101: ProcessoInfo(101, 1, r"C:\Users\ana\proj\node.exe", 11.0),
        102: ProcessoInfo(102, 1, str(copia), 12.0),
        200: ProcessoInfo(200, 1, r"C:\Program Files\Editor\editor.exe", 5.0),
    }
    achados = Resposta(store, inc, processos=procs, persistencia=PersistenciaEspia()).detectar_processos()
    assert [p.pid for p in achados] == [100, 101, 102]


def test_marcar_credencial_persiste_e_valida(tmp_path):
    store, inc = _inc(tmp_path)
    r = Resposta(store, inc, processos=None, persistencia=PersistenciaEspia())
    r.marcar_credencial("ssh", True)
    r.marcar_credencial("npm", False)
    assert store.carregar(inc.id).credenciais == {"ssh": True, "npm": False}
    with pytest.raises(IncidentError):
        r.marcar_credencial("https://evil.example", True)


def test_modulos_sem_qt():
    codigo = ("import sys; import mandacaru_win.incident, mandacaru_win.incident_proc, "
              "mandacaru_win.incident_persist, mandacaru_win.incident_cred, mandacaru_win.incident_report, "
              "mandacaru_win.incident_resposta; print('PySide6' in sys.modules)")
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}
    saida = subprocess.run([sys.executable, "-c", codigo], capture_output=True, text=True, env=env, timeout=120)
    assert saida.returncode == 0, saida.stderr
    assert saida.stdout.strip() == "False"
