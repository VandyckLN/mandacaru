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


def test_sha_para_encerrar_usa_o_achado_e_nunca_o_disco_trocado(tmp_path):
    store, inc = _inc(tmp_path)                                  # achado: EXE com SHA "a"*64
    disco = {EXE: "b" * 64, r"C:\Users\ana\proj\tool.exe": "c" * 64, r"C:\Users\ana\proj\x.exe": None}
    r = Resposta(store, inc, processos=None, persistencia=PersistenciaEspia(),
                 hash_fn=lambda p: {k.lower(): v for k, v in disco.items()}[str(p).lower()])   # NTFS ignora a caixa
    sha, motivo = r.sha_para_encerrar(ProcessoInfo(100, 1, EXE, 1.0))
    assert sha is None and "mudou desde a detecção" in motivo     # trocado no disco: não confirma
    disco[EXE] = SHA
    assert r.sha_para_encerrar(ProcessoInfo(100, 1, EXE.upper(), 1.0)) == (SHA, None)
    assert r.sha_para_encerrar(ProcessoInfo(101, 1, r"C:\Users\ana\proj\tool.exe", 1.0)) == ("c" * 64, None)
    sha, motivo = r.sha_para_encerrar(ProcessoInfo(102, 1, r"C:\Users\ana\proj\x.exe", 1.0))
    assert sha is None and "ler o executável" in motivo
    assert r.sha_para_encerrar(ProcessoInfo(103, 1, None, 1.0))[0] is None


# ---------- Proteção avançada (Guard) ----------
class GuardFalso:
    def __init__(self, respostas=None, ativo=True):
        self.respostas = respostas or {}
        self.ativo = ativo
        self.pedidos: list[tuple[str, dict]] = []

    def disponivel(self):
        return self.ativo

    def chamar(self, acao, **params):
        from mandacaru_win.guard_protocol import GuardError, validar_pedido
        validar_pedido({"acao": acao, **params})               # o mesmo esquema do serviço real
        self.pedidos.append((acao, params))
        resp = self.respostas.get(acao, {"ok": True})
        if isinstance(resp, Exception):
            raise resp
        if not resp.get("ok"):
            raise GuardError(resp["erro"])
        return resp


def _resp_guard(tmp_path, guard, **kw):
    from mandacaru_win.quarantine import Quarantine
    store, inc = _inc(tmp_path)
    q = Quarantine(tmp_path / "quarentena")
    return store, inc, Resposta(store, inc, processos=kw.get("processos"), persistencia=PersistenciaEspia(),
                                guard=guard, quarentena=q, hash_fn=kw.get("hash_fn", lambda p: SHA)), q


@pytest.mark.parametrize("entrada,pedido", [
    (Entrada("hklm_run", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Upd", f'"{EXE}"', exige_servico=True),
     {"tipo": "hklm_run", "nome": "Upd", "valor": f'"{EXE}"'}),
    (Entrada("startup_all", r"C:\ProgramData\x\StartUp", "upd.lnk", r"C:\ProgramData\x\StartUp\upd.lnk", "b" * 64,
             exige_servico=True), {"tipo": "startup_all", "nome": "upd.lnk", "valor": "b" * 64}),
    (Entrada("service", "Serviços do Windows", "MalSvc", f'"{EXE}"', exige_servico=True),
     {"tipo": "service", "nome": "MalSvc", "valor": ""}),
    (Entrada("schtask_sistema", "Agendador de Tarefas", r"\Mal", EXE, exige_servico=True),
     {"tipo": "schtask", "nome": r"\Mal", "valor": ""}),
])
def test_persistencia_do_sistema_vai_pelo_guard_e_desfaz(tmp_path, entrada, pedido):
    g = GuardFalso({"persistence_remove": {"ok": True, "id": "f" * 32}})
    store, inc, r, _q = _resp_guard(tmp_path, g)
    a = r.remover_persistencia(entrada)
    assert a.resultado == "concluida" and g.pedidos == [("persistence_remove", pedido)]
    assert a.backup == {"guard": "persistencia", "id": "f" * 32}
    d = r.desfazer(0)
    assert d.resultado == "concluida" and g.pedidos[-1] == ("persistence_restore", {"id": "f" * 32})
    assert store.carregar(inc.id).acoes[0].desfeita is True


def test_sem_guard_entrada_do_sistema_falha_registrada(tmp_path):
    e = Entrada("service", "Serviços do Windows", "MalSvc", EXE, exige_servico=True)
    for guard in (None, GuardFalso(ativo=False)):
        store, inc, r, _q = _resp_guard(tmp_path / str(id(guard)), guard)
        a = r.remover_persistencia(e)
        assert a.resultado == "falhou" and "Requer Proteção avançada" in a.detalhe
        assert store.carregar(inc.id).acoes[0].resultado == "falhou"
        assert not r.guard_disponivel()


def test_erro_do_guard_vira_falha_com_motivo(tmp_path):
    from mandacaru_win.guard_protocol import GuardError
    g = GuardFalso({"persistence_remove": GuardError("Serviço do Windows: o serviço não o desativa.")})
    _s, _i, r, _q = _resp_guard(tmp_path, g)
    a = r.remover_persistencia(Entrada("service", "Serviços do Windows", "Dhcp", EXE, exige_servico=True))
    assert a.resultado == "falhou" and a.detalhe == "Serviço do Windows: o serviço não o desativa."


def test_bloquear_rede_e_desfazer(tmp_path):
    g = GuardFalso()
    store, inc, r, _q = _resp_guard(tmp_path, g)
    a = r.bloquear_rede(EXE)
    acao, params = g.pedidos[0]
    assert acao == "firewall_block" and params["exe"] == EXE and params["regra"].startswith("Mandacaru-")
    assert a.tipo == "bloquear_rede" and a.fase == "conter" and a.resultado == "concluida"
    assert a.backup == {"guard": "firewall", "regra": params["regra"]}
    assert r.desfazer(0).resultado == "concluida"
    assert g.pedidos[-1] == ("firewall_unblock", {"regra": params["regra"]})
    _s, _i, r2, _q2 = _resp_guard(tmp_path / "sem", None)
    assert "Requer Proteção avançada" in r2.bloquear_rede(EXE).detalhe


def test_quarentenar_local_e_desfazer(tmp_path):
    f = tmp_path / "mal.ps1"
    f.write_bytes(b"abc")
    sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    g = GuardFalso()
    store, inc, r, q = _resp_guard(tmp_path, g)
    a = r.quarentenar(f, sha, "HIGH", ["regra.x"])
    assert a.resultado == "concluida" and not f.exists() and len(q.items()) == 1
    assert a.backup["local"] == "quarentena" and g.pedidos == []
    assert r.desfazer(0).resultado == "concluida" and f.read_bytes() == b"abc" and q.items() == []


def test_quarentenar_cai_no_guard_quando_a_local_falha(tmp_path):
    g = GuardFalso({"quarantine_file": {"ok": True, "id": "e" * 32}})
    _s, _i, r, _q = _resp_guard(tmp_path, g)
    a = r.quarentenar(r"C:\Program Files\Mal\mal.exe", SHA, "CRITICAL", ["hash.malicioso"])
    assert a.resultado == "concluida" and a.backup == {"guard": "quarentena", "id": "e" * 32}
    assert g.pedidos == [("quarantine_file", {"caminho": r"C:\Program Files\Mal\mal.exe", "sha256": SHA})]
    assert r.desfazer(0).resultado == "concluida" and g.pedidos[-1] == ("quarantine_restore", {"id": "e" * 32})


def test_quarentenar_sem_guard_mostra_erro_local(tmp_path):
    _s, _i, r, _q = _resp_guard(tmp_path, None)
    a = r.quarentenar(tmp_path / "nao-existe.exe", SHA, "HIGH", [])
    assert a.resultado == "falhou" and "não existe" in a.detalhe


def test_encerrar_recorre_ao_guard_quando_acesso_negado(tmp_path):
    class Negado(ProcessosFalsos):
        def encerrar(self, pid, criado):
            raise PermissionError(5, "Acesso negado")
    g = GuardFalso({"terminate_process": {"ok": True, "encerrados": [100], "falhas": []}})
    _s, _i, r, _q = _resp_guard(tmp_path, g, processos=Negado())
    a = r.encerrar_processo(100, EXE, SHA)
    assert a.resultado == "concluida" and a.alvo["encerrados"] == [100]
    assert g.pedidos == [("terminate_process", {"pid": 100, "exe": EXE, "sha256": SHA})]
    assert "Proteção avançada" in a.detalhe


def test_desfazer_pelo_guard_sem_guard_falha(tmp_path):
    g = GuardFalso({"persistence_remove": {"ok": True, "id": "f" * 32}})
    store, inc, r, _q = _resp_guard(tmp_path, g)
    r.remover_persistencia(Entrada("service", "Serviços do Windows", "MalSvc", EXE, exige_servico=True))
    g.ativo = False
    d = r.desfazer(0)
    assert d.resultado == "falhou" and "Proteção avançada" in d.detalhe
    assert store.carregar(inc.id).acoes[0].desfeita is False


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
