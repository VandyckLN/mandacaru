"""Persistência do usuário: Run/RunOnce do HKCU, pasta Inicializar e tarefas agendadas."""
import hashlib
import json
import sys
from pathlib import Path

import pytest
from mandacaru_win.incident import IncidentError
from mandacaru_win.incident_persist import (
    CHAVE_RUN,
    CHAVE_RUNONCE,
    REG_EXPAND_SZ,
    REG_SZ,
    Entrada,
    Persistencia,
    menciona,
)

EXE = r"C:\Users\ana\AppData\Roaming\upd\svc.exe"
PROJ = r"C:\Users\ana\proj"


class RegistroFalso:
    def __init__(self, dados=None):
        self.dados = dados or {}

    def valores(self, chave):
        return [(n, v, t) for n, (v, t) in self.dados.get(chave, {}).items()]

    def apagar(self, chave, nome):
        del self.dados[chave][nome]

    def gravar(self, chave, nome, valor, tipo):
        self.dados.setdefault(chave, {})[nome] = (valor, tipo)


def _reg():
    return RegistroFalso({
        CHAVE_RUN: {
            "Atualizador": (f'"{EXE}" --silencioso', REG_SZ),
            "OneDrive": (r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background', REG_SZ),
            "Binario": (b"\x00\x01", 3),
        },
        CHAVE_RUNONCE: {"Projeto": (r"node %USERPROFILE%\proj\x.js", REG_EXPAND_SZ)},
    })


def _pers(tmp_path, reg=None):
    pasta = tmp_path / "Startup"
    pasta.mkdir(exist_ok=True)
    return Persistencia(registro=reg if reg is not None else _reg(), pasta_inicializar=pasta,
                        run=lambda args, timeout: (0, "")), pasta


@pytest.fixture(autouse=True)
def _perfil(monkeypatch):
    monkeypatch.setenv("USERPROFILE", r"C:\Users\ana")


def test_menciona_fronteira_e_variaveis():
    assert menciona(f'"{EXE}" --x', EXE)
    assert menciona(EXE.upper(), EXE)
    assert menciona(EXE.replace("\\", "/"), EXE)
    assert menciona(r"node %USERPROFILE%\proj\x.js", PROJ)
    assert menciona(PROJ, PROJ + "\\")
    assert not menciona(r"C:\Users\ana\projeto\x.js", PROJ)
    assert not menciona(EXE + ".bak", EXE)
    assert not menciona("qualquer coisa", "")


def test_detecta_so_entradas_do_incidente(tmp_path):
    p, _ = _pers(tmp_path)
    achadas = p.detectar([EXE, PROJ])
    assert [(e.tipo, e.nome) for e in achadas] == [("hkcu_run", "Atualizador"), ("hkcu_runonce", "Projeto")]
    assert achadas[0] == Entrada("hkcu_run", CHAVE_RUN, "Atualizador", f'"{EXE}" --silencioso')


def test_ignora_valor_nao_texto(tmp_path):
    p, _ = _pers(tmp_path)
    assert p.detectar(["\x00\x01"]) == []


def test_inicializar_por_mencao_lnk_e_hash(tmp_path):
    p, pasta = _pers(tmp_path, RegistroFalso())
    (pasta / "atalho.lnk").write_bytes(b"L\x00\x00\x00\x01\x14" + EXE.encode("utf-16-le") + b"\x00\x00")
    (pasta / "impar.lnk").write_bytes(b"L\x00\x00" + EXE.encode("utf-16-le"))   # texto em posição ímpar
    mal = b"MZ" + b"\x90" * 64
    (pasta / "mal.exe").write_bytes(mal)
    (pasta / "outro.bat").write_text("@echo off\nstart notepad\n")
    (pasta / "sub").mkdir()
    achadas = p.detectar([EXE], {hashlib.sha256(mal).hexdigest()})
    assert sorted(e.nome for e in achadas) == ["atalho.lnk", "impar.lnk", "mal.exe"]
    assert all(e.tipo == "startup_user" and e.local == str(pasta) and e.sha256 for e in achadas)


def test_remover_e_restaurar_run(tmp_path):
    reg = _reg()
    p, _ = _pers(tmp_path, reg)
    [e, _] = p.detectar([EXE, PROJ])
    b = p.backup(e)
    assert b == {"tipo": "hkcu_run", "chave": CHAVE_RUN, "nome": "Atualizador",
                 "valor": f'"{EXE}" --silencioso', "tipo_reg": REG_SZ}
    p.remover(b)
    assert "Atualizador" not in reg.dados[CHAVE_RUN]
    p.restaurar(json.loads(json.dumps(b)))          # passa pelo JSON do incidente
    assert reg.dados[CHAVE_RUN]["Atualizador"] == (f'"{EXE}" --silencioso', REG_SZ)


def test_remover_recusa_se_mudou(tmp_path):
    reg = _reg()
    p, _ = _pers(tmp_path, reg)
    [e, _] = p.detectar([EXE, PROJ])
    b = p.backup(e)
    reg.dados[CHAVE_RUN]["Atualizador"] = (r"C:\outro.exe", REG_SZ)
    with pytest.raises(IncidentError, match="A entrada mudou desde a detecção; nada foi removido."):
        p.remover(b)
    assert reg.dados[CHAVE_RUN]["Atualizador"] == (r"C:\outro.exe", REG_SZ)
    reg.dados[CHAVE_RUN]["Atualizador"] = (r"C:\mais_outro.exe", REG_SZ)
    with pytest.raises(IncidentError, match="mudou"):
        p.backup(e)


def test_restaurar_nao_sobrescreve(tmp_path):
    reg = _reg()
    p, _ = _pers(tmp_path, reg)
    [e, _] = p.detectar([EXE, PROJ])
    b = p.backup(e)
    p.remover(b)
    reg.dados[CHAVE_RUN]["Atualizador"] = (r"C:\novo.exe", REG_SZ)
    with pytest.raises(IncidentError, match="Já existe outra entrada com esse nome; nada foi alterado."):
        p.restaurar(b)
    assert reg.dados[CHAVE_RUN]["Atualizador"] == (r"C:\novo.exe", REG_SZ)


def test_restaurar_valor_identico_ok(tmp_path):
    reg = _reg()
    p, _ = _pers(tmp_path, reg)
    [e, _] = p.detectar([EXE, PROJ])
    b = p.backup(e)
    p.restaurar(b)                                   # nem chegou a ser removido: nada muda
    assert reg.dados[CHAVE_RUN]["Atualizador"] == (f'"{EXE}" --silencioso', REG_SZ)


def test_remover_e_restaurar_inicializar(tmp_path):
    p, pasta = _pers(tmp_path, RegistroFalso())
    conteudo = f"@echo off\nstart \"\" \"{EXE}\"\n".encode()
    (pasta / "upd.bat").write_bytes(conteudo)
    [e] = p.detectar([EXE])
    b = p.backup(e)
    texto_backup = json.dumps(b)
    assert "echo off" not in texto_backup and "svc.exe" not in texto_backup
    p.remover(b)
    assert not (pasta / "upd.bat").exists()
    p.restaurar(json.loads(texto_backup))
    assert (pasta / "upd.bat").read_bytes() == conteudo
    p.restaurar(b)                                   # já está igual: sucesso sem mexer


def test_inicializar_mudou_ou_existe(tmp_path):
    p, pasta = _pers(tmp_path, RegistroFalso())
    f = pasta / "upd.bat"
    f.write_text(EXE)
    [e] = p.detectar([EXE])
    b = p.backup(e)
    f.write_text(EXE + " --outro")
    with pytest.raises(IncidentError, match="mudou"):
        p.remover(b)
    assert f.exists()
    with pytest.raises(IncidentError, match="Já existe outra entrada com esse nome"):
        p.restaurar(b)


def test_inicializar_grande_demais(tmp_path):
    p, pasta = _pers(tmp_path, RegistroFalso())
    grande = EXE.encode() + b"\x00" * (1024 * 1024)
    (pasta / "grande.exe").write_bytes(grande)
    [e] = p.detectar([], {hashlib.sha256(grande).hexdigest()})
    with pytest.raises(IncidentError, match="Arquivo grande demais para guardar no incidente; use a Quarentena."):
        p.backup(e)


@pytest.mark.parametrize("mexer", [
    lambda b: b.update(chave=r"Software\Classes\exefile\shell\open\command"),
    lambda b: b.update(tipo="hklm_run"),
    lambda b: b.update(tipo_reg=3),
    lambda b: b.update(valor=None),
])
def test_backup_de_registro_adulterado_recusado(tmp_path, mexer):
    reg = _reg()
    p, _ = _pers(tmp_path, reg)
    [e, _] = p.detectar([EXE, PROJ])
    b = p.backup(e)
    p.remover(b)
    mexer(b)
    with pytest.raises(IncidentError):
        p.restaurar(b)
    assert "Atualizador" not in reg.dados[CHAVE_RUN]
    assert set(reg.dados) == {CHAVE_RUN, CHAVE_RUNONCE}


@pytest.mark.parametrize("mexer", [
    lambda b, pasta: b.update(nome=r"..\fora.bat"),
    lambda b, pasta: b.update(nome="a/b.bat"),
    lambda b, pasta: b.update(nome=".."),
    lambda b, pasta: b.update(pasta=str(pasta.parent)),
    lambda b, pasta: b.update(sha256="0" * 64),
    lambda b, pasta: b.update(conteudo="não é base64!"),
])
def test_backup_de_inicializar_adulterado_recusado(tmp_path, mexer):
    p, pasta = _pers(tmp_path, RegistroFalso())
    (pasta / "upd.bat").write_text(EXE)
    [e] = p.detectar([EXE])
    b = p.backup(e)
    p.remover(b)
    mexer(b, pasta)
    with pytest.raises(IncidentError):
        p.restaurar(b)
    assert not (tmp_path / "fora.bat").exists() and list(pasta.iterdir()) == []


@pytest.mark.skipif(sys.platform != "win32", reason="registro real só no Windows")
def test_registro_windows_real():
    import winreg

    from mandacaru_win.incident_persist import RegistroWindows
    chave = r"Software\MandacaruTeste\Run"
    r = RegistroWindows()
    try:
        r.gravar(chave, "teste", r"C:\x\y.exe", REG_SZ)
        assert ("teste", r"C:\x\y.exe", REG_SZ) in r.valores(chave)
        r.apagar(chave, "teste")
        assert r.valores(chave) == []
        assert r.valores(r"Software\MandacaruTeste\NaoExiste") == []
    finally:
        for k in (chave, r"Software\MandacaruTeste"):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, k)
            except OSError:
                pass


# ---------- tarefas agendadas (schtasks) ----------
XML = ('<?xml version="1.0" encoding="UTF-16"?>\n<Task><Actions><Exec><Command>' + EXE
       + "</Command></Exec></Actions></Task>")


def _linha(nome, comando, como):
    cols = [""] * 28
    cols[0], cols[1], cols[8], cols[14] = "PC-ANA", nome, comando, como
    return ",".join('"' + c.replace('"', '""') + '"' for c in cols)


class Schtasks:
    """Executor falso: responde como o schtasks.exe e grava cada chamada."""

    def __init__(self, tarefas):
        self.tarefas = dict(tarefas)        # nome -> xml
        self.csv = ""
        self.chamadas: list[list[str]] = []
        self.falhar: set[str] = set()
        self.xml_criado = None

    def __call__(self, args, timeout):
        self.chamadas.append(list(args))
        op = args[1]
        if op in self.falhar:
            return 1, "ERRO: Acesso negado."
        if op == "/Query" and "/FO" in args:
            return 0, self.csv
        nome = args[args.index("/TN") + 1]
        if op == "/Query":
            return (0, self.tarefas[nome]) if nome in self.tarefas else (1, "ERRO: tarefa não existe.")
        if op == "/Delete":
            self.tarefas.pop(nome)
            return 0, "ÊXITO"
        if op == "/Create":
            if nome in self.tarefas:
                return 1, "ERRO: já existe."
            self.xml_criado = Path(args[args.index("/XML") + 1]).read_bytes().decode("utf-16")
            self.tarefas[nome] = self.xml_criado
            return 0, "ÊXITO"
        raise AssertionError(args)


def _pers_tarefas(tmp_path, st):
    return Persistencia(registro=RegistroFalso(), pasta_inicializar=tmp_path / "nao-existe", run=st,
                        usuario="ana")


def _st():
    st = Schtasks({r"\Atualizar": XML, r"\Sistema\Coletor": XML})
    st.csv = "\n".join([
        _linha(r"\Atualizar", f'"{EXE}" /silencioso', r"PC-ANA\ana"),
        _linha(r"\Atualizar", f'"{EXE}" /silencioso', r"PC-ANA\ana"),      # segundo gatilho da mesma tarefa
        _linha(r"\Sistema\Coletor", EXE, "SYSTEM"),
        _linha(r"\Microsoft\Windows\Defrag", r"%windir%\system32\defrag.exe -c", "SYSTEM"),
    ])
    return st


def test_detecta_tarefa_do_usuario_e_do_sistema(tmp_path):
    achadas = _pers_tarefas(tmp_path, _st()).detectar([EXE])
    assert [(e.tipo, e.nome, e.exige_servico) for e in achadas] == [
        ("schtask_user", r"\Atualizar", False), ("schtask_sistema", r"\Sistema\Coletor", True)]
    assert achadas[0].comando == f'"{EXE}" /silencioso'


def test_tarefas_repetidas_por_gatilho_viram_uma(tmp_path):
    achadas = _pers_tarefas(tmp_path, _st()).detectar([EXE])
    assert [e.nome for e in achadas].count(r"\Atualizar") == 1


def test_schtasks_falhando_nao_derruba_detectar(tmp_path):
    st = _st()
    st.falhar = {"/Query"}
    assert _pers_tarefas(tmp_path, st).detectar([EXE]) == []


def test_remover_tarefa_guarda_xml_antes_de_apagar(tmp_path):
    st = _st()
    p = _pers_tarefas(tmp_path, st)
    [e, _] = p.detectar([EXE])
    b = p.backup(e)
    assert b == {"tipo": "schtask_user", "nome": r"\Atualizar", "xml": XML}
    assert not any(c[1] == "/Delete" for c in st.chamadas)
    p.remover(b)
    ops = [c[1:] for c in st.chamadas if "/TN" in c]
    assert ops[-1] == ["/Delete", "/TN", r"\Atualizar", "/F"]
    assert ops[-2] == ["/Query", "/TN", r"\Atualizar", "/XML"]    # confere de novo logo antes de apagar
    assert r"\Atualizar" not in st.tarefas


def test_remover_tarefa_que_mudou_recusa(tmp_path):
    st = _st()
    p = _pers_tarefas(tmp_path, st)
    [e, _] = p.detectar([EXE])
    b = p.backup(e)
    st.tarefas[r"\Atualizar"] = XML.replace("svc.exe", "outro.exe")
    with pytest.raises(IncidentError, match="mudou"):
        p.remover(b)
    assert r"\Atualizar" in st.tarefas


def test_remover_tarefa_do_sistema_recusa(tmp_path):
    st = _st()
    p = _pers_tarefas(tmp_path, st)
    [_, e] = p.detectar([EXE])
    with pytest.raises(IncidentError, match="Proteção avançada"):
        p.backup(e)
    assert not any(c[1] == "/Delete" for c in st.chamadas)


def test_restaurar_tarefa_cria_sem_sobrescrever(tmp_path, monkeypatch):
    import tempfile
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    st = _st()
    p = _pers_tarefas(tmp_path, st)
    [e, _] = p.detectar([EXE])
    b = p.backup(e)
    p.remover(b)
    p.restaurar(json.loads(json.dumps(b)))
    [criar] = [c for c in st.chamadas if c[1] == "/Create"]
    assert "/XML" in criar and "/F" not in criar
    assert st.xml_criado == XML and st.tarefas[r"\Atualizar"] == XML
    assert not list(tmp_path.glob("*.xml"))                       # arquivo temporário apagado
    p.restaurar(b)                                                # já existe igual: sucesso
    st.tarefas[r"\Atualizar"] = XML.replace("svc.exe", "outro.exe")
    with pytest.raises(IncidentError, match="Já existe outra entrada com esse nome"):
        p.restaurar(b)


@pytest.mark.parametrize("nome", ["Atualizar", '\\a" /F /TN "\\b', "\\a\nb", "\\" + "a" * 260, "", None])
def test_nome_de_tarefa_invalido(tmp_path, nome):
    st = _st()
    p = _pers_tarefas(tmp_path, st)
    with pytest.raises(IncidentError):
        p.restaurar({"tipo": "schtask_user", "nome": nome, "xml": XML})
    with pytest.raises(IncidentError):
        p.remover({"tipo": "schtask_user", "nome": nome, "xml": XML})
    assert not any(c[1] in ("/Create", "/Delete") for c in st.chamadas)


def test_schtasks_falha_vira_erro(tmp_path):
    st = _st()
    p = _pers_tarefas(tmp_path, st)
    [e, _] = p.detectar([EXE])
    b = p.backup(e)
    st.falhar = {"/Delete"}
    with pytest.raises(IncidentError, match="Acesso negado"):
        p.remover(b)
