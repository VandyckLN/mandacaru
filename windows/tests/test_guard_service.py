"""Serviço MandacaruGuard: política de caminhos, ações privilegiadas e despachante (com falsos)."""
import hashlib
import json
import logging
import sys

import pytest
from mandacaru_win.guard_protocol import codificar, decodificar
from mandacaru_win.guard_service import (
    CHAVE_RUN_HKLM,
    CHAVE_RUNONCE_HKLM,
    AcoesGuard,
    Ambiente,
    Despachante,
    proibido,
)
from mandacaru_win.incident_proc import ProcessoInfo

AMB = Ambiente(system_root=r"C:\Windows", program_files=(r"C:\Program Files", r"C:\Program Files (x86)"),
               program_data=r"C:\ProgramData", pasta_guard=r"C:\Program Files\Mandacaru Guard")
MAL = r"C:\Users\ana\Downloads\mal.exe"
CONTEUDO = b"MZ" + b"\x90" * 100
SHA = hashlib.sha256(CONTEUDO).hexdigest()
INICIALIZAR = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"


# ---------- falsos ----------
class Aberto:
    def __init__(self, fs, final, novo=False):
        self.fs, self.caminho_final, self.novo, self.buf = fs, final, novo, bytearray()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.fechar()

    def ler(self):
        dados = self.fs.disco[self.caminho_final.lower()]
        for i in range(0, len(dados), 7):
            yield dados[i:i + 7]

    def escrever(self, b):
        self.buf += b
        self.fs.disco[self.caminho_final.lower()] = bytes(self.buf)

    def apagar(self):
        if self.fs.falhar_apagar:
            raise PermissionError("em uso")
        self.fs.disco.pop(self.caminho_final.lower(), None)
        self.fs.apagados.append(self.caminho_final)

    def fechar(self):
        pass


class ArquivosFalsos:
    """`finais` simula link/junção: abrir(A) aponta para o arquivo B."""

    def __init__(self, disco=None, finais=None):
        self.disco = {k.lower(): v for k, v in (disco or {}).items()}
        self.finais = {k.lower(): v for k, v in (finais or {}).items()}
        self.apagados: list[str] = []
        self.falhar_apagar = False

    def _final(self, caminho):
        return self.finais.get(caminho.lower(), caminho)

    def abrir(self, caminho):
        final = self._final(caminho)
        if final.lower() not in self.disco:
            raise FileNotFoundError(caminho)
        return Aberto(self, final)

    def criar_novo(self, caminho):
        final = self._final(caminho)
        if final.lower() in self.disco:
            raise FileExistsError(caminho)
        self.disco[final.lower()] = b""
        return Aberto(self, final, novo=True)


class RegistroFalso:
    def __init__(self, dados=None):
        self.dados = dados or {}

    def valores(self, chave):
        return [(n, v, t) for n, (v, t) in self.dados.get(chave, {}).items()]

    def apagar(self, chave, nome):
        del self.dados[chave][nome]

    def gravar(self, chave, nome, valor, tipo):
        self.dados.setdefault(chave, {})[nome] = (valor, tipo)


class Comandos:
    def __init__(self):
        self.chamadas: list[list[str]] = []
        self.respostas: dict[str, tuple[int, str]] = {}
        self.tarefas = {r"\Atualizador": "<Task>mal</Task>"}

    def __call__(self, args, timeout):
        self.chamadas.append(list(args))
        texto = " ".join(args[1:])
        for chave, resp in self.respostas.items():
            if chave in texto:
                return resp
        if "show rule" in texto:
            return 1, "Nenhuma regra corresponde."
        if args[1:3] == ["/Query", "/TN"]:
            nome = args[3]
            return (0, self.tarefas[nome]) if nome in self.tarefas else (1, "ERRO")
        if args[1:3] == ["/Delete", "/TN"]:
            self.tarefas.pop(args[3])
        if args[1:3] == ["/Create", "/TN"]:
            if args[3] in self.tarefas:
                return 1, "ERRO: já existe"
            from pathlib import Path
            self.tarefas[args[3]] = Path(args[5]).read_bytes().decode("utf-16")
        return 0, "Ok."


class ProcessosFalsos:
    def __init__(self):
        self.vivos = {100: ProcessoInfo(100, 1, MAL, 10.0),
                      200: ProcessoInfo(200, 1, r"C:\Windows\System32\svchost.exe", 1.0)}

    def listar(self):
        return list(self.vivos.values())

    def info(self, pid):
        return self.vivos.get(pid)

    def encerrar(self, pid, criado):
        self.vivos.pop(pid)


def _acoes(tmp_path, *, disco=None, finais=None, registro=None):
    arq = ArquivosFalsos({MAL: CONTEUDO, **(disco or {})}, finais)
    cmd = Comandos()
    procs = ProcessosFalsos()
    a = AcoesGuard(AMB, processos=procs, arquivos=arq, registro=registro or RegistroFalso(), run=cmd,
                   pasta_dados=tmp_path / "guard", pasta_inicializar_global=INICIALIZAR,
                   hash_fn=lambda p: SHA if str(p) == MAL else hashlib.sha256(b"svchost").hexdigest())
    return a, arq, cmd, procs


# ---------- política ----------
@pytest.mark.parametrize("caminho,esperado", [
    (r"C:\Windows\System32\svchost.exe", True),
    (r"c:\windows\system32\drivers\etc\hosts", True),
    (r"C:\Program Files\Windows Defender\MsMpEng.exe", True),
    (r"C:\Program Files (x86)\Windows Defender\x.exe", True),
    (r"C:\Program Files\WindowsApps\app\x.exe", True),
    (r"C:\ProgramData\Microsoft\Windows Defender\Platform\x.exe", True),
    (r"C:\Program Files\Mandacaru Guard\guard.exe", True),
    (r"C:\Windows", True),
    (r"C:\WindowsOld\x.exe", False),
    (r"C:\Program Files\Mal\mal.exe", False),
    (MAL, False),
])
def test_proibido(caminho, esperado):
    assert proibido(caminho, AMB) is esperado


# ---------- processos ----------
def test_encerra_processo_conferido(tmp_path):
    a, _arq, _cmd, procs = _acoes(tmp_path)
    r = a.terminate_process(pid=100, exe=MAL, sha256=SHA)
    assert r == {"ok": True, "encerrados": [100], "falhas": []}
    assert 100 not in procs.vivos


def test_nao_encerra_programa_do_sistema_mesmo_com_sha_certo(tmp_path):
    a, _arq, _cmd, procs = _acoes(tmp_path)
    r = a.terminate_process(pid=200, exe=r"C:\Windows\System32\svchost.exe",
                            sha256=hashlib.sha256(b"svchost").hexdigest())
    assert r["ok"] is False and "sistema" in r["erro"]
    assert 200 in procs.vivos


def test_encerrar_pid_reaproveitado_recusa(tmp_path):
    a, _arq, _cmd, procs = _acoes(tmp_path)
    r = a.terminate_process(pid=100, exe=r"C:\Users\ana\outro.exe", sha256=SHA)
    assert r["ok"] is False and 100 in procs.vivos


# ---------- quarentena ----------
def test_quarentena_e_restauracao(tmp_path):
    a, arq, _cmd, _p = _acoes(tmp_path)
    r = a.quarantine_file(caminho=MAL, sha256=SHA)
    assert r["ok"] is True and len(r["id"]) == 32
    assert MAL.lower() not in arq.disco and arq.apagados == [MAL]
    binario = (tmp_path / "guard" / "quarentena" / f"{r['id']}.bin").read_bytes()
    assert CONTEUDO not in binario                                  # guardado embaralhado
    meta = json.loads((tmp_path / "guard" / "quarentena" / f"{r['id']}.json").read_text(encoding="utf-8"))
    assert meta["caminho_original"] == MAL and meta["sha256"] == SHA
    d = a.quarantine_restore(id=r["id"])
    assert d == {"ok": True, "caminho": MAL}
    assert arq.disco[MAL.lower()] == CONTEUDO
    assert list((tmp_path / "guard" / "quarentena").iterdir()) == []


def test_quarentena_recusa_juncao_trocada(tmp_path):
    # C:\Users\ana\Downloads virou junção para C:\Windows\System32: o handle aponta para lá.
    alvo = r"C:\Windows\System32\kernel32.dll"
    a, arq, _cmd, _p = _acoes(tmp_path, disco={alvo: CONTEUDO}, finais={MAL: alvo})
    r = a.quarantine_file(caminho=MAL, sha256=SHA)
    assert r["ok"] is False and "link" in r["erro"]
    assert arq.disco[alvo.lower()] == CONTEUDO and arq.apagados == []


def test_quarentena_recusa_caminho_proibido(tmp_path):
    alvo = r"C:\Windows\System32\mal.dll"
    a, arq, _cmd, _p = _acoes(tmp_path, disco={alvo: CONTEUDO})
    r = a.quarantine_file(caminho=alvo, sha256=SHA)
    assert r["ok"] is False and arq.apagados == []


def test_quarentena_recusa_sha_diferente_e_nao_deixa_resto(tmp_path):
    a, arq, _cmd, _p = _acoes(tmp_path)
    r = a.quarantine_file(caminho=MAL, sha256="b" * 64)
    assert r == {"ok": False, "erro": "O arquivo mudou desde a detecção; nada foi movido."}
    assert MAL.lower() in arq.disco
    pasta = tmp_path / "guard" / "quarentena"
    assert not pasta.exists() or list(pasta.iterdir()) == []


def test_quarentena_arquivo_em_uso(tmp_path):
    a, arq, _cmd, _p = _acoes(tmp_path)
    arq.falhar_apagar = True
    r = a.quarantine_file(caminho=MAL, sha256=SHA)
    assert r["ok"] is False and "em uso" in r["erro"]
    assert list((tmp_path / "guard" / "quarentena").iterdir()) == []


def test_restaurar_recusa_se_caminho_agora_e_juncao(tmp_path):
    a, arq, _cmd, _p = _acoes(tmp_path)
    qid = a.quarantine_file(caminho=MAL, sha256=SHA)["id"]
    arq.finais[MAL.lower()] = r"C:\Windows\System32\mal.exe"           # pasta trocada por junção
    r = a.quarantine_restore(id=qid)
    assert r["ok"] is False and "link" in r["erro"]
    assert r"c:\windows\system32\mal.exe" not in arq.disco
    assert (tmp_path / "guard" / "quarentena" / f"{qid}.bin").exists()   # nada se perde


def test_restaurar_nao_sobrescreve_e_recusa_id_desconhecido(tmp_path):
    a, arq, _cmd, _p = _acoes(tmp_path)
    qid = a.quarantine_file(caminho=MAL, sha256=SHA)["id"]
    arq.disco[MAL.lower()] = b"outro"
    assert a.quarantine_restore(id=qid)["ok"] is False and arq.disco[MAL.lower()] == b"outro"
    assert a.quarantine_restore(id="0" * 32)["ok"] is False


# ---------- firewall ----------
def test_bloquear_e_desbloquear(tmp_path):
    a, _arq, cmd, _p = _acoes(tmp_path)
    assert a.firewall_block(regra="Mandacaru-0123abcd", exe=MAL) == {"ok": True, "regra": "Mandacaru-0123abcd"}
    add = cmd.chamadas[-1]
    assert add[1:] == ["advfirewall", "firewall", "add", "rule", "name=Mandacaru-0123abcd", "dir=out",
                       "action=block", f"program={MAL}", "enable=yes"]
    assert add[0].lower().endswith(r"system32\netsh.exe")
    assert a.firewall_unblock(regra="Mandacaru-0123abcd")["ok"] is True
    assert cmd.chamadas[-1][1:] == ["advfirewall", "firewall", "delete", "rule", "name=Mandacaru-0123abcd"]


def test_bloquear_regra_duplicada_ou_exe_do_sistema(tmp_path):
    svchost = r"C:\Windows\System32\svchost.exe"
    a, _arq, cmd, _p = _acoes(tmp_path, disco={svchost: b"x"})
    assert a.firewall_block(regra="Mandacaru-0123abcd", exe=svchost)["ok"] is False
    cmd.respostas["show rule name=Mandacaru-0123abcd"] = (0, "Nome da regra: Mandacaru-0123abcd")
    assert a.firewall_block(regra="Mandacaru-0123abcd", exe=MAL)["ok"] is False
    assert not any("add" in c for c in cmd.chamadas)


def test_bloquear_exe_inexistente_ou_por_juncao(tmp_path):
    a, _arq, cmd, _p = _acoes(tmp_path, finais={MAL: r"C:\Users\ana\outro.exe"},
                              disco={r"C:\Users\ana\outro.exe": b"x"})
    assert a.firewall_block(regra="Mandacaru-0123abcd", exe=MAL)["ok"] is False
    assert a.firewall_block(regra="Mandacaru-0123abcd", exe=r"C:\nao\existe.exe")["ok"] is False
    assert not any("add" in c for c in cmd.chamadas)


def test_netsh_falhando_vira_erro(tmp_path):
    a, _arq, cmd, _p = _acoes(tmp_path)
    cmd.respostas["add rule"] = (1, "Acesso negado.")
    assert a.firewall_block(regra="Mandacaru-0123abcd", exe=MAL) == {
        "ok": False, "erro": "O Firewall do Windows recusou a regra: Acesso negado."}


def test_remover_todas_as_regras_usa_prefixo(tmp_path):
    a, _arq, cmd, _p = _acoes(tmp_path)
    assert a.remover_todas_regras()["ok"] is True
    assert "Mandacaru-*" in cmd.chamadas[-1][-1]


# ---------- persistência ----------
def test_hklm_run_remover_e_restaurar_pelo_id(tmp_path):
    reg = RegistroFalso({CHAVE_RUN_HKLM: {"Upd": (f'"{MAL}" /s', 1)}})
    a, _arq, _cmd, _p = _acoes(tmp_path, registro=reg)
    r = a.persistence_remove(tipo="hklm_run", nome="Upd", valor=f'"{MAL}" /s')
    assert r["ok"] is True and len(r["id"]) == 32 and "Upd" not in reg.dados[CHAVE_RUN_HKLM]
    assert "valor" not in r                                          # o backup não sai do serviço
    assert a.persistence_restore(id=r["id"]) == {"ok": True}
    assert reg.dados[CHAVE_RUN_HKLM]["Upd"] == (f'"{MAL}" /s', 1)
    assert a.persistence_restore(id=r["id"])["ok"] is False           # backup já usado


def test_hklm_runonce_mudou_recusa(tmp_path):
    reg = RegistroFalso({CHAVE_RUNONCE_HKLM: {"Upd": ("outro.exe", 1)}})
    a, _arq, _cmd, _p = _acoes(tmp_path, registro=reg)
    r = a.persistence_remove(tipo="hklm_runonce", nome="Upd", valor=MAL)
    assert r["ok"] is False and reg.dados[CHAVE_RUNONCE_HKLM]["Upd"] == ("outro.exe", 1)


def test_restaurar_hklm_nao_sobrescreve(tmp_path):
    reg = RegistroFalso({CHAVE_RUN_HKLM: {"Upd": (MAL, 1)}})
    a, _arq, _cmd, _p = _acoes(tmp_path, registro=reg)
    bid = a.persistence_remove(tipo="hklm_run", nome="Upd", valor=MAL)["id"]
    reg.dados[CHAVE_RUN_HKLM]["Upd"] = ("legitimo.exe", 1)
    assert a.persistence_restore(id=bid)["ok"] is False
    assert reg.dados[CHAVE_RUN_HKLM]["Upd"] == ("legitimo.exe", 1)


def test_inicializar_global(tmp_path):
    f = INICIALIZAR + r"\upd.lnk"
    a, arq, _cmd, _p = _acoes(tmp_path, disco={f: CONTEUDO})
    r = a.persistence_remove(tipo="startup_all", nome="upd.lnk", valor=SHA)
    assert r["ok"] is True and f.lower() not in arq.disco
    assert a.persistence_restore(id=r["id"]) == {"ok": True}
    assert arq.disco[f.lower()] == CONTEUDO
    assert a.persistence_remove(tipo="startup_all", nome="upd.lnk", valor="b" * 64)["ok"] is False


def test_tarefa_do_sistema_remover_e_restaurar(tmp_path, monkeypatch):
    a, _arq, cmd, _p = _acoes(tmp_path)
    r = a.persistence_remove(tipo="schtask", nome=r"\Atualizador", valor="")
    assert r["ok"] is True and r"\Atualizador" not in cmd.tarefas
    ops = [c[1] for c in cmd.chamadas]
    assert ops.index("/Query") < ops.index("/Delete")
    assert a.persistence_restore(id=r["id"]) == {"ok": True}
    assert cmd.tarefas[r"\Atualizador"] == "<Task>mal</Task>"
    criar = next(c for c in cmd.chamadas if c[1] == "/Create")
    assert "/F" not in criar
    assert not list((tmp_path / "guard").rglob("*.xml"))


def test_tarefa_do_windows_recusa(tmp_path):
    a, _arq, cmd, _p = _acoes(tmp_path)
    r = a.persistence_remove(tipo="schtask", nome=r"\Microsoft\Windows\Defrag\ScheduledDefrag", valor="")
    assert r["ok"] is False and not any(c[1] == "/Delete" for c in cmd.chamadas)


def _servico(reg, nome, imagem, tipo=0x10, start=2):
    reg.gravar(rf"SYSTEM\CurrentControlSet\Services\{nome}", "ImagePath", imagem, 2)
    reg.dados[rf"SYSTEM\CurrentControlSet\Services\{nome}"]["Type"] = (tipo, 4)
    reg.dados[rf"SYSTEM\CurrentControlSet\Services\{nome}"]["Start"] = (start, 4)


def test_servico_desativar_e_restaurar(tmp_path):
    reg = RegistroFalso()
    _servico(reg, "MalSvc", r'"C:\Program Files\Mal\svc.exe" -k')
    a, _arq, cmd, _p = _acoes(tmp_path, registro=reg)
    r = a.persistence_remove(tipo="service", nome="MalSvc", valor="")
    assert r["ok"] is True
    sc = [c[1:] for c in cmd.chamadas if c[0].lower().endswith("sc.exe")]
    assert sc[0] == ["config", "MalSvc", "start=", "disabled"] and sc[1] == ["stop", "MalSvc"]
    assert a.persistence_restore(id=r["id"]) == {"ok": True}
    assert [c[1:] for c in cmd.chamadas if c[0].lower().endswith("sc.exe")][-1] == [
        "config", "MalSvc", "start=", "auto"]


@pytest.mark.parametrize("imagem,tipo", [
    (r"C:\Windows\System32\svchost.exe -k netsvcs", 0x20),
    (r"%SystemRoot%\System32\svchost.exe -k x", 0x20),
    (r"\SystemRoot\System32\drivers\mal.sys", 0x10),
    (r"C:\Users\ana\mal.sys", 0x1),                                    # driver de kernel
])
def test_servico_do_windows_ou_driver_recusa(tmp_path, imagem, tipo):
    reg = RegistroFalso()
    _servico(reg, "Svc", imagem, tipo=tipo)
    a, _arq, cmd, _p = _acoes(tmp_path, registro=reg)
    assert a.persistence_remove(tipo="service", nome="Svc", valor="")["ok"] is False
    assert not any(c[0].lower().endswith("sc.exe") for c in cmd.chamadas)


def test_servico_inexistente_e_sc_falhando(tmp_path):
    reg = RegistroFalso()
    _servico(reg, "MalSvc", r"C:\Mal\svc.exe")
    a, _arq, cmd, _p = _acoes(tmp_path, registro=reg)
    assert a.persistence_remove(tipo="service", nome="Nada", valor="")["ok"] is False
    cmd.respostas["config MalSvc"] = (5, "[SC] OpenService FALHA 5: Acesso negado.")
    r = a.persistence_remove(tipo="service", nome="MalSvc", valor="")
    assert r["ok"] is False and not any(c[1:2] == ["stop"] for c in cmd.chamadas)


def test_backup_adulterado_na_pasta_do_servico_recusa(tmp_path):
    reg = RegistroFalso({CHAVE_RUN_HKLM: {"Upd": (MAL, 1)}})
    a, _arq, _cmd, _p = _acoes(tmp_path, registro=reg)
    bid = a.persistence_remove(tipo="hklm_run", nome="Upd", valor=MAL)["id"]
    arq = tmp_path / "guard" / "backups" / f"{bid}.json"
    d = json.loads(arq.read_text(encoding="utf-8"))
    d["chave"] = r"SOFTWARE\Classes\exefile\shell\open\command"
    arq.write_text(json.dumps(d), encoding="utf-8")
    assert a.persistence_restore(id=bid)["ok"] is False
    assert set(reg.dados) == {CHAVE_RUN_HKLM}


# ---------- despachante ----------
def test_despachante_ida_e_volta_e_log(tmp_path, caplog):
    a, _arq, _cmd, _p = _acoes(tmp_path)
    d = Despachante(a)
    with caplog.at_level(logging.INFO, logger="mandacaru.guard"):
        r = decodificar(d.tratar(codificar({"acao": "ping"}), cliente_pid=4321))
        decodificar(d.tratar(codificar({"acao": "quarantine_file", "caminho": MAL, "sha256": SHA}), 4321))
    assert r["ok"] is True and r["servico"] == "MandacaruGuard"
    assert "cliente=4321" in caplog.text and "quarantine_file" in caplog.text
    assert "\\x90" not in caplog.text and "MZ" not in caplog.text


@pytest.mark.parametrize("linha", [
    b"{nao json\n",
    b'{"acao": "rodar", "cmd": "whoami"}\n',
    b'{"acao": "terminate_process", "pid": true, "exe": "C:\\\\x.exe", "sha256": "' + b"a" * 64 + b'"}\n',
    b"x" * 70000,
])
def test_despachante_recusa_sem_excecao(tmp_path, linha):
    a, _arq, cmd, procs = _acoes(tmp_path)
    r = decodificar(Despachante(a).tratar(linha, cliente_pid=1))
    assert r["ok"] is False and r["erro"]
    assert cmd.chamadas == [] and 100 in procs.vivos


def test_despachante_erro_interno_vira_resposta(tmp_path):
    a, _arq, _cmd, _p = _acoes(tmp_path)

    def explode(**_k):
        raise RuntimeError("bug")
    a.ping = explode
    r = decodificar(Despachante(a).tratar(codificar({"acao": "ping"}), cliente_pid=1))
    assert r == {"ok": False, "erro": "Erro interno do serviço."}


# ---------- configuração e cliente autorizado ----------
def test_pasta_protegida():
    from mandacaru_win.guard_service import pasta_protegida
    assert pasta_protegida(r"C:\Program Files\Mandacaru Guard", AMB) is True
    assert pasta_protegida(r"c:\program files (x86)\Mandacaru Guard", AMB) is True
    assert pasta_protegida(r"C:\Users\ana\AppData\Local\Programs\Mandacaru", AMB) is False
    assert pasta_protegida(r"C:\Program FilesX\Guard", AMB) is False


def test_carregar_config(tmp_path):
    from mandacaru_win.guard_service import carregar_config
    assert carregar_config(tmp_path) == []                                   # sem guard.json: ninguém
    (tmp_path / "guard.json").write_text("{quebrado", encoding="utf-8")
    assert carregar_config(tmp_path) == []
    (tmp_path / "guard.json").write_text(json.dumps({"clientes": [
        r"C:\Users\ana\AppData\Local\Programs\Mandacaru\Mandacaru.exe", "relativo.exe", 3]}), encoding="utf-8")
    assert carregar_config(tmp_path) == [r"C:\Users\ana\AppData\Local\Programs\Mandacaru\Mandacaru.exe"]


def test_verificador_de_clientes():
    from mandacaru_win.guard_service import verificador_de_clientes
    app = r"C:\Users\ana\AppData\Local\Programs\Mandacaru\Mandacaru.exe"
    exes = {10: app.upper(), 20: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", 30: None}
    ok = verificador_de_clientes([app], exe_do_pid=exes.get)
    assert ok(10) is True and ok(20) is False and ok(30) is False and ok(99) is False
    assert verificador_de_clientes([], exe_do_pid=exes.get)(10) is False


def test_main_sem_argumento_valido():
    from mandacaru_win.guard_service import main
    assert main([]) == 2 and main(["apagar-tudo"]) == 2


# ---------- Windows real ----------
windows = pytest.mark.skipif(sys.platform != "win32", reason="só no Windows")


@windows
def test_arquivos_windows_caminho_final_e_apagar_por_handle(tmp_path):
    import os

    from mandacaru_win.guard_service import ArquivosWindows
    base = os.path.realpath(tmp_path)                       # nomes longos (sem RUNNER~1)
    f = os.path.join(base, "a.bin")
    with open(f, "wb") as fh:
        fh.write(CONTEUDO)
    arq = ArquivosWindows()
    with arq.abrir(f) as h:
        assert h.caminho_final.lower() == f.lower()
        assert b"".join(h.ler()) == CONTEUDO
        h.apagar()
    assert not os.path.exists(f)
    with pytest.raises(FileNotFoundError):
        arq.abrir(f)
    with arq.criar_novo(f) as h:
        h.escrever(b"novo")
    with open(f, "rb") as fh:
        assert fh.read() == b"novo"
    with pytest.raises(FileExistsError):
        arq.criar_novo(f)


@windows
def test_arquivos_windows_juncao_mostra_o_destino(tmp_path):
    import _winapi
    import os

    from mandacaru_win.guard_service import ArquivosWindows
    base = os.path.realpath(tmp_path)
    real = os.path.join(base, "real")
    os.mkdir(real)
    with open(os.path.join(real, "x.bin"), "wb") as fh:
        fh.write(b"x")
    juncao = os.path.join(base, "juncao")
    _winapi.CreateJunction(real, juncao)
    with ArquivosWindows().abrir(os.path.join(juncao, "x.bin")) as h:
        assert h.caminho_final.lower() == os.path.join(real, "x.bin").lower()


@windows
def test_exe_do_pid_windows():
    import os

    from mandacaru_win.guard_service import exe_do_pid
    assert os.path.normcase(exe_do_pid(os.getpid())) == os.path.normcase(os.path.realpath(sys.executable))
    assert exe_do_pid(0) is None


def _servidor(tmp_path, verificar):
    import threading
    import uuid as _uuid

    from mandacaru_win.guard_service import ServidorPipe
    a, _arq, _cmd, _p = _acoes(tmp_path)
    nome = rf"\\.\pipe\MandacaruGuardTeste-{_uuid.uuid4().hex}"
    srv = ServidorPipe(nome, Despachante(a), verificar)
    t = threading.Thread(target=srv.servir, daemon=True)
    t.start()
    return srv, t, nome


def _pedir(nome, linha):
    import time
    for _ in range(100):
        try:
            with open(nome, "r+b", buffering=0) as p:
                p.write(linha)
                resp = b""
                while not resp.endswith(b"\n"):
                    bloco = p.read(4096)
                    if not bloco:
                        break
                    resp += bloco
                return resp
        except FileNotFoundError:
            time.sleep(0.05)
    raise AssertionError("pipe não apareceu")


@windows
def test_pipe_ida_e_volta(tmp_path):
    import os
    srv, t, nome = _servidor(tmp_path, lambda pid: pid == os.getpid())
    try:
        r = decodificar(_pedir(nome, codificar({"acao": "ping"})))
        assert r["ok"] is True and r["servico"] == "MandacaruGuard"
        r = decodificar(_pedir(nome, b'{"acao": "rodar"}\n'))
        assert r["ok"] is False
    finally:
        srv.parar()
        t.join(10)
    assert not t.is_alive()


@windows
def test_pipe_recusa_cliente_nao_autorizado(tmp_path):
    srv, t, nome = _servidor(tmp_path, lambda pid: False)
    try:
        r = decodificar(_pedir(nome, codificar({"acao": "ping"})))
        assert r == {"ok": False, "erro": "Cliente não autorizado."}
    finally:
        srv.parar()
        t.join(10)


@windows
def test_pipe_segundo_servidor_com_mesmo_nome_falha(tmp_path):
    import os

    from mandacaru_win.guard_service import ServidorPipe
    srv, t, nome = _servidor(tmp_path, lambda pid: pid == os.getpid())
    try:
        _pedir(nome, codificar({"acao": "ping"}))
        outro = ServidorPipe(nome, Despachante(_acoes(tmp_path)[0]), lambda pid: True)
        with pytest.raises(OSError):
            outro.servir()                                  # FILE_FLAG_FIRST_PIPE_INSTANCE
    finally:
        srv.parar()
        t.join(10)


def test_modulos_guard_sem_qt():
    import os
    import subprocess
    codigo = ("import sys, mandacaru_win.guard_protocol, mandacaru_win.guard_service, mandacaru_win.guard_client; "
              "print('PySide6' in sys.modules)")
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}
    saida = subprocess.run([sys.executable, "-c", codigo], capture_output=True, text=True, env=env, timeout=120)
    assert saida.returncode == 0, saida.stderr
    assert saida.stdout.strip() == "False"
