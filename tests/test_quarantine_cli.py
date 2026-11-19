"""`mandacaru quarentena ...`: decisoes como root, saida legivel e codigos de saida do contrato."""
import json
import os
import pwd

import pytest

from mandacaru import cli
from mandacaru.analysis import AnalysisResult, SourceResult
from mandacaru.decisions import DecisionLog
from mandacaru.events import Alert, Severity
from mandacaru.quarantine import Quarantine, TrustList
from mandacaru.quarantine_cli import cmd_quarentena

EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
NOW = 1_800_000_000.0


@pytest.fixture
def q(tmp_path):
    (tmp_path / "q").mkdir()
    return Quarantine(tmp_path / "q", DecisionLog(tmp_path / "d.jsonl"), TrustList(tmp_path / "t.json"),
                      now=lambda: NOW, strict_log=True)


def isolar(q, tmp_path, nome="mal.py", conteudo=b"print('oi')\n"):
    f = tmp_path / nome
    f.write_bytes(conteudo)
    r = q.isolate(str(f), Alert("yara.Teste", Severity.HIGH, "s", {"path": str(f)}))
    assert r.status == "isolado"
    return r.case


def log(tmp_path):
    return [json.loads(x) for x in (tmp_path / "d.jsonl").read_text().splitlines()]


def cfgfile(tmp_path, text=""):
    p = tmp_path / "c.toml"
    p.write_text(text, encoding="utf-8")
    return str(p)


def run(argv, tmp_path, cfg="", **kw):
    args = cli.build_parser().parse_args(["--config", cfgfile(tmp_path, cfg), "quarentena", *argv])
    kw.setdefault("euid", 0)
    kw.setdefault("env", {})
    kw.setdefault("stdin_isatty", lambda: False)
    return cmd_quarentena(args, **kw)


def resultado(case_id, verdict="desconhecido", status="nao_achou"):
    sources = {n: SourceResult(status) for n in ("cymru", "circl")}
    sources["malwarebazaar"] = SourceResult("desligada")
    sources["virustotal"] = SourceResult("desligada")
    return AnalysisResult(case_id, verdict, sources, f"{verdict.capitalize()}: teste")


def analisador(verdict="desconhecido", status="nao_achou"):
    chamadas = []

    def fake(case_id, sha256, cfg):
        chamadas.append((case_id, sha256, cfg))
        return resultado(case_id, verdict, status)
    fake.chamadas = chamadas
    return fake


def nao_pergunta(prompt):
    raise AssertionError("nao devia perguntar")


# ---------------------------------------------------------------- listar
def test_listar_mostra_casos_sem_root(q, tmp_path, capsys):
    c1 = isolar(q, tmp_path, "a.py")
    c2 = isolar(q, tmp_path, "b.py", b"outro")
    q.set_analysis(c2.id, resultado(c2.id, "malicioso").to_dict())
    assert run(["listar"], tmp_path, quarantine=q, euid=1000) == 0
    linhas = capsys.readouterr().out.splitlines()
    assert len(linhas) == 3  # cabecalho + 2 casos
    por_id = {ln.split("\t")[0]: ln.split("\t") for ln in linhas[1:]}
    import time
    data = time.strftime("%Y-%m-%d %H:%M", time.localtime(NOW))
    assert por_id[c1.id] == [c1.id, data, str(tmp_path / "a.py"), "yara.Teste", "30 dia(s)", "-"]
    assert por_id[c2.id] == [c2.id, data, str(tmp_path / "b.py"), "yara.Teste", "30 dia(s)", "malicioso"]


def test_listar_vazio(q, tmp_path, capsys):
    assert run(["listar"], tmp_path, quarantine=q, euid=1000) == 0
    assert capsys.readouterr().out.strip() == "Nenhum caso em quarentena."


def test_listar_nao_deixa_nome_com_quebra_de_linha_forjar_linhas(q, tmp_path, capsys):
    isolar(q, tmp_path, "a\nb\tc.py")
    assert run(["listar"], tmp_path, quarantine=q, euid=1000) == 0
    linhas = capsys.readouterr().out.splitlines()
    assert len(linhas) == 2 and len(linhas[1].split("\t")) == 6


def test_listar_sem_permissao_sai_com_1(tmp_path, capsys):
    q = Quarantine(tmp_path / "nao-existe", DecisionLog(tmp_path / "d.jsonl"))
    assert run(["listar"], tmp_path, quarantine=q, euid=1000) == 1
    err = capsys.readouterr().err
    assert err.startswith("mandacaru: erro: ") and "Traceback" not in err


# ---------------------------------------------------------------- root e erros
@pytest.mark.parametrize("argv", [["analisar", "a" * 32], ["manter", "a" * 32], ["confiar", "a" * 32],
                                  ["apagar", "a" * 32], ["desconfiar", "a" * 64], ["limpar"]])
def test_decisao_sem_root_sai_com_1(q, tmp_path, capsys, argv):
    assert run(argv, tmp_path, quarantine=q, euid=1000) == 1
    assert capsys.readouterr().err.strip() == (
        "mandacaru: erro: este comando precisa de root (use sudo ou o botao do popup)")


def test_id_inexistente_sai_com_3(q, tmp_path, capsys):
    for sub in ("analisar", "manter", "confiar", "apagar"):
        assert run([sub, "0" * 32], tmp_path, quarantine=q, analyzer=analisador()) == 3
    assert "Traceback" not in capsys.readouterr().err


def test_id_malformado_sai_com_3(q, tmp_path, capsys):
    assert run(["manter", "../../etc/passwd"], tmp_path, quarantine=q) == 3
    assert capsys.readouterr().err.startswith("mandacaru: erro: ")


def test_bin_adulterado_sai_com_4(q, tmp_path):
    case = isolar(q, tmp_path)
    (tmp_path / "q" / f"{case.id}.bin").write_bytes(b"trocado")
    assert run(["confiar", case.id], tmp_path, quarantine=q) == 4
    assert not (tmp_path / "mal.py").exists()


def test_diretorio_original_sumiu_sai_com_1(q, tmp_path, capsys):
    (tmp_path / "sub").mkdir()
    case = isolar(q, tmp_path, "sub/x.py")
    (tmp_path / "sub").rmdir()
    assert run(["confiar", case.id], tmp_path, quarantine=q) == 1
    err = capsys.readouterr().err
    assert err.startswith("mandacaru: erro: ") and "nao existe mais" in err


# ---------------------------------------------------------------- decisoes
def test_confiar_restaura_e_registra_quem(q, tmp_path, capsys):
    case = isolar(q, tmp_path)
    assert run(["confiar", case.id], tmp_path, quarantine=q, env={"PKEXEC_UID": str(os.getuid())}) == 0
    assert (tmp_path / "mal.py").read_bytes() == b"print('oi')\n"
    assert str(tmp_path / "mal.py") in capsys.readouterr().out
    ultimo = log(tmp_path)[-1]
    assert ultimo["action"] == "confiar"
    assert ultimo["by"] == pwd.getpwuid(os.getuid()).pw_name and ultimo["uid"] == os.getuid()
    assert q.trust.contains(case.sha256)
    assert run(["confiar", case.id], tmp_path, quarantine=q) == 3  # ja resolvido


def test_confiar_avisa_quando_restaura_com_outro_nome(q, tmp_path, capsys):
    case = isolar(q, tmp_path)
    (tmp_path / "mal.py").write_bytes(b"novo")
    assert run(["confiar", case.id], tmp_path, quarantine=q) == 0
    out = capsys.readouterr().out
    assert "Restaurado como " in out and "(o caminho original ja existia)" in out
    assert (tmp_path / "mal.py").read_bytes() == b"novo"


def test_manter_registra(q, tmp_path, capsys):
    case = isolar(q, tmp_path)
    assert run(["manter", case.id], tmp_path, quarantine=q, env={"SUDO_UID": str(os.getuid())}) == 0
    assert log(tmp_path)[-1]["action"] == "manter" and log(tmp_path)[-1]["uid"] == os.getuid()
    assert q.load(case.id).expires_at == case.expires_at


def test_apagar_remove(q, tmp_path):
    case = isolar(q, tmp_path)
    assert run(["apagar", case.id], tmp_path, quarantine=q) == 0
    assert q.list() == [] and log(tmp_path)[-1]["action"] == "apagar"


def test_limpar_apaga_vencidos(q, tmp_path, capsys):
    velho = isolar(q, tmp_path, "a.py")
    q.now = lambda: NOW + 1
    novo = isolar(q, tmp_path, "b.py", b"outro")
    q.now = lambda: velho.expires_at + 0.5
    assert run(["limpar"], tmp_path, quarantine=q) == 0
    assert capsys.readouterr().out.strip() == "1 caso(s) expirado(s) apagado(s)"
    assert [c.id for c in q.list()] == [novo.id]
    assert log(tmp_path)[-1]["action"] == "expirado"


def test_desconfiar_tira_da_lista(q, tmp_path, capsys):
    sha = "ab" * 32
    q.trust.add(sha, "/x", "eu")
    assert run(["desconfiar", sha], tmp_path, quarantine=q, env={"SUDO_UID": str(os.getuid())}) == 0
    assert not TrustList(tmp_path / "t.json").contains(sha)
    ultimo = log(tmp_path)[-1]
    assert ultimo["action"] == "desconfiar" and ultimo["sha256"] == sha and ultimo["uid"] == os.getuid()
    assert sha in capsys.readouterr().out
    assert run(["desconfiar", sha], tmp_path, quarantine=q) == 3  # ja nao esta na lista
    assert run(["desconfiar", "AB" * 32], tmp_path, quarantine=q) == 3
    assert run(["desconfiar", "xyz"], tmp_path, quarantine=q) == 3


# ---------------------------------------------------------------- analisar
def test_analisar_json_segue_contrato(q, tmp_path, capsys):
    case = isolar(q, tmp_path)
    fake = analisador("malicioso", "achou")
    assert run(["analisar", case.id, "--json"], tmp_path, quarantine=q, analyzer=fake) == 0
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 1
    d = json.loads(out[0])
    assert d["v"] == 1 and d["id"] == case.id and d["verdict"] == "malicioso"
    assert set(d["sources"]) == {"cymru", "circl", "malwarebazaar", "virustotal"}
    assert fake.chamadas[0][:2] == (case.id, case.sha256)
    assert q.load(case.id).analysis == d
    ultimo = log(tmp_path)[-1]
    assert ultimo["action"] == "analisar" and ultimo["detail"] == d


def test_analisar_texto_com_tty_mostra_proximos_passos(q, tmp_path, capsys):
    case = isolar(q, tmp_path)
    assert run(["analisar", case.id], tmp_path, quarantine=q, analyzer=analisador(),
               stdin_isatty=lambda: True, input_fn=nao_pergunta) == 0
    out = capsys.readouterr().out
    assert "Desconhecido: teste" in out and "cymru" in out and "virustotal" in out
    assert (f"Confiar: sudo mandacaru quarentena confiar {case.id} | "
            f"Manter: sudo mandacaru quarentena manter {case.id}") in out


def test_analisar_sem_tty_nao_pergunta(q, tmp_path, capsys):
    case = isolar(q, tmp_path)
    assert run(["analisar", case.id], tmp_path, quarantine=q, analyzer=analisador(), input_fn=nao_pergunta) == 0
    out = capsys.readouterr().out
    assert "Desconhecido: teste" in out and "Confiar:" not in out


def test_analisar_sem_resposta_roda_yara_local(q, tmp_path, capsys):
    case = isolar(q, tmp_path, "eicar.com", EICAR.encode())
    assert run(["analisar", case.id, "--json"], tmp_path, quarantine=q, analyzer=analisador(status="erro")) == 0
    d = json.loads(capsys.readouterr().out)
    assert list(d["sources"])[-1] == "yara_local"
    assert d["sources"]["yara_local"]["status"] == "achou" and "yara." in d["sources"]["yara_local"]["detail"]
    assert "; YARA local: yara." in d["summary"] and d["verdict"] == "desconhecido"


def test_analisar_sem_resposta_yara_local_limpo(q, tmp_path, capsys):
    case = isolar(q, tmp_path)
    assert run(["analisar", case.id, "--json"], tmp_path, quarantine=q, analyzer=analisador(status="erro")) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["sources"]["yara_local"] == {"status": "nao_achou", "detail": ""}
    assert d["summary"].endswith("; YARA local: nada encontrado")


def test_analisar_com_resposta_nao_roda_yara_local(q, tmp_path, capsys):
    case = isolar(q, tmp_path, "eicar.com", EICAR.encode())
    assert run(["analisar", case.id, "--json"], tmp_path, quarantine=q, analyzer=analisador()) == 0
    assert "yara_local" not in json.loads(capsys.readouterr().out)["sources"]


PROMPT = "O arquivo ficara acessivel a pesquisadores e empresas parceiras do VirusTotal. Enviar? [s/N] "


def test_enviar_exige_chave_tty_e_confirmacao(q, tmp_path, capsys):
    case = isolar(q, tmp_path)
    enviados = []

    def uploader(data, filename, key):
        enviados.append((data, filename, key))
        return "analise-123"

    com_chave = '[analysis]\nvirustotal_key = "k"\n'
    # sem chave
    assert run(["analisar", case.id, "--enviar"], tmp_path, quarantine=q, analyzer=analisador(),
               stdin_isatty=lambda: True, input_fn=nao_pergunta, uploader=uploader) == 1
    assert "VirusTotal" in capsys.readouterr().err
    # sem TTY
    assert run(["analisar", case.id, "--enviar"], tmp_path, com_chave, quarantine=q, analyzer=analisador(),
               input_fn=nao_pergunta, uploader=uploader) == 1
    assert "TTY" in capsys.readouterr().err
    # veredito conhecido
    assert run(["analisar", case.id, "--enviar"], tmp_path, com_chave, quarantine=q,
               analyzer=analisador("malicioso", "achou"), stdin_isatty=lambda: True, input_fn=nao_pergunta,
               uploader=uploader) == 1
    assert "desconhecido" in capsys.readouterr().err
    perguntas = []

    def responde(r):
        def f(prompt):
            perguntas.append(prompt)
            return r
        return f
    # resposta vazia: nao envia
    assert run(["analisar", case.id, "--enviar"], tmp_path, com_chave, quarantine=q, analyzer=analisador(),
               stdin_isatty=lambda: True, input_fn=responde(""), uploader=uploader) == 0
    assert enviados == [] and perguntas == [PROMPT]
    assert "enviado" not in log(tmp_path)[-1]["detail"]
    # "s": envia o conteudo original, desembaralhado
    assert run(["analisar", case.id, "--enviar"], tmp_path, com_chave, quarantine=q, analyzer=analisador(),
               stdin_isatty=lambda: True, input_fn=responde("s"), uploader=uploader) == 0
    assert enviados == [(b"print('oi')\n", "mal.py", "k")]
    ultimo = log(tmp_path)[-1]
    assert ultimo["action"] == "analisar" and ultimo["detail"]["enviado"] is True
    assert ultimo["detail"]["verdict"] == "desconhecido"


def test_enviar_com_falha_de_rede_sai_com_1(q, tmp_path, capsys):
    case = isolar(q, tmp_path)

    def uploader(data, filename, key):
        raise RuntimeError("VirusTotal recusou o envio (status 403)")

    assert run(["analisar", case.id, "--enviar"], tmp_path, '[analysis]\nvirustotal_key = "k"\n', quarantine=q,
               analyzer=analisador(), stdin_isatty=lambda: True, input_fn=lambda p: "S", uploader=uploader) == 1
    assert "status 403" in capsys.readouterr().err
    ultimo = log(tmp_path)[-1]
    assert ultimo["action"] == "analisar" and "enviado" not in ultimo["detail"]


# ---------------------------------------------------------------- parser
def test_main_despacha_quarentena(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert cli.main(["--config", cfgfile(tmp_path), "quarentena", "manter", "a" * 32]) == 1
    assert "precisa de root" in capsys.readouterr().err


# ---------------------------------------------------------------- log de decisoes obrigatorio
def test_log_indisponivel_recusa_antes_de_mudar_algo(q, tmp_path, capsys):
    case = isolar(q, tmp_path)
    antes = log(tmp_path)
    q.log = DecisionLog(tmp_path / "nao-existe" / "d.jsonl")
    for argv in (["manter", case.id], ["apagar", case.id], ["confiar", case.id], ["limpar"],
                 ["desconfiar", "ab" * 32]):
        assert run(argv, tmp_path, quarantine=q) == 1
        assert capsys.readouterr().err.startswith("mandacaru: erro: log de decisoes indisponivel: ")
    assert q.load(case.id) == case and log(tmp_path) == antes
    assert not (tmp_path / "mal.py").exists()


@pytest.mark.parametrize("sub", ["manter", "apagar", "confiar", "analisar"])
def test_falha_do_log_depois_da_acao_sai_com_1(q, tmp_path, capsys, monkeypatch, sub):
    case = isolar(q, tmp_path)

    def quebra(self, action, **kw):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(DecisionLog, "record", quebra)
    assert run([sub, case.id], tmp_path, quarantine=q, analyzer=analisador()) == 1
    err = capsys.readouterr().err
    assert err.strip() == "mandacaru: erro: decisao aplicada, mas nao registrada no log: No space left on device"


def test_falha_do_log_no_desconfiar_e_no_limpar_sai_com_1(q, tmp_path, capsys, monkeypatch):
    q.trust.add("ab" * 32, "/x", "eu")
    velho = isolar(q, tmp_path)
    q.now = lambda: velho.expires_at + 1
    monkeypatch.setattr(DecisionLog, "record", lambda self, action, **kw: (_ for _ in ()).throw(OSError(5, "EIO")))
    assert run(["desconfiar", "ab" * 32], tmp_path, quarantine=q) == 1
    assert run(["limpar"], tmp_path, quarantine=q) == 1
    assert capsys.readouterr().err.count("decisao aplicada, mas nao registrada no log: EIO") == 2


def test_quarentena_do_monitor_continua_engolindo_falha_do_log(tmp_path, monkeypatch):
    (tmp_path / "q").mkdir()
    q = Quarantine(tmp_path / "q", DecisionLog(tmp_path / "d.jsonl"))
    case = isolar(q, tmp_path)
    monkeypatch.setattr(DecisionLog, "record", lambda self, action, **kw: (_ for _ in ()).throw(OSError(5, "EIO")))
    q.keep(case.id, "eu", 1)
    q.delete(case.id, "eu", 1)
    assert q.list() == []


# ---------------------------------------------------------------- YARA local que falha
def test_yara_local_que_falha_nao_derruba_a_analise(q, tmp_path, capsys, monkeypatch):
    from mandacaru.detectors import static

    class Quebrado:
        def __init__(self, *a):
            pass

        def scan_bytes(self, path, data):
            raise RuntimeError("yara explodiu")
    monkeypatch.setattr(static, "StaticScanner", Quebrado)
    case = isolar(q, tmp_path)
    assert run(["analisar", case.id, "--json"], tmp_path, quarantine=q, analyzer=analisador(status="erro")) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["sources"]["yara_local"] == {"status": "erro", "detail": "yara explodiu"}
    assert d["summary"].endswith("; YARA local: erro") and d["verdict"] == "desconhecido"
    assert q.load(case.id).analysis == d and log(tmp_path)[-1]["detail"] == d


def test_regra_yara_invalida_no_config_nao_derruba_a_analise(q, tmp_path, capsys):
    regras = tmp_path / "regras"
    regras.mkdir()
    (regras / "quebrada.yar").write_text("rule x { condition: ")
    case = isolar(q, tmp_path)
    assert run(["analisar", case.id, "--json"], tmp_path, f'[rules]\ndirs = ["{regras}"]\n', quarantine=q,
               analyzer=analisador(status="erro")) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["sources"]["yara_local"]["status"] == "erro" and q.load(case.id).analysis == d


@pytest.mark.parametrize("exc", [EOFError, KeyboardInterrupt])
def test_enviar_com_entrada_encerrada_nao_envia_e_sai_com_1(q, tmp_path, capsys, exc):
    case = isolar(q, tmp_path)

    def input_morto(prompt):
        raise exc()

    def uploader(*a):
        raise AssertionError("nao deveria enviar")

    assert run(["analisar", case.id, "--enviar"], tmp_path, '[analysis]\nvirustotal_key = "k"\n', quarantine=q,
               analyzer=analisador(), stdin_isatty=lambda: True, input_fn=input_morto, uploader=uploader) == 1
    assert "nao confirmado" in capsys.readouterr().err
    assert log(tmp_path)[-1]["action"] == "analisar"


def test_enviar_com_erro_http_sai_com_1_sem_traceback(q, tmp_path, capsys):
    import http.client
    case = isolar(q, tmp_path)

    def uploader(*a):
        raise http.client.IncompleteRead(b"")

    assert run(["analisar", case.id, "--enviar"], tmp_path, '[analysis]\nvirustotal_key = "k"\n', quarantine=q,
               analyzer=analisador(), stdin_isatty=lambda: True, input_fn=lambda p: "s", uploader=uploader) == 1
    assert "envio ao VirusTotal falhou" in capsys.readouterr().err


def test_log_que_e_symlink_e_recusado(q, tmp_path, capsys):
    case = isolar(q, tmp_path)
    (tmp_path / "alvo").write_text("")
    (tmp_path / "d2.jsonl").symlink_to(tmp_path / "alvo")
    q.log = DecisionLog(tmp_path / "d2.jsonl")
    assert run(["apagar", case.id], tmp_path, quarantine=q) == 1
    assert "log de decisoes indisponivel" in capsys.readouterr().err
    assert (tmp_path / "alvo").read_text() == ""
