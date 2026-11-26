"""installer.iss: modo "para todos os usuários" com a Proteção avançada (MandacaruGuard)."""
import re
from pathlib import Path

ISS = (Path(__file__).resolve().parents[1] / "installer.iss").read_text(encoding="utf-8")


def _secao(nome: str) -> str:
    m = re.search(rf"^\[{nome}\]\s*$(.*?)(?=^\[|\Z)", ISS, re.M | re.S)
    assert m, f"seção [{nome}] ausente"
    return m.group(1)


def test_escolha_para_todos_ou_so_para_mim():
    s = _secao("Setup")
    assert "PrivilegesRequired=lowest" in s
    assert "PrivilegesRequiredOverridesAllowed=dialog" in s
    assert r"DefaultDirName={autopf}\Mandacaru" in s


def test_atalhos_e_menu_de_contexto_seguem_o_modo():
    assert "{userprograms}" not in ISS and "{userdesktop}" not in ISS
    assert "{autoprograms}" in _secao("Icons") and "{autodesktop}" in _secao("Icons")
    reg = _secao("Registry")
    assert "Root: HKCU" not in reg and reg.count("Root: HKA") >= 15


def test_tarefa_protecao_avancada_so_no_modo_para_todos():
    t = [linha for linha in _secao("Tasks").splitlines() if "protecaoavancada" in linha]
    assert len(t) == 1 and "Check: IsAdminInstallMode" in t[0] and "Proteção avançada" in t[0]


def test_janela_nunca_abre_elevada():
    for linha in _secao("Run").splitlines():
        if "Mandacaru.exe" in linha and not linha.lstrip().startswith(";"):
            assert "runasoriginaluser" in linha, linha


def test_servico_instalado_parado_e_removido():
    code = _secao("Code")
    assert "--guard-servico" in code and "LocalSystem" in code and "guard.json" in code
    assert "NomeServico = 'MandacaruGuard'" in code and "'stop ' + NomeServico" in code
    prep = code[code.index("function PrepareToInstall"):]
    assert "PararServico" in prep[:prep.index("end;")]                 # para antes de copiar os arquivos
    desinst = _secao("UninstallRun")
    assert "--guard-remover-regras" in desinst
    assert desinst.index("--guard-remover-regras") < desinst.index("delete MandacaruGuard")
    assert all("Check: IsAdminInstallMode" in linha for linha in desinst.splitlines() if "Filename" in linha)
