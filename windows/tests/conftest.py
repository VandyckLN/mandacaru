import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from mandacaru_win.scan import make_scanner

# Mesmo texto de tests/test_detectors.py::test_powershell_encoded (não usar
# EICAR: o Defender do runner apaga o arquivo).
PS_TEXT = (
    "powershell.exe -NoP -enc "
    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBi" + "\n"
)


@pytest.fixture(scope="session")
def scanner():
    return make_scanner()


@pytest.fixture
def ps_text():
    return PS_TEXT


class _HKLMVazio:
    def valores(self, chave):
        return []

    def subchaves(self, chave):
        return []


@pytest.fixture(autouse=True)
def _sem_persistencia_real_do_sistema(monkeypatch, tmp_path_factory):
    """Nenhum teste lê o HKLM nem a Inicializar de todos os usuários da máquina.

    No Windows, a `Persistencia` usa os dois de verdade por padrão; um atalho real do runner
    (com bytes como \\x00\\x01) chegou a "casar" com o alvo de um teste.
    """
    from mandacaru_win import incident_persist
    monkeypatch.setattr(incident_persist, "RegistroHKLMLeitura", _HKLMVazio, raising=False)
    monkeypatch.setenv("ProgramData", str(tmp_path_factory.mktemp("programdata")))
