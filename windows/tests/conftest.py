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
