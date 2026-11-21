"""Só coleta os testes daqui quando o pytest é executado a partir de windows/.

O CI Linux roda `pytest` na raiz sem instalar mandacaru_win/PySide6; sem isto
ele tentaria importar estes testes (e colidiria com tests/test_quarantine.py).
"""
from pathlib import Path

_AQUI = Path(__file__).resolve().parent


def pytest_ignore_collect(collection_path, config):
    if Path(config.rootpath).resolve() != _AQUI:
        return True
    return None
