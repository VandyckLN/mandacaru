"""Ponto de entrada do Mandacaru.exe: o serviço MandacaruGuard não carrega o Qt."""
import os
import subprocess
import sys

import pytest
from mandacaru_win.entrada import guard_argv


@pytest.mark.parametrize("argv,esperado", [
    (["--guard-servico"], ["servico"]),
    (["--guard-remover-regras"], ["remover-regras"]),
    ([], None),
    (["--scan", r"C:\x"], None),
    (["--guard-servico", "extra"], None),
    (["servico"], None),
])
def test_guard_argv(argv, esperado):
    assert guard_argv(argv) == esperado


def test_entrada_nao_importa_qt():
    codigo = "import sys, mandacaru_win.entrada; print('PySide6' in sys.modules)"
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}
    saida = subprocess.run([sys.executable, "-c", codigo], capture_output=True, text=True, env=env, timeout=120)
    assert saida.returncode == 0, saida.stderr
    assert saida.stdout.strip() == "False"


def test_spec_do_pyinstaller_usa_a_entrada():
    from pathlib import Path
    spec = (Path(__file__).resolve().parents[1] / "mandacaru-win.spec").read_text(encoding="utf-8")
    assert '"src/mandacaru_win/entrada.py"' in spec
