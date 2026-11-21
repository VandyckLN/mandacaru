"""Ponto de entrada: python -m mandacaru_win / mandacaru-win."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from PySide6.QtWidgets import QApplication

from mandacaru.events import Severity
from mandacaru_win.app import MainWindow
from mandacaru_win.scan import make_scanner, scan_paths
from mandacaru_win.store import data_dir

# Mesmo texto de tests/conftest.py (não usar EICAR: o Defender apaga o arquivo).
SELFTEST_PS = (
    "powershell.exe -NoP -enc "
    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBi" + "\n"
)


def selftest() -> int:
    """0 = regras carregadas e texto PowerShell de teste detectado (HIGH)."""
    try:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "teste.ps1").write_text(SELFTEST_PS, encoding="utf-8")
            found = []
            scan_paths([Path(tmp)], make_scanner(), set(), lambda *_: None,
                       found.append, lambda: False)
        code = 0 if any(f.severity >= Severity.HIGH for f in found) else 1
        msg = f"{'OK' if code == 0 else 'FALHOU'}: {len(found)} achado(s)"
    except Exception as exc:  # noqa: BLE001 - o autoteste deve sempre reportar
        code, msg = 1, f"FALHOU: {exc!r}"
    try:  # com console=False não há stdout
        out = Path(os.environ.get("TEMP") or tempfile.gettempdir())
        (out / "mandacaru-selftest.txt").write_text(msg + "\n", encoding="utf-8")
    except OSError:
        pass
    return code


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    app = QApplication(sys.argv)
    app.setApplicationName("Mandacaru")
    win = MainWindow(data_dir())
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
