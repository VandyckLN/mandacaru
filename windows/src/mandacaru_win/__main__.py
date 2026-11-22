"""Ponto de entrada: python -m mandacaru_win / mandacaru-win."""
from __future__ import annotations

import os
import sys
import tempfile
import traceback
from datetime import datetime
from importlib import resources
from pathlib import Path

from PySide6.QtCore import QLockFile
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QMessageBox

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


def log_exception(log_dir: Path, exc_type, exc, tb) -> None:
    """Grava a exceção em erros.log e avisa o usuário (o exe não tem console)."""
    try:
        with open(Path(log_dir) / "erros.log", "a", encoding="utf-8") as fh:
            fh.write(f"--- {datetime.now().isoformat(timespec='seconds')} ---\n")
            fh.write("".join(traceback.format_exception(exc_type, exc, tb)))
    except OSError:
        pass
    if QApplication.instance() is not None:
        QMessageBox.critical(
            None, "Mandacaru",
            f"Ocorreu um erro inesperado: {exc!r}\nDetalhes em {Path(log_dir) / 'erros.log'}")


def install_excepthook(log_dir: Path) -> None:
    sys.excepthook = lambda t, e, tb: log_exception(log_dir, t, e, tb)


def acquire_lock(directory: Path) -> QLockFile | None:
    """Trava de instância única; None se outra instância já está aberta."""
    lock = QLockFile(str(Path(directory) / "mandacaru.lock"))
    return lock if lock.tryLock(0) else None


APP_ID = "VandyckLN.Mandacaru"


def set_app_id() -> bool:
    """Dá ao processo um AppUserModelID próprio: a barra de tarefas usa o ícone da janela, não o cache do exe."""
    if sys.platform != "win32":
        return False
    import ctypes

    return ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID) == 0


def app_icon() -> QIcon:
    return QIcon(str(resources.files("mandacaru_win") / "assets" / "mandacaru.png"))


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    set_app_id()  # antes de criar qualquer janela
    app = QApplication(sys.argv)
    app.setApplicationName("Mandacaru")
    app.setWindowIcon(app_icon())
    data = data_dir()
    install_excepthook(data)
    lock = acquire_lock(data)
    if lock is None:
        QMessageBox.information(None, "Mandacaru", "O Mandacaru já está em execução.")
        return 0
    win = MainWindow(data)
    win.show()
    win.check_updates()  # em thread; no máximo 1×/24 h
    rc = app.exec()
    # a janela precisa morrer antes do QApplication, senão o Windows fecha com access violation
    del win
    return rc


if __name__ == "__main__":
    sys.exit(main())
