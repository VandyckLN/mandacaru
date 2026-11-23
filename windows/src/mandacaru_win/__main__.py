"""Ponto de entrada: python -m mandacaru_win / mandacaru-win."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import traceback
import uuid
from datetime import datetime
from importlib import resources
from pathlib import Path

from PySide6.QtCore import QLockFile, QTimer
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


def _parse_flag_paths(argv: list[str], flag: str) -> list[Path]:
    paths: list[Path] = []
    prefix = flag + "="
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == flag and i + 1 < len(argv):
            val = argv[i + 1].strip()
            if val:
                paths.append(Path(val))
            i += 2
            continue
        if arg.startswith(prefix):
            val = arg.split("=", 1)[1].strip()
            if val:
                paths.append(Path(val))
        i += 1
    return paths


def parse_scan_args(argv: list[str]) -> list[Path]:
    """Extrai caminhos passados via `--scan CAMINHO` (usado pelo menu de contexto do Explorer)."""
    return _parse_flag_paths(argv, "--scan")


def parse_shred_args(argv: list[str]) -> list[Path]:
    """Extrai caminhos passados via `--shred CAMINHO` (destruição definitiva pelo Explorer)."""
    return _parse_flag_paths(argv, "--shred")


def _forward_request(directory: Path, action: str, paths: list[Path]) -> Path:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    name = f"scan-req-{uuid.uuid4().hex}.json"
    tmp = directory / (name + ".tmp")
    dest = directory / name
    payload = json.dumps({"action": action, "paths": [str(p) for p in paths]}, ensure_ascii=False)
    tmp.write_text(payload, encoding="utf-8")
    os.replace(tmp, dest)
    return dest


def forward_scan_request(directory: Path, paths: list[Path]) -> Path:
    """Grava uma requisição atômica para a instância já aberta iniciar a varredura."""
    return _forward_request(directory, "scan", paths)


def forward_shred_request(directory: Path, target: Path) -> Path:
    """Grava uma requisição atômica para a instância já aberta pedir confirmação e destruir o alvo."""
    return _forward_request(directory, "shred", [target])


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    scan_targets = parse_scan_args(sys.argv[1:])
    shred_targets = parse_shred_args(sys.argv[1:])
    set_app_id()  # antes de criar qualquer janela
    app = QApplication(sys.argv)
    app.setApplicationName("Mandacaru")
    app.setWindowIcon(app_icon())
    data = data_dir()
    install_excepthook(data)
    lock = acquire_lock(data)
    if lock is None:
        if shred_targets:
            try:
                forward_shred_request(data, shred_targets[0])
                return 0
            except OSError:
                pass
        elif scan_targets:
            try:
                forward_scan_request(data, scan_targets)
                return 0
            except OSError:
                pass
        QMessageBox.information(None, "Mandacaru", "O Mandacaru já está em execução.")
        return 0
    win = MainWindow(data)
    win.show()
    win.watch_scan_requests()
    win.check_updates()  # em thread; no máximo 1×/24 h
    if shred_targets:
        QTimer.singleShot(0, lambda w=win, t=shred_targets[0]: w.shred_target(t))
    elif scan_targets:
        QTimer.singleShot(0, lambda w=win, t=scan_targets: w.start_scan(t))
    rc = app.exec()
    # a janela precisa morrer antes do QApplication, senão o Windows fecha com access violation
    del win
    return rc


if __name__ == "__main__":
    sys.exit(main())
