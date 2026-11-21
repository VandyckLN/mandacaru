"""Ponto de entrada: python -m mandacaru_win / mandacaru-win."""
from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from mandacaru_win.app import MainWindow
from mandacaru_win.store import data_dir


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Mandacaru")
    win = MainWindow(data_dir())
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
