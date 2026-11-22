"""Ponto de entrada do mandacaru.exe (PyInstaller)."""
import sys

from mandacaru.cli import main

if __name__ == "__main__":
    sys.exit(main())
