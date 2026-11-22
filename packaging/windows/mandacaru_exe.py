"""Ponto de entrada do mandacaru.exe (PyInstaller).

Com argumentos, e o CLI de sempre. Aberto com dois cliques (sem argumentos), varre as
pastas do usuario e espera um Enter: sem isso a janela fecha antes de a pessoa ler.
"""
from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path

from mandacaru.cli import default_watch_paths
from mandacaru.cli import main as cli_main


def run(argv: list[str] | None = None, pause: Callable[[str], object] = input) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        return cli_main(argv)
    if os.name == "nt":
        os.system("")  # liga as cores ANSI no console do Windows
    paths = default_watch_paths() or [str(Path.home())]
    print("Mandacaru: varrendo " + ", ".join(paths) + "\n")
    try:
        rc = cli_main(["scan", *paths])
    except SystemExit as exc:
        rc = exc.code if isinstance(exc.code, int) else 1
    except Exception as exc:  # a janela nao pode sumir sem mostrar o erro
        print(f"\nErro: {exc}")
        rc = 1
    if rc == 0:
        print("\nNenhum arquivo perigoso encontrado.")
    elif rc == 2:
        print("\nATENCAO: arquivos suspeitos acima. Nao abra esses arquivos.")
    print("\nPara varrer outra pasta: mandacaru.exe scan \"C:\\caminho\\da\\pasta\"")
    try:
        pause("\nPressione Enter para fechar...")
    except EOFError:
        pass
    return rc


if __name__ == "__main__":
    sys.exit(run())
