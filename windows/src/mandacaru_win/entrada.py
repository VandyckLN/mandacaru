"""Ponto de entrada do Mandacaru.exe (PyInstaller).

O mesmo executável é a janela e, no modo "para todos os usuários", o serviço MandacaruGuard. A
escolha acontece aqui, antes de qualquer import pesado: o serviço (SYSTEM) nunca carrega o Qt.
"""
from __future__ import annotations

import sys

_GUARD = {"--guard-servico": ["servico"], "--guard-remover-regras": ["remover-regras"]}


def guard_argv(argv: list[str]) -> list[str] | None:
    """Argumentos para `guard_service.main`, ou None quando é para abrir a janela."""
    return list(_GUARD[argv[0]]) if len(argv) == 1 and argv[0] in _GUARD else None


def main() -> int:
    g = guard_argv(sys.argv[1:])
    if g is not None:
        from mandacaru_win.guard_service import main as guard_main
        return guard_main(g)
    from mandacaru_win.__main__ import main as app_main
    return app_main()


if __name__ == "__main__":
    sys.exit(main())
