"""Testes do pipeline de treino: a raiz do repo (tools.treino) e esta pasta (helpers) entram no sys.path."""
import sys
from pathlib import Path

_AQUI = Path(__file__).resolve().parent
for _p in (_AQUI.parent.parent, _AQUI):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
