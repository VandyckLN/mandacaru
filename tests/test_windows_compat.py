"""No Windows nao existem grp/pwd/fcntl nem os.geteuid: o `scan` tem que funcionar assim mesmo."""
from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import mandacaru

# pasta que contem o pacote importado: no build do .deb os testes rodam de uma copia sem src/
SRC = Path(mandacaru.__file__).resolve().parents[1]

# libs de terceiros carregam antes do bloqueio: no Windows elas usam o backend proprio delas
SIMULA_WINDOWS = textwrap.dedent("""
    import os, sys
    import psutil, yara, watchdog.observers
    for m in ("grp", "pwd", "fcntl"):
        sys.modules[m] = None
    for a in ("geteuid", "getuid", "fchown", "chown"):
        if hasattr(os, a):
            delattr(os, a)
    sys.path.insert(0, sys.argv[1])
    sys.argv = ["mandacaru", "scan", sys.argv[2]]
    from mandacaru.cli import main
    sys.exit(main())
""")


def test_scan_sem_apis_unix(tmp_path):
    alvo = tmp_path / "alvo"
    alvo.mkdir()
    (alvo / "limpo.txt").write_text("nada aqui\n")
    r = subprocess.run([sys.executable, "-I", "-c", SIMULA_WINDOWS, str(SRC), str(alvo)],
                       capture_output=True, text=True, timeout=120)
    assert "ModuleNotFoundError" not in r.stderr, r.stderr
    assert "AttributeError" not in r.stderr, r.stderr
    assert r.returncode == 0, r.stdout + r.stderr
