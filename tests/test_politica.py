"""Politica do repositorio: nenhuma amostra (ELF/zip) versionada e modelos so com numeros e nomes."""
import json
import subprocess
from pathlib import Path

import pytest

from mandacaru.ml import MODEL_SHA256
from mandacaru.ml.model import load_model

ROOT = Path(__file__).resolve().parent.parent
MAGICS = {b"\x7fELF": "ELF", b"PK\x03\x04": "zip", b"7z\xbc\xaf": "7z", b"Rar!": "rar"}


def _versionados():
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("fora de um repositorio git (ex.: build do .deb)")
    return [ROOT / p.decode() for p in out.split(b"\0") if p]


def _strings(o):
    if isinstance(o, str):
        yield o
    elif isinstance(o, dict):
        for k, v in o.items():
            yield k
            yield from _strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from _strings(v)


def test_nenhum_binario_ou_compactado_versionado():
    achados = []
    for p in _versionados():
        if p.is_file():
            with open(p, "rb") as fh:
                head = fh.read(4)
            achados += [f"{p.relative_to(ROOT)} ({n})" for m, n in MAGICS.items() if head.startswith(m)]
    assert achados == []


def test_modelos_instalados_batem_com_os_hashes_fixados():
    pasta = ROOT / "src" / "mandacaru" / "ml" / "models"
    presentes = {p.stem: p for p in pasta.glob("*.json")}
    assert set(presentes) == set(MODEL_SHA256)
    for fam, p in presentes.items():
        load_model(p, expected_sha256=MODEL_SHA256[fam])
        for s in _strings(json.loads(p.read_text())):
            assert len(s) <= 64                 # nada que pareca conteudo codificado


def test_modelos_vao_no_pacote():
    assert '"ml/models/*.json"' in (ROOT / "pyproject.toml").read_text()
