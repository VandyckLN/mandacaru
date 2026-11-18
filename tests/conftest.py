"""Fixtures compartilhadas."""
import shutil
import tempfile

import pytest


@pytest.fixture
def short_dir():
    """Pasta com caminho curto: socket AF_UNIX aceita no maximo 108 bytes, e o tmp_path do pytest passa disso."""
    d = tempfile.mkdtemp(prefix="mc", dir="/tmp")
    yield d
    shutil.rmtree(d, ignore_errors=True)
