"""Instalacao do modelo no repositorio: valida os 5 artefatos e recusa qualquer coisa estranha."""
import hashlib
import os
import shutil

import pytest

pytest.importorskip("sklearn")
pytest.importorskip("pyzipper")

from treino_corpus import corpus_sintetico

from tools import instalar_modelo
from tools.treino import pipeline


@pytest.fixture(scope="module")
def _artefatos_modulo(tmp_path_factory):
    base = tmp_path_factory.mktemp("artefatos")
    corpus = corpus_sintetico(base, n_scripts=300, n_elf=60)
    out = base / "saida" / "teste"
    assert pipeline.main(["--corpus", str(corpus), "--cache", str(base / "c.sqlite"), "--saida", str(out),
                          "--corte-teste", "2026-10-01", "--corte-calibracao", "2026-08-01",
                          "--model-id", "teste"]) == 0
    return out


@pytest.fixture
def origem(_artefatos_modulo, tmp_path):
    destino = tmp_path / "origem"
    shutil.copytree(_artefatos_modulo, destino)
    return destino


def _repo_falso(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src/mandacaru/ml/models").mkdir(parents=True)
    (repo / "src/mandacaru/ml/__init__.py").write_text(
        '"""x"""\n\n# familia -> sha256\nMODEL_SHA256: dict[str, str] = {}\nSHADOW_LOG = "x"\n')
    return repo


def test_instalar_modelo_valida_e_fixa_o_hash(origem, tmp_path):
    repo = _repo_falso(tmp_path)
    assert instalar_modelo.main([str(origem), "--repo", str(repo)]) == 0
    assert (repo / "tests/fixtures/ml_golden.json").is_file()
    assert list((repo / "docs/ml").glob("relatorio-*.md"))
    texto = (repo / "src/mandacaru/ml/__init__.py").read_text()
    for fam in ("elf", "script"):
        h = hashlib.sha256((repo / f"src/mandacaru/ml/models/{fam}.json").read_bytes()).hexdigest()
        assert f'"{fam}": "{h}"' in texto
    assert 'SHADOW_LOG = "x"' in texto                       # o resto do arquivo fica intacto


def test_instalar_modelo_recusa_estranho_symlink_e_ansi(origem, tmp_path):
    (origem / "amostra.bin").write_bytes(b"\x7fELF")
    assert instalar_modelo.main([str(origem), "--repo", str(_repo_falso(tmp_path / "a"))]) == 1
    (origem / "amostra.bin").unlink()
    [rel] = origem.glob("relatorio-*.md")
    rel.write_text("\x1b[31minjection\x1b[0m\n")
    assert instalar_modelo.main([str(origem), "--repo", str(_repo_falso(tmp_path / "b"))]) == 1
    rel.write_text("# ok\n")
    (origem / "elf.json").unlink()
    os.symlink("/etc/passwd", origem / "elf.json")
    repo = _repo_falso(tmp_path / "c")
    assert instalar_modelo.main([str(origem), "--repo", str(repo)]) == 1
    assert not list((repo / "src/mandacaru/ml/models").glob("*.json"))   # nada copiado
