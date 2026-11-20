"""Pipeline ponta a ponta com um corpus sintetico inofensivo (scripts e ELF montados a mao)."""
import pytest

pytest.importorskip("sklearn")
pytest.importorskip("pyzipper")

from treino_corpus import corpus_sintetico

from tools.treino import pipeline


def test_pipeline_ponta_a_ponta_sintetico(tmp_path):
    corpus = corpus_sintetico(tmp_path, n_scripts=300, n_elf=60)
    out = tmp_path / "out" / "2026.11"
    assert pipeline.main(["--corpus", str(corpus), "--cache", str(tmp_path / "cache.sqlite"),
                          "--saida", str(out), "--corte-teste", "2026-10-01",
                          "--corte-calibracao", "2026-08-01", "--model-id", "2026.11"]) == 0
    assert {p.name for p in out.iterdir()} == {
        "elf.json", "script.json", "golden.json", "relatorio-2026.11.md", "manifesto-2026.11.txt",
    }


def test_pipeline_nao_sobrescreve_modelo_existente(tmp_path):
    corpus = corpus_sintetico(tmp_path, n_scripts=120, n_elf=60)
    out = tmp_path / "out" / "x"
    out.mkdir(parents=True)
    with pytest.raises(FileExistsError):
        pipeline.main(["--corpus", str(corpus), "--cache", str(tmp_path / "c.sqlite"), "--saida", str(out),
                       "--corte-teste", "2026-10-01", "--corte-calibracao", "2026-08-01", "--model-id", "x"])
