import os
from pathlib import Path

import pytest

from mandacaru.events import Severity
from mandacaru.projeto.achado import Achado
from mandacaru.projeto.percurso import (
    PULAR,
    excluir_por_globs,
    ler_texto,
    linha_de,
    listar,
)


def test_listar_pula_pastas_pesadas_e_git(projeto):
    raiz = projeto({
        "src/a.py": "x", "node_modules/x/i.js": "x", ".venv/l.py": "x",
        ".git/config": "x", "dist/b.js": "x",
    })
    assert listar(raiz) == (["src/a.py"], False)


def test_listar_corta_no_limite(projeto):
    raiz = projeto({f"f{i}.txt": "x" for i in range(5)})
    rels, cortado = listar(raiz, limite=3)
    assert len(rels) == 3
    assert cortado is True


def test_listar_nao_segue_link(projeto, tmp_path_factory):
    raiz = projeto({"ok.md": "x"})
    fora = tmp_path_factory.mktemp("fora") / "segredo.txt"
    fora.write_text("segredo")
    try:
        os.symlink(fora, raiz / "AGENTS.md")
        os.symlink(".", raiz / "loop")
    except (OSError, NotImplementedError):
        pytest.skip("symlink indisponivel")
    rels, cortado = listar(raiz)
    assert "AGENTS.md" not in rels
    assert rels == ["ok.md"]
    assert cortado is False
    assert ler_texto(raiz / "AGENTS.md") is None


def test_ler_texto_binario_e_bom(tmp_path):
    for nome, dados in [("b", b"\x00\x01"), ("bom", b"\xef\xbb\xbfol\xc3\xa1"), ("inv", b"a\xffb")]:
        (tmp_path / nome).write_bytes(dados)
    assert ler_texto(tmp_path / "b") is None
    assert ler_texto(tmp_path / "bom") == "olá"
    assert ler_texto(tmp_path / "inv") == "a�b"
    assert ler_texto(tmp_path / "nao_existe") is None
    assert ler_texto(tmp_path) is None


def test_linha_de_crlf():
    t = "a\r\nb\r\nalvo"
    assert linha_de(t, t.index("alvo")) == 3


def test_achado_to_alert():
    a = Achado("projeto.x", Severity.HIGH, "a/b.md", "explica", 7, "tr", ("T1204",))
    al = a.to_alert(Path("/r"))
    assert al.summary == "a/b.md:7: explica"
    assert al.evidence["path"] == str(Path("/r/a/b.md"))
    assert al.mitre == ["T1204"]
    sem = Achado("projeto.x", Severity.LOW, "a.md", "e").to_alert(Path("/r"))
    assert sem.summary == "a.md: e"


def test_excluir_por_globs():
    assert excluir_por_globs(["*/segredo*"])(Path("/p/segredo/x.md")) is True
    assert excluir_por_globs(["*/segredo*"])(Path("/p/outro/x.md")) is False
    assert excluir_por_globs([])(Path("/p/x.md")) is False


def test_pular_exato():
    assert PULAR == frozenset({"node_modules", ".venv", "venv", "__pycache__", "dist", "build"})


def test_fifo_nao_trava(projeto):
    if not hasattr(os, "mkfifo"):
        pytest.skip("mkfifo indisponivel")
    raiz = projeto({"ok.md": "x"})
    os.mkfifo(raiz / "AGENTS.md")
    assert listar(raiz) == (["ok.md"], False)
    assert ler_texto(raiz / "AGENTS.md") is None
