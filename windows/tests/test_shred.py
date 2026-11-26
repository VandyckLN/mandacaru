"""Testes da destruição segura (shred) de arquivos e pastas."""
import os
import stat
from pathlib import Path

import pytest
from mandacaru_win.shred import ShredError, shred_file, shred_path


def test_shred_file_overwrites_content_before_unlink(tmp_path, monkeypatch):
    f = tmp_path / "segredo.txt"
    original = b"SENHA-ULTRA-SECRETA-" * 200
    f.write_bytes(original)

    captured = {}
    real_unlink = os.unlink

    def spy_unlink(p):
        # Antes do unlink, o arquivo já foi truncado (0 bytes) e renomeado
        captured["name"] = Path(p).name
        captured["size"] = Path(p).stat().st_size
        real_unlink(p)

    monkeypatch.setattr(os, "unlink", spy_unlink)
    shred_file(f, passes=2)
    assert not f.exists()
    assert captured["name"] != "segredo.txt" and captured["size"] == 0


def test_shred_file_handles_readonly_and_empty(tmp_path):
    f = tmp_path / "somente_leitura.bin"
    f.write_bytes(b"abc123")
    os.chmod(f, stat.S_IREAD)
    shred_file(f)
    assert not f.exists()

    vazio = tmp_path / "vazio.txt"
    vazio.write_bytes(b"")
    shred_file(vazio)
    assert not vazio.exists()


def test_shred_path_destroys_folder_tree_and_ignores_symlink_target(tmp_path):
    fora = tmp_path / "fora"
    fora.mkdir()
    protegido = fora / "manter.txt"
    protegido.write_text("nao tocar")

    alvo = tmp_path / "lixo"
    (alvo / "sub" / "vazia").mkdir(parents=True)
    (alvo / "a.txt").write_text("dados A")
    (alvo / "sub" / "b.txt").write_text("dados B")
    try:
        (alvo / "link_fora").symlink_to(fora, target_is_directory=True)
    except OSError:
        pass

    progress = []
    summary = shred_path(alvo, on_progress=lambda p, i, n: progress.append((i, n)))
    assert summary.completed and not summary.errors
    assert not alvo.exists()
    assert summary.files_shredded >= 2 and summary.dirs_removed == 3
    assert protegido.read_text() == "nao tocar"
    assert progress and progress[-1][0] == progress[-1][1]


def test_shred_path_blocks_protected_dirs():
    with pytest.raises(ShredError):
        shred_path(Path(os.sep))
    with pytest.raises(ShredError):
        shred_path(Path.home())


def _hard_link(alvo: Path, link: Path) -> None:
    try:
        os.link(alvo, link)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("sistema de arquivos sem suporte a hard link")


def test_shred_file_hard_link_nao_apaga_conteudo_de_fora(tmp_path):
    fora = tmp_path / "usuario" / "tese.txt"
    fora.parent.mkdir()
    fora.write_bytes(b"minha tese importante")
    link = tmp_path / "AGENTS.md"
    _hard_link(fora, link)

    shred_file(link)

    assert not link.exists()
    assert fora.read_bytes() == b"minha tese importante"


def test_shred_path_hard_link_dentro_da_pasta_nao_destroi_arquivo_externo(tmp_path):
    fora = tmp_path / "usuario" / "tese.txt"
    fora.parent.mkdir()
    fora.write_bytes(b"minha tese importante")
    proj = tmp_path / "proj"
    (proj / "sub").mkdir(parents=True)
    _hard_link(fora, proj / "sub" / "AGENTS.md")
    (proj / "normal.txt").write_bytes(b"segredo do projeto")

    resumo = shred_path(proj)

    assert resumo.completed and not resumo.errors
    assert not proj.exists()
    assert fora.read_bytes() == b"minha tese importante"


def test_shred_file_hard_link_ainda_sobrescreve_quando_e_o_ultimo_nome(tmp_path, monkeypatch):
    # Sem outro nome apontando para o conteúdo, o comportamento antigo continua: sobrescreve antes de apagar.
    alvo = tmp_path / "unico.bin"
    alvo.write_bytes(b"A" * 64)
    escritos = []
    real_urandom = os.urandom
    monkeypatch.setattr(os, "urandom", lambda n: escritos.append(n) or real_urandom(n))
    shred_file(alvo)
    assert escritos and not alvo.exists()
