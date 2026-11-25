import pytest


@pytest.fixture
def projeto(tmp_path):
    """Devolve `criar(arquivos)`: grava os arquivos em tmp_path e devolve a raiz."""
    def criar(arquivos: dict[str, str | bytes]):
        for rel, conteudo in arquivos.items():
            alvo = tmp_path / rel
            alvo.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(conteudo, bytes):
                alvo.write_bytes(conteudo)
            else:
                alvo.write_text(conteudo, encoding="utf-8")
        return tmp_path
    return criar
