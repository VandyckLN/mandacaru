"""Politica de tools/treino: nenhum codigo executa, extrai ou carrega dinamicamente."""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TREINO = ROOT / "tools" / "treino"
PROIBIDOS_IMPORT = {
    "subprocess", "pty", "ctypes", "cffi", "importlib",
    "pickle", "marshal", "shelve", "webbrowser",
}
PROIBIDOS_MOD_ATRIB = {"os", "posix", "shutil", "zipfile", "tarfile"}
PROIBIDOS_ATRIB = {
    "system", "popen", "posix_spawn", "posix_spawnp",
    "extract", "extractall", "unpack_archive", "chmod", "fchmod",
}
PROIBIDOS_PREFIXOS = ("exec", "spawn", "posix_spawn")
PROIBIDOS_BUILTINS = {"eval", "exec", "compile", "__import__"}


def violacoes(arquivos):
    achados = []
    for p in arquivos:
        tree = ast.parse(p.read_text(), filename=str(p))
        aliases_mod = set(PROIBIDOS_MOD_ATRIB)
        nomes_proibidos = set(PROIBIDOS_BUILTINS)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    base = a.name.split(".")[0]
                    if base in PROIBIDOS_IMPORT:
                        achados.append(f"{p.name}: import {a.name}")
                    if base in PROIBIDOS_MOD_ATRIB:
                        aliases_mod.add(a.asname or base)
            elif isinstance(node, ast.ImportFrom):
                base = (node.module or "").split(".")[0]
                if base in PROIBIDOS_IMPORT:
                    achados.append(f"{p.name}: from {node.module}")
                if base in PROIBIDOS_MOD_ATRIB:
                    for a in node.names:
                        if a.name == "*" or a.name in PROIBIDOS_ATRIB or a.name.startswith(PROIBIDOS_PREFIXOS):
                            achados.append(f"{p.name}:{node.lineno}: from {node.module} import {a.name}")
                            nomes_proibidos.add(a.asname or a.name)
            elif isinstance(node, ast.Attribute):
                if node.attr in PROIBIDOS_ATRIB:
                    achados.append(f"{p.name}:{node.lineno}: .{node.attr}")
                elif node.attr.startswith(PROIBIDOS_PREFIXOS) and isinstance(node.value, ast.Name) \
                        and node.value.id in aliases_mod:
                    achados.append(f"{p.name}:{node.lineno}: {node.value.id}.{node.attr}")
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in nomes_proibidos:
                achados.append(f"{p.name}:{node.lineno}: {node.func.id}()")
    return achados


def test_existe_e_tem_codigo():
    assert (TREINO / "__init__.py").is_file()


def test_nenhum_import_ou_chamada_proibida():
    assert violacoes(sorted(TREINO.rglob("*.py"))) == []


def test_politica_pega_violacao(tmp_path):
    casos_ruins = (
        "import subprocess\n",
        "import os\nos.system('x')\n",
        "from os import system\nsystem('x')\n",
        "import os as o\no.posix_spawn('/bin/sh', ['sh'], {})\n",
        "from shutil import unpack_archive\n",
        "z.extractall('d')\n",
        "z.extract('x', 'd')\n",
        "import os\nos.execv('a', [])\n",
        "from ctypes import CDLL\n",
        "import importlib\n",
        "import pickle\n",
        "eval('1 + 1')\n",
    )
    for codigo in casos_ruins:
        (tmp_path / "ruim.py").write_text(codigo)
        assert violacoes([tmp_path / "ruim.py"]), codigo


def test_treino_fora_do_pacote():
    toml = (ROOT / "pyproject.toml").read_text()
    # corta so nos cabecalhos de secao ("\n["): o "[" de 'where = ["src"]' nao conta
    assert 'where = ["src"]' in toml.split("[tool.setuptools.packages.find]")[1].split("\n[")[0]
    assert "treino =" in toml.split("[project.optional-dependencies]")[1].split("\n[")[0]
    assert "--ignore=tests/treino" in (ROOT / "debian" / "rules").read_text()
