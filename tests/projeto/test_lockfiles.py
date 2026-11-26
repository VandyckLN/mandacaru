import json
import time

import pytest

from mandacaru.projeto import lockfiles
from mandacaru.projeto.achado import ArquivoIlegivel
from mandacaru.projeto.lockfiles import (
    Dependencia,
    dependencias_sem_lockfile,
    eh_lockfile,
    ler_lockfile,
)


def trio(deps):
    return {(d.ecossistema, d.nome, d.versao) for d in deps}


def test_eh_lockfile():
    assert eh_lockfile("a/package-lock.json")
    assert eh_lockfile("requirements-dev.txt")
    assert eh_lockfile("sub/requirements.txt")
    assert not eh_lockfile("package.json")
    assert not eh_lockfile("notes.txt")


def test_desconhecido():
    assert ler_lockfile("foo.lock", "x") == ([], 0)


def test_package_lock_v3():
    texto = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "version": "1.0.0"},
        "node_modules/lodash": {"version": "4.17.15"},
        "node_modules/@babel/core/node_modules/semver": {"version": "6.3.0"},
        "node_modules/@scope/pkg": {"version": "1.2.3"},
        "node_modules/ws": {"link": True, "resolved": "packages/ws"},
        "node_modules/ruim": 5,
        "node_modules/lista": {"version": ["1"]},
        "node_modules/git": {"version": "git+https://x/y.git"},
    }})
    deps, sem = ler_lockfile("package-lock.json", texto)
    assert trio(deps) == {("npm", "lodash", "4.17.15"), ("npm", "semver", "6.3.0"),
                          ("npm", "@scope/pkg", "1.2.3")}
    assert sem == 1
    assert deps[0].origem == "package-lock.json"


def test_package_lock_v1_iterativo():
    texto = json.dumps({"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}})
    deps, _ = ler_lockfile("npm-shrinkwrap.json", texto)
    assert trio(deps) == {("npm", "a", "1.0.0"), ("npm", "b", "2.0.0")}


def _v1_aninhado(n):
    return '{"dependencies":' + '{"x%d":{"version":"1.0.0","dependencies":' % 0 + "".join(
        '{"x%d":{"version":"1.0.0","dependencies":' % i for i in range(1, n)) + "{}" + "}}" * n + "}"


def test_package_lock_v1_profundo_limite():
    deps, _ = ler_lockfile("package-lock.json", _v1_aninhado(100))
    assert len(deps) == 64  # limite de profundidade
    assert deps[0].nome == "x0"


def test_package_lock_v1_muito_profundo():
    # depende do limite de recursao do json do interpretador: ilegivel ou limitado a 64
    t = time.monotonic()
    try:
        deps, _ = ler_lockfile("package-lock.json", _v1_aninhado(5000))
    except ArquivoIlegivel:
        pass
    else:
        assert len(deps) == 64
    assert time.monotonic() - t < 1


def test_dedupe():
    texto = json.dumps({"packages": {
        "node_modules/a": {"version": "1.0.0"},
        "node_modules/x/node_modules/a": {"version": "1.0.0"}}})
    deps, _ = ler_lockfile("package-lock.json", texto)
    assert len(deps) == 1


PNPM9 = """\
lockfileVersion: '9.0'
packages:
  '@types/node@20.1.0':
    resolution: {integrity: sha512-x}
  react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-y}
"""
PNPM5 = """\
lockfileVersion: 5.4
packages:
  /lodash/4.17.21:
    resolution: {integrity: sha512-x}
  /@types/node/20.1.0:
    dev: true
  /react-dom/18.2.0_react@18.2.0:
    dev: false
"""


def test_pnpm_v9():
    deps, _ = ler_lockfile("pnpm-lock.yaml", PNPM9)
    assert trio(deps) == {("npm", "@types/node", "20.1.0"), ("npm", "react-dom", "18.2.0")}


def test_pnpm_v5():
    deps, _ = ler_lockfile("pnpm-lock.yaml", PNPM5)
    assert trio(deps) == {("npm", "lodash", "4.17.21"), ("npm", "@types/node", "20.1.0"),
                          ("npm", "react-dom", "18.2.0")}


YARN1 = """\
# yarn lockfile v1


"@scope/pkg@^1", "@scope/pkg@^1.2":
  version "1.2.3"
  resolved "https://x"

"lodash@^4.17.0", lodash@^4.17.15:
  version "4.17.21"
  dependencies:
    foo "^1"

"strip-ansi-cjs@npm:strip-ansi@^6.0.1":
  version "6.0.1"

"x@npm:@s/real@^1":
  version "1.0.0"
"""


def test_yarn_v1():
    deps, _ = ler_lockfile("yarn.lock", YARN1)
    assert trio(deps) == {("npm", "@scope/pkg", "1.2.3"), ("npm", "lodash", "4.17.21"),
                          ("npm", "strip-ansi", "6.0.1"), ("npm", "@s/real", "1.0.0")}


YARN_BERRY = """\
__metadata:
  version: 6

"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"

"x@npm:@s/real@^1":
  version: 1.0.0

"strip-ansi-cjs@npm:strip-ansi@^6.0.1":
  version: 6.0.1

"app@workspace:.":
  version: 0.0.0-use.local
"""


def test_yarn_berry():
    deps, _ = ler_lockfile("yarn.lock", YARN_BERRY)
    assert trio(deps) == {("npm", "lodash", "4.17.21"), ("npm", "@s/real", "1.0.0"),
                          ("npm", "strip-ansi", "6.0.1")}


POETRY = """\
[[package]]
name = "Django"
version = "4.2.0"

[[package]]
name = "typing_extensions"
version = "4.0.0"
"""


def test_poetry():
    deps, _ = ler_lockfile("poetry.lock", POETRY)
    assert trio(deps) == {("PyPI", "django", "4.2.0"), ("PyPI", "typing-extensions", "4.0.0")}


UV = """\
[[package]]
name = "meu-proj"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "ed"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"""


def test_uv():
    deps, _ = ler_lockfile("uv.lock", UV)
    assert trio(deps) == {("PyPI", "requests", "2.31.0")}


def test_pipfile_lock():
    texto = json.dumps({"default": {"Flask": {"version": "==2.0.1"},
                                    "x": {"version": ">=1"}, "y": 3},
                        "develop": {"pytest": {"version": "==7.0.0"}}})
    deps, sem = ler_lockfile("Pipfile.lock", texto)
    assert trio(deps) == {("PyPI", "flask", "2.0.1"), ("PyPI", "pytest", "7.0.0")}
    assert sem == 1


def test_requirements():
    texto = "Flask==2.0.1\nrequests>=2\n# c\n-r base.txt\nPyYAML[libyaml]==6.0 ; python_version>'3'\n"
    deps, sem = ler_lockfile("requirements.txt", texto)
    assert [(d.nome, d.versao) for d in deps] == [("flask", "2.0.1"), ("pyyaml", "6.0")]
    assert sem == 1


def test_requirements_casos():
    texto = (
        "a==1.*\n"
        "b\n"
        "c==1.0 --hash=sha256:abc\n"
        "d==1.0 \\\n    --hash=sha256:abc\n"
        "e==1.0  # comentario\n"
        "-e .\n--index-url https://x\nhttps://x/y.whl\ngit+https://x/y.git\n"
        "f==1.0,!=1.1\n"
        "g==2.0\t--hash=sha256:abc\n"
    )
    deps, sem = ler_lockfile("requirements-dev.txt", texto)
    assert [(d.nome, d.versao) for d in deps] == [("c", "1.0"), ("d", "1.0"), ("e", "1.0"), ("g", "2.0")]
    assert sem == 3  # a, b, f


@pytest.mark.parametrize("rel", ["package-lock.json", "Pipfile.lock", "pnpm-lock.yaml",
                                 "poetry.lock", "uv.lock"])
def test_lockfile_malformado(rel):
    with pytest.raises(ArquivoIlegivel):
        ler_lockfile(rel, "{[ invalido: = ")


def test_berry_malformado():
    with pytest.raises(ArquivoIlegivel):
        ler_lockfile("yarn.lock", "__metadata:\n  a: [\n")


@pytest.mark.parametrize("rel,texto", [
    ("package-lock.json", '{"packages": []}'),
    ("package-lock.json", "[]"),
    ("Pipfile.lock", '{"default": []}'),
    ("pnpm-lock.yaml", "packages: []"),
    ("pnpm-lock.yaml", "packages: {1: 2, null: b}"),
    ("poetry.lock", "package = 3"),
    ("uv.lock", 'package = [1, {name = 3}]'),
])
def test_tipos_hostis(rel, texto):
    assert ler_lockfile(rel, texto) == ([], 0)


def test_sem_lockfile():
    pj = json.dumps({"dependencies": {"a": "^1", "b": "^2"}, "devDependencies": {"c": "^3"}})
    assert dependencias_sem_lockfile("package.json", pj, {"package.json"}) == 3
    assert dependencias_sem_lockfile("package.json", pj, {"package-lock.json"}) == 0
    assert dependencias_sem_lockfile("package.json", pj, {"yarn.lock"}) == 0
    py = '[project]\ndependencies = ["a", "b>=1"]\n'
    assert dependencias_sem_lockfile("pyproject.toml", py, set()) == 2
    assert dependencias_sem_lockfile("pyproject.toml", py, {"uv.lock"}) == 0
    assert dependencias_sem_lockfile("x.txt", "", set()) == 0
    assert dependencias_sem_lockfile("package.json", '{"dependencies": 3}', set()) == 0


def test_tempo_hostil():
    t = time.monotonic()
    ler_lockfile("yarn.lock", '"' + "a," * 1_000_000 + ":\n  version \"1\"\n")
    ler_lockfile("yarn.lock", ("a" * 70 + "\n") * 30000 + "\"@" * 500000)
    ler_lockfile("requirements.txt", "a" * 2_000_000)
    ler_lockfile("requirements.txt", "a" + " " * 2_000_000 + "[x")
    ler_lockfile("requirements.txt", "a[" * 1_000_000)
    ler_lockfile("requirements.txt", "x\\\n" * 700_000)
    ler_lockfile("pnpm-lock.yaml", "packages:\n  ? '" + "a/" * 100_000 + "'\n  : x\n")
    assert time.monotonic() - t < 1


def test_modulo_expoe():
    assert lockfiles.Dependencia is Dependencia
