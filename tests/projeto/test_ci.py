import time

import pytest

from mandacaru.events import Severity
from mandacaru.projeto import ci, yamlseguro
from mandacaru.projeto.achado import ArquivoIlegivel

REL = ".github/workflows/ci.yml"

CHECKOUT_PR = """\
on: pull_request_target
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""


def _rodar(projeto, texto, rel=REL):
    raiz = projeto({rel: texto})
    return ci.verificar(raiz, rel, texto)


def test_yaml_bomba_de_alias():
    linhas = ['a: &a ["x","x"]']
    ant = "a"
    for i in range(1, 9):
        nome = chr(ord("a") + i)
        linhas.append(f"{nome}: &{nome} [*{ant},*{ant}]")
        ant = nome
    t0 = time.monotonic()
    with pytest.raises(ArquivoIlegivel):
        yamlseguro.carregar("\n".join(linhas))
    assert time.monotonic() - t0 < 1


def test_yaml_aninhamento_absurdo():
    with pytest.raises(ArquivoIlegivel):
        yamlseguro.carregar("[" * 100_000)


def test_yaml_tags_perigosas_recusadas():
    with pytest.raises(ArquivoIlegivel):
        yamlseguro.carregar("x: !!python/object/apply:os.system ['id']")


def test_pull_request_target_com_checkout_do_pr(projeto):
    (a,) = _rodar(projeto, CHECKOUT_PR)
    assert (a.regra, a.severidade, a.linha) == ("projeto.ci.pull_request_target", Severity.HIGH, 8)
    assert a.mitre == ("T1195.002",)


def test_pull_request_target_sem_checkout_do_pr(projeto):
    t = "on: pull_request_target\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n"
    assert _rodar(projeto, t) == []


def test_checkout_do_pr_sem_pull_request_target(projeto):
    assert _rodar(projeto, CHECKOUT_PR.replace("pull_request_target", "pull_request")) == []


def test_injecao_expressao(projeto):
    t = ("on: push\njobs:\n  b:\n    steps:\n"
         "      - run: echo \"${{ github.event.issue.title }}\"\n")
    (a,) = _rodar(projeto, t)
    assert (a.regra, a.severidade, a.linha) == ("projeto.ci.injecao_expressao", Severity.MEDIUM, 5)
    assert a.mitre == ("T1059",)


def test_injecao_em_bloco_multilinha(projeto):
    t = ("on: push\njobs:\n  b:\n    steps:\n      - run: |\n          echo ok\n"
         "          echo ${{ github.head_ref }}\n")
    (a,) = _rodar(projeto, t)
    assert (a.regra, a.linha) == ("projeto.ci.injecao_expressao", 7)


def test_expressao_inofensiva(projeto):
    t = "on: push\njobs:\n  b:\n    steps:\n      - run: echo ${{ github.sha }}\n"
    assert _rodar(projeto, t) == []


def test_baixa_e_executa_no_run(projeto):
    t = "on: push\njobs:\n  b:\n    steps:\n      - run: curl -fsSL https://x.sh | sh\n"
    (a,) = _rodar(projeto, t)
    assert (a.regra, a.severidade, a.linha) == ("projeto.ci.baixa_e_executa", Severity.MEDIUM, 5)


def test_on_como_lista(projeto):
    t = CHECKOUT_PR.replace("on: pull_request_target", "on: [push, pull_request_target]")
    (a,) = _rodar(projeto, t)
    assert a.severidade is Severity.HIGH


def test_on_como_dicionario(projeto):
    t = CHECKOUT_PR.replace("on: pull_request_target", "on:\n  pull_request_target:\n    types: [opened]")
    (a,) = _rodar(projeto, t)
    assert a.severidade is Severity.HIGH


def test_workflow_invalido(projeto):
    raiz = projeto({REL: "on: [\n"})
    with pytest.raises(ArquivoIlegivel):
        ci.verificar(raiz, REL, "on: [\n")


def test_fora_de_workflows_e_ignorado(projeto):
    assert _rodar(projeto, "on: [\n", rel="outro/ci.yml") == []


@pytest.mark.parametrize("texto", [
    "", "- a\n- b\n", "42", "on: 5\njobs: 7\n", "jobs: [1, 2]\n", "jobs:\n  a: 3\n  b: [x]\n",
    "jobs:\n  a:\n    steps: {x: 1}\n", "jobs:\n  a:\n    steps: [1, null, [a], 'x']\n",
    "on: pull_request_target\njobs:\n  a:\n    steps:\n"
    "      - uses: [1]\n        with: [1]\n        run: {a: 1}\n"
    "      - uses: actions/checkout@v4\n        with: {ref: [1]}\n"
    "      - uses: actions/checkout@v4\n        with: 7\n        run: 9\n",
    "on: {[1]: 2}\n", "? [a]\n: b\n",
])
def test_tipos_hostis_nao_levantam(projeto, texto):
    try:
        assert ci.verificar(projeto({}), REL, texto) == []
    except ArquivoIlegivel:
        pass  # sintaxe invalida e permitido; qualquer outra excecao falha


def test_entrada_hostil_e_rapida(projeto):
    run = "${{ " * 20000 + " " * 50000
    t = "on: push\njobs:\n  b:\n    steps:\n      - run: '" + run + "'\n"
    t0 = time.monotonic()
    _rodar(projeto, t)
    assert time.monotonic() - t0 < 1
