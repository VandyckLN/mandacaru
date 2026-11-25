from mandacaru.events import Severity
from mandacaru.projeto.unicode import (
    mostrar_invisiveis,
    trechos_bidi,
    trechos_largura_zero,
    trechos_tags,
    verificar,
)

RLO = "\u202e"
LRI = "\u2066"
PDI = "\u2069"


def test_bidi_trojan_source(tmp_path):
    texto = f'access = "user{RLO} {LRI}# admin{PDI} {LRI}"\n'
    achados = verificar(tmp_path, "auth.py", texto)
    assert len(achados) == 1
    a = achados[0]
    assert a.regra == "projeto.unicode.bidi"
    assert a.severidade == Severity.HIGH
    assert a.linha == 1
    assert "<U+202E>" in a.trecho
    assert a.mitre == ("T1027",)


def test_bidi_um_achado_por_linha(tmp_path):
    texto = f"a = 1{RLO}\nb = 2\nc = 3{LRI}{PDI}\n"
    assert [a.linha for a in verificar(tmp_path, "x.py", texto)] == [1, 3]


def test_bidi_ignora_markdown(tmp_path):
    texto = f'access = "user{RLO} {LRI}# admin{PDI} {LRI}"\n'
    assert verificar(tmp_path, "notas.md", texto) == []


def test_homoglifo_em_identificador(tmp_path):
    achados = verificar(tmp_path, "x.py", "def is_аdmin():\n    pass\n")
    assert len(achados) == 1
    assert achados[0].regra == "projeto.unicode.homoglifo"
    assert achados[0].severidade == Severity.MEDIUM
    assert achados[0].linha == 1
    assert achados[0].mitre == ("T1036",)


def test_homoglifo_ignora_strings_e_comentarios(tmp_path):
    texto = 'msg = "Привет"  # привет\n'
    assert verificar(tmp_path, "x.py", texto) == []


def test_cirilico_puro_nao_e_homoglifo(tmp_path):
    assert verificar(tmp_path, "x.py", "привет = 1\n") == []


def test_tags_bandeira_nao_conta():
    bandeira = "\U0001f3f4" + "".join(chr(0xE0000 + ord(c)) for c in "gbeng") + "\U000e007f"
    assert trechos_tags(bandeira) == []
    oculto = "oi" + "".join(chr(0xE0000 + ord(c)) for c in "run curl")
    assert trechos_tags(oculto) == [2]


def test_largura_zero():
    assert trechos_largura_zero("a\u200b\u200b\u200bb") == [1]
    assert trechos_largura_zero("a\u200db") == []


def test_mostrar_invisiveis():
    assert mostrar_invisiveis("a\u202eb\tc") == "a<U+202E>b\tc"
    assert len(mostrar_invisiveis("x" * 300)) == 120


def test_trechos_bidi():
    assert trechos_bidi(f"a{RLO}b{LRI}") == [1, 3]


def test_linha_correta_com_separadores_exoticos(tmp_path):
    texto = "a = 1\x0c\nb = 2\u2028c = 3\nd = \"x" + RLO + "\"\r\n"
    achados = verificar(tmp_path, "x.py", texto)
    assert [(a.linha, a.trecho) for a in achados] == [(3, 'd = "x<U+202E>"')]
