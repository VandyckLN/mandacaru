"""Checklist de credenciais: itens por tipo de ameaça e links oficiais fixos."""
from urllib.parse import urlsplit

import pytest
from mandacaru_win.incident import AMEACAS, IncidentError
from mandacaru_win.incident_cred import CATALOGO, HOSTS_OFICIAIS, ItemCredencial, montar_checklist, url_oficial


def test_links_auditados():
    urls = [u for _texto, u in CATALOGO.values() if u is not None]
    assert urls
    for u in urls:
        p = urlsplit(u)
        assert p.scheme == "https", u
        assert p.hostname in HOSTS_OFICIAIS, u
        assert p.username is None and p.password is None and p.port is None and p.query == "", u


def test_os_seis_provedores_tem_link():
    hosts = {urlsplit(u).hostname for _t, u in CATALOGO.values() if u}
    assert {"github.com", "myaccount.google.com", "account.microsoft.com", "console.aws.amazon.com",
            "docs.npmjs.com", "pypi.org"} <= hosts


def test_itens_sem_link_so_orientam():
    for item_id in ("env", "navegador", "bancos"):
        assert CATALOGO[item_id][1] is None and url_oficial(item_id) is None


@pytest.mark.parametrize("ameaca,destaques", [
    ("projeto", ["ssh", "env", "github_tokens", "npm", "pypi", "aws"]),
    ("malware", ["navegador", "google", "microsoft", "bancos", "ssh"]),
    ("vulnerabilidade", ["navegador", "google", "microsoft"]),
])
def test_destaques_por_ameaca(ameaca, destaques):
    lista = montar_checklist(ameaca)
    assert all(isinstance(i, ItemCredencial) for i in lista)
    assert sorted(i.id for i in lista) == sorted(CATALOGO)           # todos os itens, sem repetir
    assert [i.id for i in lista if i.destaque] == destaques
    assert [i.destaque for i in lista] == sorted((i.destaque for i in lista), reverse=True)
    assert all(i.url == CATALOGO[i.id][1] and i.texto == CATALOGO[i.id][0] for i in lista)


def test_toda_ameaca_tem_checklist():
    for a in AMEACAS:
        assert montar_checklist(a)


def test_ameaca_desconhecida():
    with pytest.raises(IncidentError):
        montar_checklist("ransomware")


def test_url_oficial_so_do_catalogo():
    assert url_oficial("github_tokens") == "https://github.com/settings/tokens"
    assert url_oficial("https://evil.example") is None
    assert url_oficial("nada") is None
