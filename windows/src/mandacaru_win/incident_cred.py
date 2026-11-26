"""Recuperar: checklist de credenciais para trocar, com links oficiais fixos.

O Mandacaru nunca lê .env, chaves privadas nem cookies: só lembra o que trocar e aponta a página
oficial. Os links ficam nesta tabela, revisada à mão; a interface só abre o que `url_oficial()`
devolver, e só quando a pessoa clica.
"""
from __future__ import annotations

from dataclasses import dataclass

from mandacaru_win.incident import IncidentError

HOSTS_OFICIAIS = frozenset({
    "github.com", "myaccount.google.com", "account.microsoft.com",
    "console.aws.amazon.com", "docs.npmjs.com", "pypi.org",
})

# id -> (texto, link oficial ou None)
CATALOGO: dict[str, tuple[str, str | None]] = {
    "ssh": ("Gerar novas chaves SSH e remover as antigas do GitHub e dos servidores",
            "https://github.com/settings/keys"),
    "env": ("Trocar os segredos dos arquivos .env (chaves de API, senhas de banco de dados)", None),
    "github_tokens": ("Revogar os tokens de acesso pessoal do GitHub",
                      "https://github.com/settings/tokens"),
    "github_senha": ("Trocar a senha do GitHub e encerrar as sessões abertas",
                     "https://github.com/settings/security"),
    "npm": ("Revogar os tokens do npm", "https://docs.npmjs.com/revoking-access-tokens"),
    "pypi": ("Revogar os tokens de API do PyPI", "https://pypi.org/manage/account/"),
    "aws": ("Desativar e recriar as chaves de acesso da AWS",
            "https://console.aws.amazon.com/iam/home#/security_credentials"),
    "navegador": ("Trocar as senhas salvas no navegador e sair das sessões abertas", None),
    "google": ("Trocar a senha da Conta Google e revisar os dispositivos conectados",
               "https://myaccount.google.com/security"),
    "microsoft": ("Trocar a senha da conta Microsoft e revisar a atividade recente",
                  "https://account.microsoft.com/security"),
    "bancos": ("Avisar o banco e trocar as senhas do internet banking", None),
}

_DESTAQUES = {
    "projeto": ("ssh", "env", "github_tokens", "npm", "pypi", "aws"),
    "malware": ("navegador", "google", "microsoft", "bancos", "ssh"),
    "vulnerabilidade": ("navegador", "google", "microsoft"),
}


@dataclass(frozen=True)
class ItemCredencial:
    id: str
    texto: str
    url: str | None
    destaque: bool


def montar_checklist(ameaca: str) -> list[ItemCredencial]:
    """Todos os itens; os mais prováveis para esta ameaça vêm primeiro, destacados."""
    if ameaca not in _DESTAQUES:
        raise IncidentError(f"Tipo de ameaça desconhecido: {ameaca}")
    destaques = _DESTAQUES[ameaca]
    ordem = [*destaques, *(i for i in CATALOGO if i not in destaques)]
    return [ItemCredencial(i, CATALOGO[i][0], CATALOGO[i][1], i in destaques) for i in ordem]


def url_oficial(item_id: str) -> str | None:
    item = CATALOGO.get(item_id)
    return item[1] if item else None
