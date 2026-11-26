"""Recuperar: relatório do incidente para guardar ou mandar a quem vai ajudar.

HTML autocontido (sem script nem recurso externo, imprimível em PDF) ou JSON. Por padrão oculta
o nome de usuário, o computador e os caminhos pessoais, preservando hashes, regras, técnicas MITRE
e as ações tomadas. Os backups do Desfazer nunca saem no relatório.
"""
from __future__ import annotations

import getpass
import html
import json
import os
import platform
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from mandacaru_win import __version__
from mandacaru_win.incident import Incidente, IncidentError, agora
from mandacaru_win.incident_cred import montar_checklist

TITULO = "Relatório de incidente — Mandacaru"
PERFIL = "%USERPROFILE%"
_PRESERVAR = frozenset({"id", "regra", "sha256", "mitre", "severidade", "tipo", "fase", "modo", "resultado"})
_OUTRO_PERFIL = re.compile(r"""(?i)\b[a-z]:[\\/]users[\\/][^\\/\s"'<>|:*?]+""")
_MIN_NOME = 3

_TIPOS = {"encerrar_processo": "Encerrar processo", "remover_persistencia": "Remover persistência",
          "desfazer": "Desfazer"}
_FASES = {"conter": "Conter", "neutralizar": "Neutralizar", "recuperar": "Recuperar"}
_MODOS = {"automatica": "automática", "guiada": "guiada"}
_RESULTADOS = {"em_andamento": "em andamento", "concluida": "concluída", "parcial": "parcial",
               "falhou": "falhou"}
_ORIGENS = {"varredura": "Varredura", "projeto": "Verificar projeto", "atualizacoes": "Atualizações"}
_AMEACAS = {"malware": "Malware", "projeto": "Projeto armado", "vulnerabilidade": "Falha explorada"}


@dataclass(frozen=True)
class Ambiente:
    perfil: str
    usuario: str
    host: str

    @staticmethod
    def atual() -> Ambiente:
        try:
            usuario = os.environ.get("USERNAME") or getpass.getuser()
        except (OSError, KeyError):
            usuario = ""
        return Ambiente(os.environ.get("USERPROFILE") or str(Path.home()), usuario,
                        os.environ.get("COMPUTERNAME") or platform.node())


def _palavra(nome: str) -> re.Pattern[str]:
    return re.compile(rf"(?i)(?<![0-9a-z_]){re.escape(nome)}(?![0-9a-z_])")


def sanitizar(texto: str, amb: Ambiente) -> str:
    perfil = amb.perfil.rstrip("\\/")
    if perfil:
        partes = re.split(r"[\\/]+", perfil)
        padrao = r"[\\/]+".join(re.escape(p) for p in partes)
        texto = re.sub(rf"""(?i){padrao}(?![^\\/\s"'<>|])""", lambda _m: PERFIL, texto)
    texto = _OUTRO_PERFIL.sub(lambda _m: PERFIL, texto)
    # O host primeiro: "PC-FULANO" contém o usuário "fulano".
    for nome, troca in ((amb.host, "<computador>"), (amb.usuario, "<usuário>")):
        if len(nome) >= _MIN_NOME:
            texto = _palavra(nome).sub(troca, texto)
    return texto


def _limpar(obj: object, amb: Ambiente | None) -> object:
    """Cópia sem backups; com `amb`, sanitiza todo texto fora dos campos técnicos."""
    if isinstance(obj, dict):
        saida = {}
        for k, v in obj.items():
            if k == "backup":
                continue
            saida[k] = v if (k in _PRESERVAR or amb is None) and not isinstance(v, (dict, list)) \
                else _limpar(v, None if k in _PRESERVAR else amb)
        return saida
    if isinstance(obj, list):
        return [_limpar(v, amb) for v in obj]
    if isinstance(obj, str) and amb is not None:
        return sanitizar(obj, amb)
    return obj


def _dados(inc: Incidente, ocultar: bool, amb: Ambiente | None) -> dict:
    amb = amb or Ambiente.atual()
    d = _limpar(asdict(inc), amb if ocultar else None)
    d.update(exportado=agora(), sanitizado=ocultar, gerador=f"Mandacaru {__version__}")
    return d


def exportar_json(inc: Incidente, *, ocultar: bool = True, amb: Ambiente | None = None) -> str:
    return json.dumps(_dados(inc, ocultar, amb), ensure_ascii=False, indent=2)


_CSS = """
body{font-family:"Segoe UI",system-ui,sans-serif;margin:24px auto;max-width:980px;color:#1b1b1b;
background:#fff;line-height:1.45}
h1{color:#1b5e20;font-size:1.6em}h2{border-bottom:2px solid #c8e6c9;padding-bottom:4px;margin-top:28px}
table{border-collapse:collapse;width:100%;font-size:.92em}
th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#e8f5e9}code{font-family:Consolas,monospace;word-break:break-all}
.desfeita{color:#8a6d00}ul{list-style:none;padding-left:0}li{margin:4px 0}
.destaque{font-weight:600}.url{color:#555;font-family:Consolas,monospace;font-size:.9em}
footer{margin-top:32px;color:#555;font-size:.85em}
"""


def _e(v: object) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def _linhas(cab: list[str], linhas: list[list[str]], vazio: str) -> str:
    if not linhas:
        return f"<p>{_e(vazio)}</p>"
    th = "".join(f"<th>{_e(c)}</th>" for c in cab)
    corpo = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in lin) + "</tr>" for lin in linhas)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{corpo}</tbody></table>"


def exportar_html(inc: Incidente, *, ocultar: bool = True, amb: Ambiente | None = None) -> str:
    d = _dados(inc, ocultar, amb)
    achados = [[_e(a.get("severidade")), f"<code>{_e(a.get('regra'))}</code>",
                f"<code>{_e(a.get('caminho'))}</code>", f"<code>{_e(a.get('sha256', ''))}</code>",
                _e(", ".join(a.get("mitre") or []))] for a in d["achados"]]
    acoes = []
    for a in d["acoes"]:
        alvo = " · ".join(f"{k}: {v}" for k, v in (a.get("alvo") or {}).items())
        nome = _e(_TIPOS.get(a["tipo"], a["tipo"]))
        if a.get("desfeita"):
            nome += ' <span class="desfeita">(desfeita)</span>'
        acoes.append([_e(a["data"]), _e(_FASES.get(a["fase"], a["fase"])), nome,
                      _e(_MODOS.get(a["modo"], a["modo"])), _e(_RESULTADOS.get(a["resultado"], a["resultado"])),
                      _e(a["detalhe"]), f"<code>{_e(alvo)}</code>"])
    try:
        checklist = montar_checklist(inc.ameaca)
    except IncidentError:
        checklist = []
    itens = ""
    for i in checklist:
        classe = ' class="destaque"' if i.destaque else ""
        marca = "x" if d["credenciais"].get(i.id) else " "
        url = f' <span class="url">{_e(i.url)}</span>' if i.url else ""
        itens += f"<li{classe}>[{marca}] {_e(i.texto)}{url}</li>"
    aviso = ("Nome de usuário, computador e caminhos pessoais foram ocultados." if d["sanitizado"]
             else "Este relatório contém nome de usuário e caminhos pessoais.")
    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>{_e(TITULO)}</title><style>{_CSS}</style></head>
<body>
<h1>{_e(TITULO)}</h1>
<table><tbody>
<tr><th>Incidente</th><td><code>{_e(d["id"])}</code></td></tr>
<tr><th>Aberto em</th><td>{_e(d["criado"])}</td></tr>
<tr><th>Origem</th><td>{_e(_ORIGENS.get(d["origem"], d["origem"]))}</td></tr>
<tr><th>Ameaça</th><td>{_e(_AMEACAS.get(d["ameaca"], d["ameaca"]))}</td></tr>
{f'<tr><th>Pasta</th><td><code>{_e(d["pasta"])}</code></td></tr>' if d.get("pasta") else ""}
</tbody></table>
<h2>Achados</h2>
{_linhas(["Severidade", "Regra", "Caminho", "SHA-256", "MITRE ATT&CK"], achados, "Nenhum achado registrado.")}
<h2>Linha do tempo</h2>
{_linhas(["Data", "Fase", "Ação", "Modo", "Resultado", "Detalhe", "Alvo"], acoes, "Nenhuma ação registrada.")}
<h2>Credenciais para trocar</h2>
<ul>{itens}</ul>
<footer>{_e(aviso)} Gerado por {_e(d["gerador"])} em {_e(d["exportado"])}.</footer>
</body></html>
"""


def salvar_relatorio(destino: Path, texto: str) -> None:
    """Grava o relatório de forma atômica (arquivo temporário + fsync + troca)."""
    destino = Path(destino)
    tmp = destino.with_name(destino.name + ".tmp")
    try:
        destino.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(texto)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, destino)
    except OSError as e:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise IncidentError(f"Não foi possível salvar o relatório: {e}") from e
