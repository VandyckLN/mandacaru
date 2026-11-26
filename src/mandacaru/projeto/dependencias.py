"""Consulta das bibliotecas do projeto no OSV.dev e no CISA KEV.

Só ecossistema, nome e versão saem da máquina; o caminho do arquivo (`origem`) fica local.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from ..events import Severity
from ..vuln import InstalledPackage, KevCache, OsvClient, classify_finding
from ..vuln.scorer import drop_redundant_advisories
from .achado import Achado
from .lockfiles import Dependencia

_MITRE = ("T1195.002",)
_MAX_IDS = 5
_MAX_VERSAO = 64
_MAX_ORIGENS = 5
_ERRO_SEM_REDE = "bibliotecas não verificadas (--sem-rede)"
_ERRO_OSV = "bibliotecas não verificadas (sem conexão com o OSV.dev)"
_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
_SEVERIDADE = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH}


@dataclass
class ResultadoDeps:
    achados: list[Achado]
    verificadas: int
    sem_versao: int
    erro: str | None
    detalhes_faltando: int = 0


def _norm(ecossistema: str, nome: str) -> str:
    return re.sub(r"[-_.]+", "-", nome).lower() if ecossistema == "PyPI" else nome


def _chave_versao(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d{1,18}", v))


def versao_corrigida(vulns: list[dict], ecossistema: str, nome: str) -> str | None:
    """Maior versão `fixed` dos avisos para o pacote, ou None. Tolera dados malformados."""
    alvo = _norm(ecossistema, nome)
    melhor: str | None = None
    melhor_chave: tuple[int, ...] = ()
    for vuln in vulns:
        if not isinstance(vuln, dict) or not isinstance(vuln.get("affected"), list):
            continue
        for af in vuln["affected"]:
            if not isinstance(af, dict) or not isinstance(af.get("package"), dict):
                continue
            pkg = af["package"]
            pnome = pkg.get("name")
            if pkg.get("ecosystem") != ecossistema or not isinstance(pnome, str):
                continue
            if _norm(ecossistema, pnome) != alvo or not isinstance(af.get("ranges"), list):
                continue
            for rng in af["ranges"]:
                if not isinstance(rng, dict) or not isinstance(rng.get("events"), list):
                    continue
                for ev in rng["events"]:
                    fixed = ev.get("fixed") if isinstance(ev, dict) else None
                    if not isinstance(fixed, str) or not fixed or len(fixed) > _MAX_VERSAO:
                        continue
                    chave = _chave_versao(fixed)
                    if chave and (melhor is None or chave > melhor_chave):
                        melhor, melhor_chave = fixed, chave
    return melhor


def _lista_ids(ids: list[str]) -> str:
    texto = ", ".join(ids[:_MAX_IDS])
    return texto + f" +{len(ids) - _MAX_IDS}" if len(ids) > _MAX_IDS else texto


def _kev_cves(kev: KevCache | None) -> set[str]:
    if kev is None:
        return set()
    for offline in (False, True):
        try:
            return set(kev.get_cves(offline_only=offline))
        except Exception:  # noqa: BLE001 - rede/disco: cai para o cache e, por fim, vazio
            continue
    return set()


def _pontuar(vulns: list[dict], nome: str, versao: str, kev_cves: set[str]) -> list:
    pontuadas = []
    for v in vulns:
        try:
            pontuadas.append(classify_finding(v, nome, versao, kev_cves, set()))
        except Exception:  # noqa: BLE001 - aviso com formato inesperado: pula só ele
            continue
    return pontuadas


def _tambem_em(outras: list[str]) -> str:
    if not outras:
        return ""
    mais = f" +{len(outras) - _MAX_ORIGENS}" if len(outras) > _MAX_ORIGENS else ""
    return f" · também em {', '.join(outras[:_MAX_ORIGENS])}{mais}"


def verificar_dependencias(
    deps: list[Dependencia],
    sem_versao: int,
    osv: OsvClient | None,
    kev: KevCache | None,
    ao_consultar: Callable[[int], None] | None = None,
) -> ResultadoDeps:
    grupos: dict[tuple[str, str, str], list[str]] = {}
    for d in deps:
        origens = grupos.setdefault((d.ecossistema, d.nome, d.versao), [])
        if d.origem not in origens:
            origens.append(d.origem)
    if osv is None:
        return ResultadoDeps([], 0, sem_versao, _ERRO_SEM_REDE)

    pacotes = {chave: InstalledPackage(chave[1], chave[1], chave[2], chave[0]) for chave in grupos}
    if ao_consultar is not None:
        ao_consultar(len(pacotes))
    try:
        resposta = osv.query_packages(list(pacotes.values()))
    except Exception:  # noqa: BLE001 - qualquer falha de rede/HTTP/JSON vira aviso, nunca exceção
        return ResultadoDeps([], 0, sem_versao, _ERRO_OSV)

    kev_cves = _kev_cves(kev)
    # Ids do lote (querybatch): um MAL-... conta mesmo se o download do detalhe falhar.
    lote = getattr(osv, "batch_ids", None)
    lote = lote if isinstance(lote, dict) else {}
    achados: list[Achado] = []
    for chave, pkg in pacotes.items():
        vulns = [v for v in resposta.get(pkg, []) if isinstance(v, dict)]
        ids_lote = [i for i in lote.get(pkg, ()) if isinstance(i, str)]
        mal = list(dict.fromkeys(
            [str(v.get("id")) for v in vulns if str(v.get("id", "")).startswith("MAL-")]
            + [i for i in ids_lote if i.startswith("MAL-")]))
        if not vulns and not mal:
            continue
        eco, nome, versao = chave
        origens = grupos[chave]
        caminho = origens[0]
        extra = _tambem_em(origens[1:])
        if mal:
            achados.append(Achado(
                "projeto.dep.malicioso", Severity.CRITICAL, caminho,
                f"{nome} {versao}: pacote catalogado como malicioso ({_lista_ids(mal)}); não instale." + extra,
                mitre=_MITRE, chave=(eco, nome, versao, *sorted(mal))))
            continue
        if versao == "":
            continue
        pontuadas = drop_redundant_advisories(_pontuar(vulns, nome, versao, kev_cves))
        if not pontuadas:
            continue
        ids: list[str] = []
        for p in pontuadas:
            for i in (p.cve_ids or (p.vuln_id,)):
                if i not in ids:
                    ids.append(i)
        em_kev = any(p.in_kev for p in pontuadas)
        if em_kev:
            severidade = Severity.CRITICAL
        else:
            topo = max(pontuadas, key=lambda p: _RANK.get(p.priority, 1)).priority
            severidade = _SEVERIDADE.get(topo, Severity.LOW)
        texto = f"{nome} {versao}: {_lista_ids(ids)}"
        if em_kev:
            texto += " · já explorada (CISA KEV)"
        fix = versao_corrigida(vulns, eco, nome)
        if fix:
            texto += f" · corrigida na versão {fix}"
        todos = {str(v["id"]) for v in vulns if isinstance(v.get("id"), str)} | set(ids_lote)
        achados.append(Achado("projeto.dep.vulneravel", severidade, caminho, texto + extra, mitre=_MITRE,
                              chave=(eco, nome, versao, *sorted(todos))))

    return ResultadoDeps(achados, len(pacotes), sem_versao, None, len(getattr(osv, "errors", []) or []))
