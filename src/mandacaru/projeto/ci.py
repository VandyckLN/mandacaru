"""Familia 5: GitHub Actions inseguro."""
from __future__ import annotations

import re
from pathlib import Path

from ..events import Severity
from . import yamlseguro
from .abrir import baixa_e_executa
from .achado import Achado
from .percurso import linha_do_trecho

_REF_DO_PR = re.compile(r"github\.event\.pull_request\.head|github\.head_ref")
_INJECAO = re.compile(
    r"\$\{\{\s*github\.(?:event\.(?:issue\.(?:title|body)"
    r"|pull_request\.(?:title|body|head\.ref|head\.label)"
    r"|comment\.body|review\.body|review_comment\.body|head_commit\.message|commits)"
    r"|head_ref)"
)
_MAX_PASSOS = 2000


def _eh_workflow(rel: str) -> bool:
    return rel.startswith(".github/workflows/") and rel.endswith((".yml", ".yaml")) \
        and "/" not in rel[len(".github/workflows/"):]


def _gatilhos(doc: dict) -> set[str]:
    on = doc.get("on", doc.get(True))  # YAML 1.1 le `on` como True
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {g for g in on if isinstance(g, str)}
    if isinstance(on, dict):
        return {g for g in on if isinstance(g, str)}
    return set()


def _passos(doc: dict):
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return
    n = 0
    for job in jobs.values():
        passos = job.get("steps") if isinstance(job, dict) else None
        if not isinstance(passos, list):
            continue
        for passo in passos:
            if isinstance(passo, dict):
                n += 1
                if n > _MAX_PASSOS:
                    return
                yield passo


def _linha(texto: str, valor: str) -> int | None:
    for parte in valor.splitlines():
        if parte.strip():
            return linha_do_trecho(texto, parte.strip())
    return None


def verificar(raiz: Path, rel: str, texto: str) -> list[Achado]:
    if not _eh_workflow(rel):
        return []
    doc = yamlseguro.carregar(texto, rel)
    if not isinstance(doc, dict):
        return []
    saida: list[Achado] = []
    alvo_prt = "pull_request_target" in _gatilhos(doc)
    for passo in _passos(doc):
        uses, com, run = passo.get("uses"), passo.get("with"), passo.get("run")
        if alvo_prt and isinstance(uses, str) and (uses == "actions/checkout" or uses.startswith("actions/checkout@")) \
                and isinstance(com, dict):
            ref = com.get("ref")
            if isinstance(ref, str) and _REF_DO_PR.search(ref):
                saida.append(Achado(
                    "projeto.ci.pull_request_target", Severity.HIGH, rel,
                    "pull_request_target com checkout do código do PR: código não confiável "
                    "roda com segredos e permissão de escrita",
                    _linha(texto, ref), ref[:300], ("T1195.002",)))
        if isinstance(run, str):
            if (m := _INJECAO.search(run)):
                saida.append(Achado(
                    "projeto.ci.injecao_expressao", Severity.MEDIUM, rel,
                    "expressão controlada por quem abre o PR/issue usada direto em run: "
                    "(injeção de comandos)",
                    linha_do_trecho(texto, m.group(0)) or _linha(texto, run),
                    run.strip()[:300], ("T1059",)))
            if baixa_e_executa(run):
                saida.append(Achado(
                    "projeto.ci.baixa_e_executa", Severity.MEDIUM, rel,
                    "passo do workflow baixa e executa código remoto",
                    _linha(texto, run), run.strip()[:300], ("T1059",)))
    return saida
