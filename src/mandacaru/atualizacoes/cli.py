"""`mandacaru atualizacoes listar|aplicar`: o que esta desatualizado (apt, Snap, Flatpak) e com qual risco.

Roda a mao, com o usuario da pessoa (o servico nao tem $HOME nem sessao para Snap/Flatpak de usuario).
Nao gera alertas nem popups. Codigos de saida do `listar`: 0 nada de risco alto pendente, 2 ha item
pre-selecionado (CRITICAL_ACTIVE/HIGH), 1 erro. Nesta versao o `aplicar` so atualiza Flatpak do usuario
(sem root); apt, Snap e Flatpak do sistema sao recusados.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from ..config import load_config
from ..vuln.cli import run_vuln_scan
from ..vuln.publish import DEFAULT_REPORT
from .fontes import (
    APT_LISTS,
    ORDEM_RISCO,
    Atualizacao,
    Coleta,
    Runner,
    Which,
    coletar,
    executar,
    nome_valido,
)
from .risco import aplicar_riscos, fontes_dos_binarios, riscos_do_relatorio, riscos_dos_achados

APT_VELHO_SEG = 24 * 3600
SISTEMA_INDISPONIVEL = "atualizacao de pacotes do sistema ainda nao disponivel nesta versao"
PERGUNTA = "Atualizar {n} item(ns)? [s/N] "


def _rodar_no_terminal(argv: list[str]) -> int:
    """O `flatpak update` mostra o progresso direto no terminal da pessoa."""
    try:
        return subprocess.run(argv, check=False).returncode
    except OSError as exc:
        print(f"mandacaru: erro: {argv[0]}: {exc.strerror or exc}", file=sys.stderr)
        return 127


@dataclass
class Ambiente:
    """Tudo que toca o sistema, injetavel nos testes."""
    runner: Runner = executar
    which: Which = shutil.which
    rodar: Callable[[list[str]], int] = _rodar_no_terminal
    entrada: Callable[[str], str] = input
    scan: Callable[..., list] = run_vuln_scan
    agora: Callable[[], float] = time.time
    apt_lists: Path = APT_LISTS


def _cache_padrao() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "mandacaru"


def add_parser(sub) -> None:
    p = sub.add_parser("atualizacoes", help="programas com atualizacao pendente (apt, Snap, Flatpak) e seus riscos")
    s = p.add_subparsers(dest="acmd", required=True)
    li = s.add_parser("listar", help="lista o que tem versao nova e marca com * o que tem falha alta")
    li.add_argument("--completo", action="store_true",
                    help="consulta OSV.dev e CISA KEV agora (usa rede) em vez do ultimo relatorio")
    li.add_argument("--json", dest="as_json", action="store_true", help="saida JSON em stdout")
    ap = s.add_parser("aplicar", help="atualiza os itens escolhidos (nesta versao, so Flatpak do usuario)")
    ap.add_argument("nomes", nargs="*", help="nomes como aparecem no `listar`")
    ap.add_argument("--selecionados", action="store_true", help="os itens marcados com * no `listar`")
    ap.add_argument("--sim", action="store_true", help="nao pede confirmacao")
    for sp in (li, ap):
        sp.add_argument("--relatorio", default=str(DEFAULT_REPORT),
                        help=f"relatorio do ultimo `vuln scan` (padrao: {DEFAULT_REPORT})")
        sp.add_argument("--status-file", default="/var/lib/dpkg/status", help="arquivo dpkg/status")
        sp.add_argument("--cache-dir", default=None,
                        help="cache do --completo (padrao: ~/.cache/mandacaru)")
    p.set_defaults(fn=cmd_atualizacoes)


def _aviso(msg: str) -> None:
    print(f"mandacaru: aviso: {msg}", file=sys.stderr)


def _data(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def _coletar(amb: Ambiente) -> Coleta:
    c = coletar(amb.runner, amb.which, amb.apt_lists)
    for erro in c.erros:
        _aviso(f"consulta falhou: {erro}")
    if c.apt_atualizado_em is not None:
        idade = amb.agora() - c.apt_atualizado_em
        if idade > APT_VELHO_SEG:
            _aviso(f"a lista do apt e de {_data(c.apt_atualizado_em)} (ha {int(idade // 3600)} h); "
                   "rode `sudo apt update` para ver tudo o que esta pendente")
        else:
            print(f"[mandacaru] lista do apt de {_data(c.apt_atualizado_em)}", file=sys.stderr)
    return c


def _com_riscos(args, cfg, amb: Ambiente, itens: list[Atualizacao]) -> tuple[list[Atualizacao], bool]:
    """(itens com risco, houve erro). Sem dado de CVE o item fica DESCONHECIDO e nao e pre-selecionado."""
    if not any(i.gerenciador == "apt" for i in itens):
        return itens, False
    if not cfg.vuln_enabled:
        _aviso("scanner de vulnerabilidades desligado na configuracao; risco nao avaliado")
        return itens, False
    try:
        binario_fonte = fontes_dos_binarios(Path(args.status_file))
    except OSError as exc:
        _aviso(f"nao foi possivel ler {args.status_file} ({exc.strerror or exc}); risco nao avaliado")
        return itens, False

    if getattr(args, "completo", False):
        try:
            achados = amb.scan(
                status_path=Path(args.status_file),
                ecosystem=None,
                cache_dir=Path(args.cache_dir) if args.cache_dir else _cache_padrao(),
                ttl_hours=cfg.vuln_cache_ttl_hours,
                kev_enabled=cfg.vuln_kev_enrichment,
                correlate_running=cfg.vuln_correlate_running_procs,
                alert_min_cvss=cfg.vuln_alert_min_cvss,
            )
        except Exception as exc:  # noqa: BLE001 - rede/cache: a lista sai mesmo assim, sem risco
            print(f"mandacaru: erro no scanner de vulnerabilidades: {exc}", file=sys.stderr)
            return itens, True
        return aplicar_riscos(itens, riscos_dos_achados(achados), binario_fonte), False

    relatorio = Path(args.relatorio)
    try:
        riscos = riscos_do_relatorio(relatorio)
        quando = relatorio.stat().st_mtime
    except FileNotFoundError:
        _aviso(f"sem relatorio de CVEs em {relatorio}; rode com --completo para ver as falhas")
        return itens, False
    except PermissionError:
        _aviso(f"sem permissao para ler {relatorio}; rode com --completo para ver as falhas")
        return itens, False
    except (OSError, ValueError) as exc:
        _aviso(f"relatorio de CVEs ilegivel ({exc}); rode com --completo para ver as falhas")
        return itens, False
    print(f"[mandacaru] riscos do relatorio de {_data(quando)} ({relatorio})", file=sys.stderr)
    return aplicar_riscos(itens, riscos, binario_fonte), False


def _ordenar(itens: list[Atualizacao]) -> list[Atualizacao]:
    return sorted(itens, key=lambda i: (ORDEM_RISCO.get(i.risco, 9), i.gerenciador, i.nome))


def _cves_curto(cves: tuple[str, ...], n: int = 3) -> str:
    if not cves:
        return "-"
    resto = len(cves) - n
    return ",".join(cves[:n]) + (f" (+{resto})" if resto > 0 else "")


def formatar_tabela(itens: list[Atualizacao]) -> str:
    linhas = [("", "GERENCIADOR", "NOME", "INSTALADA", "DISPONIVEL", "RISCO", "CVES")]
    for i in itens:
        linhas.append(("*" if i.selecionado else "", i.gerenciador, i.nome, i.instalada or "?",
                       i.disponivel or "?", i.risco, _cves_curto(i.cves)))
    larguras = [max(len(linha[c]) for linha in linhas) for c in range(len(linhas[0]) - 1)]
    return "\n".join(
        "  ".join(cel.ljust(larguras[c]) for c, cel in enumerate(linha[:-1])) + "  " + linha[-1]
        for linha in linhas
    )


def cmd_listar(args, cfg, amb: Ambiente) -> int:
    c = _coletar(amb)
    if not c.fontes:
        print("mandacaru: erro: nenhum gerenciador de pacotes encontrado (apt, snap, flatpak)", file=sys.stderr)
        return 1
    itens, erro_risco = _com_riscos(args, cfg, amb, c.itens)
    itens = _ordenar(itens)

    if args.as_json:
        print(json.dumps([i.to_dict() for i in itens], ensure_ascii=False, indent=2))
    elif itens:
        print(formatar_tabela(itens))
    marcados = sum(1 for i in itens if i.selecionado)
    if itens:
        print(f"{len(itens)} atualizacao(oes) pendente(s); {marcados} pre-selecionada(s) "
              "(*: risco CRITICAL_ACTIVE ou HIGH).", file=sys.stderr)
    else:
        print("nenhuma atualizacao pendente.", file=sys.stderr)

    if marcados:
        return 2
    return 1 if c.erros or erro_risco else 0


def _escolher(args, cfg, amb: Ambiente, c: Coleta) -> list[Atualizacao] | str:
    """Itens pedidos ou a mensagem de erro. Nomes so casam com o que o `listar` mostrou."""
    if args.selecionados:
        itens, _ = _com_riscos(args, cfg, amb, c.itens)
        return [i for i in itens if i.selecionado]
    escolhidos: list[Atualizacao] = []
    faltando = []
    for nome in args.nomes:
        achados = [i for i in c.itens if nome in (i.nome, i.nome.split("//", 1)[0])]
        if not achados:
            faltando.append(nome)
        escolhidos += [i for i in achados if i not in escolhidos]
    if faltando:
        return f"nenhuma atualizacao pendente para: {', '.join(faltando)}"
    return escolhidos


def cmd_aplicar(args, cfg, amb: Ambiente) -> int:
    if args.selecionados == bool(args.nomes):
        print("mandacaru: erro: use --selecionados ou informe os nomes (nao os dois)", file=sys.stderr)
        return 1
    c = _coletar(amb)
    escolhidos = _escolher(args, cfg, amb, c)
    if isinstance(escolhidos, str):
        print(f"mandacaru: erro: {escolhidos}", file=sys.stderr)
        return 1
    if not escolhidos:
        print("nada a atualizar." if not c.erros else "nada a atualizar (alguma consulta falhou).", file=sys.stderr)
        return 1 if c.erros else 0

    sistema = [i for i in escolhidos if i.gerenciador != "flatpak-usuario"]
    if sistema:
        lista = ", ".join(f"{i.gerenciador} {i.nome}" for i in sistema)
        print(f"mandacaru: erro: {SISTEMA_INDISPONIVEL} ({lista}). Nada foi alterado.", file=sys.stderr)
        return 1

    # revalida antes de virar argumento de comando (defesa em profundidade: o parse ja filtrou)
    if not all(nome_valido(i.gerenciador, i.nome) for i in escolhidos):
        print("mandacaru: erro: nome invalido na lista; nada foi alterado", file=sys.stderr)
        return 1

    print("Flatpak do usuario a atualizar:")
    for i in escolhidos:
        print(f"  {i.nome}  {i.instalada or '?'} -> {i.disponivel or '?'}")
    if not args.sim:
        try:
            resposta = amb.entrada(PERGUNTA.format(n=len(escolhidos)))
        except (EOFError, KeyboardInterrupt):
            resposta = ""
        if resposta.strip().lower() not in ("s", "sim"):
            print("Nada foi alterado.")
            return 0

    rc = amb.rodar(["flatpak", "update", "--user", "-y", *(i.nome for i in escolhidos)])
    if rc != 0:
        print(f"mandacaru: erro: flatpak update saiu com codigo {rc}", file=sys.stderr)
        return 1
    print(f"{len(escolhidos)} item(ns) atualizado(s).")
    return 0


def cmd_atualizacoes(args, amb: Ambiente | None = None) -> int:
    cfg = load_config(args.config)
    amb = amb or Ambiente()
    if args.acmd == "listar":
        return cmd_listar(args, cfg, amb)
    return cmd_aplicar(args, cfg, amb)
