"""Pipeline completo em um comando: higiene -> divisao -> cache de features -> treino -> avaliacao -> exportacao.

Roda dentro do bubblewrap sem rede (Parte B do plano). Imprime so contagens e o resumo do portao; o portao
reprovado nao e erro (o tipo reprovado vai para o pacote em modo alerta, pelo proprio gate_passed).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mandacaru.ml.model import Model, load_model

from .avaliar import avaliar
from .corpus import Corpus
from .exportar import gravar_saida
from .extrair import extrair_cache, montar_tabelas
from .higiene import dividir, remover_conflitos, remover_conhecidos
from .treinar import treinar

_FAMILIAS = ("elf", "script")


def _ler_conhecidos(path: Path | None) -> set[str]:
    if path is None:
        return set()
    return {linha.strip().lower() for linha in path.read_text(encoding="ascii").splitlines() if linha.strip()}


def _anteriores(pasta: Path | None) -> dict[str, Model]:
    if pasta is None:
        return {}
    return {fam: load_model(pasta / f"{fam}.json", expected_sha256=None) for fam in _FAMILIAS
            if (pasta / f"{fam}.json").is_file()}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m tools.treino.pipeline", description="treina o classificador de IA")
    ap.add_argument("--corpus", required=True, type=Path)
    ap.add_argument("--cache", required=True, type=Path)
    ap.add_argument("--saida", required=True, type=Path, help="pasta NOVA do modelo, ex.: ~/saida/<model_id>")
    ap.add_argument("--corte-teste", required=True)
    ap.add_argument("--corte-calibracao", required=True)
    ap.add_argument("--conhecidos", type=Path, default=None, help="hashes que o CIRCL conhece (higiene)")
    ap.add_argument("--anterior", type=Path, default=None, help="pasta com o elf.json/script.json anteriores")
    ap.add_argument("--model-id", default=None, help="padrao: o nome da pasta de saida")
    args = ap.parse_args(argv)
    model_id = args.model_id or args.saida.name
    if args.saida.exists():
        raise FileExistsError(f"{args.saida} ja existe: um modelo anterior nunca e sobrescrito")

    corpus = Corpus(args.corpus)
    entradas = remover_conhecidos(remover_conflitos(corpus.entries()), _ler_conhecidos(args.conhecidos))
    divisao = dividir(entradas, corte_teste=args.corte_teste, corte_calibracao=args.corte_calibracao)
    args.cache.parent.mkdir(parents=True, exist_ok=True)
    cont = extrair_cache(corpus, args.cache)
    print("cache: " + " ".join(f"{k}={v}" for k, v in cont.items()))
    tabelas = montar_tabelas(corpus, divisao, args.cache)
    for fam in _FAMILIAS:
        if len(tabelas[fam].y) == 0 or len(set(tabelas[fam].y.tolist())) < 2:
            print(f"erro: familia {fam} sem as duas classes no corpus", file=sys.stderr)
            return 1

    anteriores = _anteriores(args.anterior)
    treinados = {fam: treinar(tabelas[fam]) for fam in _FAMILIAS}
    portoes = {fam: avaliar(treinados[fam], tabelas[fam], anterior=anteriores.get(fam),
                            legitimos_anteriores=tabelas[fam] if fam in anteriores else None)
               for fam in _FAMILIAS}
    manifesto = sorted(set(divisao.treino) | set(divisao.calibracao) | set(divisao.teste))
    contagens = {f"{fam}_{c}": int((tabelas[fam].y == (1 if c == "maliciosos" else 0)).sum())
                 for fam in _FAMILIAS for c in ("maliciosos", "legitimos")}
    pasta = gravar_saida(args.saida, model_id=model_id, treinados=treinados, tabelas=tabelas, portoes=portoes,
                         manifesto=manifesto, contagens=contagens)
    for fam in _FAMILIAS:
        for kind, p in sorted(portoes[fam].items()):
            situacao = "aprovado" if p.aprovado else "reprovado (" + "; ".join(p.motivos) + ")"
            print(f"{fam}/{kind}: {situacao}")
    print(f"saida: {pasta}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
