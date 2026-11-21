"""Higiene e divisoes do corpus: so hashes sinteticos."""
import json

from tools.treino.corpus import Entry
from tools.treino.higiene import conhecidos_circl, dividir, remover_conflitos, remover_conhecidos


def E(sha, label, family="Fam", first_seen="2026-01-01", categoria="geral", package=""):
    return Entry(sha, label, "teste", family, first_seen, "r", categoria, package=package)


def test_conflito_sai_dos_dois_lados():
    e = [E("a" * 64, 1), E("a" * 64, 0), E("b" * 64, 1)]
    assert [x.sha256 for x in remover_conflitos(e)] == ["b" * 64]


def test_conhecidos_saem_so_do_lado_malicioso():
    e = [E("a" * 64, 1), E("c" * 64, 0)]
    assert {x.sha256 for x in remover_conhecidos(e, {"a" * 64, "c" * 64})} == {"c" * 64}


def test_circl_em_lotes_so_com_hashes():
    enviados = []
    def http(url, corpo):
        enviados.append(json.loads(corpo))
        return 200, json.dumps([{"SHA-256": h.upper()} for h in enviados[-1]["hashes"][:1]]).encode()
    hs = [f"{i:064x}" for i in range(2500)]
    assert conhecidos_circl(hs, http=http, lote=1000) == {hs[0], hs[1000], hs[2000]}
    assert [len(e["hashes"]) for e in enviados] == [1000, 1000, 500]


def test_divisao_temporal_sem_familia_fora_do_sorteio_e_benigno_por_pacote():
    mal = [E(f"{i:064x}", 1, family="sem_familia" if i % 4 == 0 else f"F{i % 20}",
             first_seen=f"2026-{1 + i % 12:02d}-01") for i in range(400)]
    leg = [E(f"{i + 10_000:064x}", 0, categoria="go_rust_estatico" if i % 5 == 0 else "geral",
             package=f"pacote_{i % 100}") for i in range(1000)]
    d1 = dividir(mal + leg, corte_teste="2026-10-01", corte_calibracao="2026-08-01")
    d2 = dividir(mal + leg, corte_teste="2026-10-01", corte_calibracao="2026-08-01")
    assert d1 == d2
    assert "sem_familia" not in d1.familias_teste
    assert any(e.family == "sem_familia" and e.sha256 in d1.treino for e in mal)
    todos = set(d1.treino) | set(d1.calibracao) | set(d1.teste)
    assert len(todos) == 1400 and not (set(d1.treino) & set(d1.teste))
    fam_treino = {e.family for e in mal if e.sha256 in d1.treino}
    assert d1.familias_teste and not (set(d1.familias_teste) & fam_treino)
    # arquivos do mesmo pacote ficam na mesma particao
    partes_por_pkg = {}
    for parte_nome, hs in (("treino", d1.treino), ("calibracao", d1.calibracao), ("teste", d1.teste)):
        hs_set = set(hs)
        for e in leg:
            if e.sha256 in hs_set:
                partes_por_pkg.setdefault(e.package, set()).add(parte_nome)
    assert all(len(v) == 1 for v in partes_por_pkg.values())
