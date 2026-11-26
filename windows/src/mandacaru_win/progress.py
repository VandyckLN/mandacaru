"""Frases das barras de progresso ("Verificando 1.234 de 2.900 arquivos · 42% · cerca de 1 min").

Funções puras, sem Qt: o desenho fica em widgets.MandacaruProgressBar.
"""
from __future__ import annotations


def fmt_int(n: int) -> str:
    """1234 -> "1.234" (separador de milhar brasileiro)."""
    return f"{int(n):,}".replace(",", ".")


def pct(done: int, total: int) -> int:
    return min(100, max(0, done * 100 // total)) if total > 0 else 0


def eta_text(elapsed: float, done: int, total: int) -> str:
    """Tempo restante por regra de três; vazio enquanto ainda não dá para estimar bem."""
    if done <= 0 or total <= 0 or done >= total or elapsed < 3:
        return ""
    rest = elapsed * (total - done) / done
    if rest < 45:
        return "menos de 1 min"
    mins = max(1, round(rest / 60))
    if mins < 60:
        return f"cerca de {mins} min"
    h, m = divmod(mins, 60)
    return f"cerca de {h} h {m:02d} min" if m else f"cerca de {h} h"


def _files(total: int) -> str:
    return "arquivo" if total == 1 else "arquivos"


def scan_text(done: int, total: int, eta: str = "") -> str:
    """"Verificando 1.234 de 2.900 arquivos · 42% · cerca de 1 min"."""
    parts = [f"Verificando {fmt_int(done)} de {fmt_int(total)} {_files(total)}", f"{pct(done, total)}%"]
    if eta:
        parts.append(eta)
    return " · ".join(parts)


def scan_done_text(files: int, total: int, completed: bool) -> str:
    if completed:
        return f"Concluída · {fmt_int(files)} {_files(files)} {'verificado' if files == 1 else 'verificados'}"
    if total > 0:  # "1 de 3 arquivos verificados": concorda com o total
        return (f"Interrompida · {fmt_int(files)} de {fmt_int(total)} {_files(total)} "
                f"{'verificado' if total == 1 else 'verificados'}")
    return "Interrompida"


def shred_text(done: int, total: int) -> str:
    """"Destruindo 3 de 10 arquivos · 30%"."""
    return f"Destruindo {fmt_int(done)} de {fmt_int(total)} {_files(total)} · {pct(done, total)}%"


def count_text(done: int, total: int, unit: str) -> str:
    """"3 de 20 programas · 15%"."""
    return f"{fmt_int(done)} de {fmt_int(total)} {unit} · {pct(done, total)}%"


def download_text(got: int, total: int) -> str:
    """"41% · 31 de 74 MB" (total arredondado para cima); sem tamanho conhecido, só "31 MB"."""
    mb = 1024 * 1024
    if total > 0:
        return f"{pct(got, total)}% · {fmt_int(got // mb)} de {fmt_int(-(-total // mb))} MB"
    return f"{fmt_int(got // mb)} MB"


def _pct_arredondado(done: int, total: int) -> int:
    """Como pct, mas arredondado (312 de 900 -> 35); só chega a 100 no fim."""
    if total <= 0:
        return 0
    p = min(100, max(0, round(done * 100 / total)))
    return min(p, 99) if done < total else p


def projeto_text(done: int, total: int) -> str:
    """"Verificando projeto · 312 de 900 arquivos · 35%"."""
    return (f"Verificando projeto · {fmt_int(done)} de {fmt_int(total)} {_files(total)} · "
            f"{_pct_arredondado(done, total)}%")


def consulta_text(n: int) -> str:
    """"Consultando bibliotecas no OSV.dev · 240 pacotes"."""
    return f"Consultando bibliotecas no OSV.dev · {fmt_int(n)} {'pacote' if n == 1 else 'pacotes'}"


def projeto_done_text(arquivos: int, achados: int, completo: bool) -> str:
    """"Projeto verificado · 900 arquivos · 3 achados" ou "Interrompida · 312 arquivos verificados"."""
    if completo:
        return (f"Projeto verificado · {fmt_int(arquivos)} {_files(arquivos)} · "
                f"{fmt_int(achados)} {'achado' if achados == 1 else 'achados'}")
    return f"Interrompida · {fmt_int(arquivos)} {_files(arquivos)} {'verificado' if arquivos == 1 else 'verificados'}"
