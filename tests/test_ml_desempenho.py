"""Desempenho no hardware real (opt-in): MANDACARU_LENTO=1 pytest tests/test_ml_desempenho.py"""
import os
import statistics
import time
from pathlib import Path

import pytest

from mandacaru.ml.features import extract
from mandacaru.ml.kind import detect_kind

pytestmark = [pytest.mark.lento,
              pytest.mark.skipif(os.environ.get("MANDACARU_LENTO") != "1", reason="defina MANDACARU_LENTO=1")]


def test_latencia_da_extracao_em_programas_reais():
    tempos = []
    for p in sorted(Path("/usr/bin").iterdir())[:600]:
        if not p.is_file() or p.is_symlink():
            continue
        data = p.read_bytes()[: 8 * 1024 * 1024 - 1]
        kind = detect_kind(data)
        if kind is None:
            continue
        t = time.perf_counter()
        extract(kind, data)
        tempos.append(time.perf_counter() - t)
    assert len(tempos) >= 100
    tempos.sort()
    mediana, p99 = statistics.median(tempos), tempos[int(len(tempos) * 0.99)]
    print(f"\n{len(tempos)} arquivos: mediana {mediana * 1000:.1f} ms, p99 {p99 * 1000:.1f} ms")
    assert mediana <= 0.030 and p99 <= 0.150
