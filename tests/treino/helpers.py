"""Ajudantes dos testes do pipeline de treino: so bytes inofensivos."""
import io
import stat

import pyzipper

SENHA = b"infected"


def zip_aes(nome, data, *, senha=SENHA, membros=1, symlink=False) -> bytes:
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, compresslevel=1,
                             encryption=pyzipper.WZ_AES) as z:
        z.setpassword(senha)
        for i in range(membros):
            if symlink:
                zi = z.zipinfo_cls(f"{nome}{i or ''}")
                zi.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(zi, data)
            else:
                z.writestr(f"{nome}{i or ''}", data)
    return buf.getvalue()


def sintetico_script(n=2000, semente=0, *, regra_media=True, separavel=False, categoria_dificil=None,
                     kind="sh", n_tmp=0):
    """Tabela sintetica de scripts: 2 caracteristicas informativas, o resto ruido. Nada de amostra real."""
    import hashlib

    import numpy as np

    from mandacaru.ml.features import SCRIPT_FEATURE_NAMES
    from tools.treino.extrair import Tabela

    rnd = np.random.default_rng(semente)
    dim = len(SCRIPT_FEATURE_NAMES)
    y = (rnd.random(n) < 0.5).astype(np.int8)
    X = rnd.normal(0, 1, (n, dim)).astype(np.float32)
    gap = 6.0 if separavel else 2.5
    X[:, 0] += y * gap
    X[:, 1] += y * (gap / 2)
    sha = tuple(hashlib.sha256(f"{semente}:{i}".encode()).hexdigest() for i in range(n))
    parte = tuple("treino" if i % 10 < 6 else "calibracao" if i % 10 < 8 else "teste" for i in range(n))
    categoria = []
    for i in range(n):
        if y[i] == 1:
            categoria.append("malicioso")
        elif i < n_tmp:
            categoria.append("build_tmp")
        elif categoria_dificil and i % 5 == 0:
            categoria.append(categoria_dificil)
        else:
            categoria.append("geral")
    media = (rnd.random(n) < 0.3) if regra_media else np.zeros(n, dtype=bool)
    return Tabela(X=X, y=y, kind=(kind,) * n, sha=sha, parte=parte, categoria=tuple(categoria),
                  regra_alta=np.zeros(n, dtype=bool), regra_media=media.astype(bool),
                  temporal_teste=np.array([p == "teste" and yy == 1 for p, yy in zip(parte, y, strict=True)]))


def probs_calibracao_legitimos(tr, t):
    """Probabilidades calibradas dos legitimos da metade da calibracao que escolheu os limiares."""

    from tools.treino.treinar import dividir_calibracao, probabilidade

    _, limiar = dividir_calibracao(t)
    m = limiar & (t.y == 0)
    return list(probabilidade(tr, t.X[m]))
