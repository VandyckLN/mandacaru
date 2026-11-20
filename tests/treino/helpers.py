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
