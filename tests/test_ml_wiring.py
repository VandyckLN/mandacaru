"""Secao [ml], modo efetivo por comando e ligacao do classificador no monitor e no scan."""
import json
import os
import stat

import pytest

from mandacaru.cli import build_classifier, effective_ml_mode, shadow_writer
from mandacaru.config import Config, ConfigError, load_config


def test_config_ml(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('[ml]\nmode = "isolate"\n')
    assert load_config(p).ml_mode == "isolate"
    assert Config().ml_mode == "shadow" and Config().ml_enabled is True
    p.write_text('[ml]\nmode = "tudo"\n')
    with pytest.raises(ConfigError):
        load_config(p)


@pytest.mark.parametrize("cfg,scan,esperado", [
    (Config(ml_mode="isolate"), False, "isolate"),
    (Config(ml_mode="isolate"), True, "alert"),
    (Config(ml_mode="shadow"), True, "off"),
    (Config(ml_enabled=False, ml_mode="isolate"), False, "off"),
])
def test_modo_efetivo(cfg, scan, esperado):
    assert effective_ml_mode(cfg, for_scan=scan) == esperado


def test_sem_modelo_instalado_fica_desligado_sem_alerta():
    clf, alerta = build_classifier(Config(ml_mode="isolate"), for_scan=False)
    assert clf is None and alerta is None          # Plano 1 nao instala modelo


def test_modelo_invalido_vira_alerta_no_monitor(monkeypatch):
    from mandacaru import ml
    monkeypatch.setattr(ml, "load_default", lambda *a, **k: ml.LoadResult(None, "elf.json: hash diferente", True))
    clf, alerta = build_classifier(Config(), for_scan=False)
    assert clf is None and alerta.rule == "ml.modelo_invalido" and alerta.severity.name == "HIGH"
    assert build_classifier(Config(), for_scan=True) == (None, None)     # scan avulso nao alerta


def test_shadow_writer_cria_0640_e_grava_jsonl(tmp_path):
    p = tmp_path / "ml-shadow.jsonl"
    w = shadow_writer(str(p))
    w({"band": "alto"})
    w({"band": "medio"})
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o640
    assert [json.loads(x)["band"] for x in p.read_text().splitlines()] == ["alto", "medio"]
    assert shadow_writer(str(tmp_path / "nao" / "existe.jsonl")) is None
