"""Alertas ml.* no scanner estatico: motivos sem conteudo, regras intactas e modo sombra."""
import json
from pathlib import Path

from ml_model import DROPPER, script_classifier

from mandacaru.detectors.static import MAX_BYTES, StaticScanner


# tmp_path fica dentro de /tmp: valor=4.0 (nota ~0.98) passa do alto_tmp de 0.97
def _script_classifier(mode="isolate"):
    return script_classifier(mode, valor=4.0)


def test_scanner_anexa_alerta_ml(tmp_path):
    s = StaticScanner(classifier=_script_classifier())
    f = tmp_path / "x.sh"
    f.write_bytes(DROPPER)
    ml = [a for a in s.scan_file(f) if a.rule.startswith("ml.")]
    assert len(ml) == 1 and ml[0].rule == "ml.malware" and ml[0].severity.name == "HIGH"
    ev = ml[0].evidence
    assert ev["ml_isolate"] is True and ev["kind"] == "sh" and len(ev["motivos"]) <= 5
    assert ev["sha256"] and ev["path"] == str(f)
    assert len(ml[0].summary) <= 200 and ml[0].summary.startswith("IA: x.sh parece malware")
    assert "exemplo.invalid" not in ml[0].summary                      # nada do conteudo
    assert "T1105" in ml[0].mitre


def test_regras_continuam_iguais(tmp_path):
    f = tmp_path / "x.sh"
    f.write_bytes(DROPPER)
    sem = {a.rule for a in StaticScanner().scan_file(f)}
    com = {a.rule for a in StaticScanner(classifier=_script_classifier()).scan_file(f)}
    assert sem and sem <= com and not any(r.startswith("ml.") for r in sem)


def test_modo_sombra_nao_alerta_e_grava(tmp_path):
    got = []
    s = StaticScanner(classifier=_script_classifier("shadow"), shadow_sink=got.append)
    f = tmp_path / "x.sh"
    f.write_bytes(DROPPER)
    assert not [a for a in s.scan_file(f) if a.rule.startswith("ml.")]
    assert got[0]["would_isolate"] is True and got[0]["band"] == "alto"    # o que faria no modo isolate
    json.dumps(got[0])


def test_arquivo_do_tamanho_limite_nao_e_avaliado():
    s = StaticScanner(classifier=_script_classifier())
    assert not [a for a in s.scan_bytes(Path("/x/y.sh"), DROPPER + b"#" * MAX_BYTES) if a.rule.startswith("ml.")]


def test_erro_no_classificador_nao_derruba_as_regras(tmp_path):
    class Quebrado:
        mode = "isolate"

        def score(self, *a, **k):
            raise RuntimeError("bug")

    f = tmp_path / "x.sh"
    f.write_bytes(DROPPER)
    rules = {a.rule for a in StaticScanner(classifier=Quebrado()).scan_file(f)}
    assert rules == {a.rule for a in StaticScanner().scan_file(f)}
