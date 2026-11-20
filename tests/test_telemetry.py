"""Testes do pipeline de telemetria segura (sanitizacao LGPD, outbox, MISP e dispatcher)."""
from __future__ import annotations

import json
from pathlib import Path

from mandacaru.config import Config, ConfigError, load_config
from mandacaru.telemetry.dispatcher import TelemetryDispatcher
from mandacaru.telemetry.mappers import build_malwarebazaar_metadata, build_misp_event
from mandacaru.telemetry.outbox import TelemetryOutbox
from mandacaru.telemetry.sanitizer import is_public_ip, is_sample_allowed, sanitize_event_payload, sanitize_text


def test_sanitizer_bloqueia_documentos_pessoais_e_aceita_elf(tmp_path: Path) -> None:
    pdf = tmp_path / "contrato.pdf"
    pdf.write_bytes(b"%PDF-1.7 documento pessoal")
    assert is_sample_allowed(pdf) is False

    env = tmp_path / ".env"
    env.write_bytes(b"SECRET=123")
    assert is_sample_allowed(env) is False

    elf = tmp_path / "dropper"
    elf.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)
    assert is_sample_allowed(elf) is True

    script = tmp_path / "run.sh"
    script.write_bytes(b"#!/bin/sh\necho hi\n")
    assert is_sample_allowed(script) is True


def test_sanitizer_remove_pii_e_segredos() -> None:
    raw = "/home/vandyck/bin/x --password=segredo123 -H 'Authorization: Bearer tok_999' https://u:p@ex.com"
    cleaned = sanitize_text(raw)
    assert "vandyck" not in cleaned
    assert "segredo123" not in cleaned
    assert "tok_999" not in cleaned
    assert "u:p@" not in cleaned
    assert "/home/$USER/bin/x" in cleaned


def test_misp_e_malwarebazaar_mappers_filtram_ips_privados() -> None:
    assert is_public_ip("192.168.1.10") is False
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("93.184.216.34") is True

    event = build_misp_event(
        sha256="a" * 64,
        mime="application/x-elf",
        size_bytes=4096,
        yara_rules=["Linux_ReverseShell_ELF"],
        mitre_techniques=["T1059.004"],
        cmdline="/home/alice/.cache/kworker",
        dst_ips=["10.0.0.5", "93.184.216.34"],
    )
    ips = [a["value"] for a in event["Event"]["Attribute"] if a["type"] == "ip-dst"]
    assert ips == ["93.184.216.34"]
    cmds = [a["value"] for a in event["Event"]["Attribute"] if a["type"] == "text"]
    assert cmds == ["/home/$USER/.cache/kworker"]

    payload = sanitize_event_payload(
        sha256="b" * 64,
        mime="application/x-elf",
        size_bytes=2048,
        yara_rules=["Miner_XMR"],
        mitre_attack=["T1496"],
        dst_ips=["10.1.1.1", "8.8.8.8"],
    )
    assert payload["network_iocs"] == [{"type": "ip-dst", "value": "8.8.8.8"}]
    mb = build_malwarebazaar_metadata(payload)
    assert "elf" in mb["tags"] and "linux" in mb["tags"] and "t1496" in mb["tags"]


def test_outbox_deduplica_e_respeita_aprovacao_opt_in(tmp_path: Path) -> None:
    outbox = TelemetryOutbox(tmp_path / "outbox.db")
    payload = sanitize_event_payload(
        sha256="c" * 64,
        mime="application/x-elf",
        size_bytes=1024,
        yara_rules=["RuleA"],
        mitre_attack=["T1059.004"],
    )
    item_id, created = outbox.enqueue(payload, require_approval=True)
    assert created is True
    item_id2, created2 = outbox.enqueue(payload, require_approval=True)
    assert created2 is False and item_id2 == item_id

    assert outbox.get(item_id).status == "PENDING"
    assert outbox.approve(item_id) is True
    assert outbox.get(item_id).status == "APPROVED"


def test_dispatcher_nao_envia_quando_off_e_envia_para_misp_quando_aprovado(tmp_path: Path) -> None:
    outbox = TelemetryOutbox(tmp_path / "outbox.db")
    payload = sanitize_event_payload(
        sha256="d" * 64,
        mime="application/x-elf",
        size_bytes=512,
        yara_rules=["RuleB"],
        mitre_attack=["T1053.003"],
    )
    item_id, _ = outbox.enqueue(payload, require_approval=False)

    sent_reqs = []

    def fake_http(req, timeout, verify_tls):
        sent_reqs.append((req.full_url, dict(req.header_items()), json.loads(req.data.decode()), verify_tls))
        return 200, b"{}"

    res_off = TelemetryDispatcher(Config(), outbox, http=fake_http).flush()
    assert res_off.sent == 0 and res_off.skipped == 1 and not sent_reqs

    cfg = Config(
        telemetry_level="iocs_only",
        telemetry_misp_enabled=True,
        telemetry_misp_url="https://misp.exemplo.org",
    )
    res_on = TelemetryDispatcher(cfg, outbox, http=fake_http, misp_api_key="chave-secreta").flush()
    assert res_on.sent == 1 and res_on.failed == 0
    assert outbox.get(item_id).status == "SENT"
    assert sent_reqs[0][0] == "https://misp.exemplo.org/events/add"
    assert sent_reqs[0][1]["Authorization"] == "chave-secreta"
    assert "Event" in sent_reqs[0][2]


def test_config_valida_secoes_vuln_e_telemetry(tmp_path: Path) -> None:
    p = tmp_path / "c.toml"
    p.write_text(
        '[vuln]\nalert_min_cvss = 8.5\n'
        '[telemetry]\nlevel = "iocs_only"\ntlp = "tlp:green"\nmisp_enabled = true\n',
        encoding="utf-8",
    )
    cfg = load_config(p)
    assert cfg.vuln_alert_min_cvss == 8.5
    assert cfg.telemetry_level == "iocs_only"
    assert cfg.telemetry_tlp == "TLP:GREEN"
    assert cfg.telemetry_misp_enabled is True

    bad = tmp_path / "bad.toml"
    bad.write_text('[telemetry]\nlevel = "tudo"\n', encoding="utf-8")
    try:
        load_config(bad)
        raise AssertionError("esperava ConfigError")
    except ConfigError as exc:
        assert "telemetry.level" in str(exc)


def _payload(ch: str) -> dict:
    return sanitize_event_payload(sha256=ch * 64, mime="application/x-elf", size_bytes=10,
                                  yara_rules=["R"], mitre_attack=[])


def test_aprovar_so_vale_para_pendente_ou_falho(tmp_path: Path) -> None:
    outbox = TelemetryOutbox(tmp_path / "outbox.db")
    sent, _ = outbox.enqueue(_payload("1"), require_approval=False)
    assert outbox.mark_sent(sent)
    assert outbox.approve(sent) is False and outbox.get(sent).status == "SENT"   # nao reenvia
    assert outbox.reject(sent) is False

    rej, _ = outbox.enqueue(_payload("2"))
    assert outbox.reject(rej)
    assert outbox.approve(rej) is False and outbox.get(rej).status == "REJECTED"  # opt-out e definitivo

    fail, _ = outbox.enqueue(_payload("3"), require_approval=False)
    assert outbox.mark_failed(fail, "timeout")
    assert outbox.approve(fail) is True                                          # nova tentativa
    assert outbox.mark_sent(9999) is False


def test_spool_exporta_envia_e_importa(tmp_path: Path) -> None:
    from mandacaru.telemetry.spool import BATCH, RESULTS, export_batch, import_results, send_batch

    outbox = TelemetryOutbox(tmp_path / "fila" / "outbox.db")
    ok_id, _ = outbox.enqueue(_payload("a"), require_approval=False)
    bad_id, _ = outbox.enqueue(_payload("b"), require_approval=False)
    pend_id, _ = outbox.enqueue(_payload("c"))                                   # nao aprovado: fica
    spool = tmp_path / "spool"
    spool.mkdir()
    cfg = Config(telemetry_level="iocs_only", telemetry_hub_enabled=True,
                 telemetry_hub_endpoint="https://hub.exemplo.org/v1/reports")

    assert export_batch(TelemetryDispatcher(cfg, outbox), spool) == 2

    def fake_http(req, timeout, verify_tls):
        sha = json.loads(req.data)["indicator"]["sha256"]
        return (202, b"") if sha.startswith("a") else (500, b"")

    res = send_batch(TelemetryDispatcher(cfg, None, http=fake_http), spool)  # sem acesso a fila
    assert (res.sent, res.failed) == (1, 1)

    # results.json forjado tentando marcar o item pendente como enviado
    data = json.loads((spool / RESULTS).read_text())
    data["results"].append({"id": pend_id, "ok": True})
    (spool / RESULTS).write_text(json.dumps(data))

    assert import_results(outbox, spool) == (1, 1)
    assert outbox.get(ok_id).status == "SENT"
    assert outbox.get(bad_id).status == "FAILED" and "500" in outbox.get(bad_id).last_error
    assert outbox.get(pend_id).status == "PENDING"
    assert not (spool / RESULTS).exists() and not (spool / BATCH).exists()


def test_spool_desligado_nao_exporta_nada(tmp_path: Path) -> None:
    from mandacaru.telemetry.spool import export_batch

    outbox = TelemetryOutbox(tmp_path / "outbox.db")
    outbox.enqueue(_payload("d"), require_approval=False)
    spool = tmp_path / "spool"
    spool.mkdir()
    assert export_batch(TelemetryDispatcher(Config(), outbox), spool) == 0
    assert json.loads((spool / "batch.json").read_text())["items"] == []


def test_payload_leva_nota_do_modelo_sem_conteudo() -> None:
    from types import SimpleNamespace

    from mandacaru.events import Alert, Severity
    from mandacaru.telemetry.producer import payload_from_case

    case = SimpleNamespace(sha256="a" * 64, size=10, quarantined_at=0.0)
    ml = Alert("ml.malware", Severity.HIGH, "IA: x", {"path": "/home/ana/x", "score": 0.9731, "model_id": "elf-1",
                                                       "motivos": [{"feature": "upx"}]})
    p = payload_from_case(case, [ml], tlp="TLP:CLEAR")
    assert p["detection"]["ml"] == {"model_id": "elf-1", "score": 0.9731}
    assert "/home/ana" not in json.dumps(p)
    assert "ml" not in payload_from_case(case, [], tlp="TLP:CLEAR")["detection"]
