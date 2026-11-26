"""Empacotamento: config de exemplo valido, versoes coerentes, unit apontando para o config."""
import re
import struct
from pathlib import Path

import pytest

import mandacaru
from mandacaru.config import Config, load_config
from mandacaru.events import Severity

ROOT = Path(__file__).resolve().parent.parent
# Estes testes leem debian/ e packaging/, que nao existem no diretorio de build do pybuild:
# debian/rules os tira do dh_auto_test (ver test_build_do_deb_ignora_este_arquivo).


def test_config_de_exemplo_e_valido():
    cfg = load_config(ROOT / "packaging" / "config.toml")
    assert cfg == Config(ebpf=True, min_severity=Severity.LOW,
                         json_path="/var/log/mandacaru/alerts.jsonl",
                         socket_path="/run/mandacaru/alerts.sock",
                         rule_dirs=("/etc/mandacaru/rules.d",))
    assert "uso NAO comercial" in (ROOT / "packaging" / "config.toml").read_text()


def test_exemplos_de_endereco_nunca_usam_dominio_registravel():
    # um dominio de exemplo que alguem registre receberia os relatorios de quem copiar o exemplo
    for arq in ("packaging/config.toml", "docs/novidades-0.5.md"):
        texto = (ROOT / arq).read_text()
        hosts = re.findall(r'(?:hub_endpoint|misp_url)\s*=\s*"https?://([^/"]+)', texto)
        hosts += re.findall(r'ex\.:\s*"https?://([^/"]+)', texto)
        assert hosts and all(h.endswith(".invalid") for h in hosts), (arq, hosts)


def test_versao_do_changelog_debian_bate_com_o_pacote():
    first = (ROOT / "debian" / "changelog").read_text().splitlines()[0]
    assert re.match(r"mandacaru \(([^)]+)\)", first).group(1) == mandacaru.__version__


def test_unit_aponta_para_o_config_instalado():
    unit = (ROOT / "debian" / "mandacaru.service").read_text()
    assert "ExecStart=/usr/bin/mandacaru --config /etc/mandacaru/config.toml monitor" in unit


def test_nome_no_pypi_e_changelog_da_versao():
    tomllib = pytest.importorskip("tomllib")
    proj = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert proj["name"] == "mandacaru-edr"
    assert f"## {mandacaru.__version__}" in (ROOT / "CHANGELOG.md").read_text()


def test_build_do_deb_ignora_este_arquivo():
    rules = (ROOT / "debian" / "rules").read_text()
    assert "export PYBUILD_TEST_ARGS = --ignore=tests/test_packaging.py" in rules


def test_unit_protege_o_log_e_nao_reinicia_em_erro_de_config():
    unit = (ROOT / "debian" / "mandacaru.service").read_text()
    assert "LogsDirectoryMode=0750" in unit and "UMask=0027" in unit   # alertas trazem linhas de comando
    assert "RestartPreventExitStatus=1" in unit                        # saida 1 = erro de config: nao adianta reiniciar


def test_unit_cria_o_diretorio_do_socket():
    unit = (ROOT / "debian" / "mandacaru.service").read_text()
    assert "RuntimeDirectory=mandacaru" in unit and "RuntimeDirectoryMode=0755" in unit


def test_postinst_cria_o_grupo_antes_do_debhelper():
    post = (ROOT / "debian" / "mandacaru.postinst").read_text()
    assert "addgroup --system --quiet mandacaru" in post
    assert post.index("addgroup") < post.index("#DEBHELPER#")   # grupo existe antes de o servico subir


def test_control_depende_de_adduser():
    assert "adduser" in (ROOT / "debian" / "control").read_text().split("Package: mandacaru", 1)[1]


def test_yaml_e_dependencia():
    control = (ROOT / "debian" / "control").read_text()
    assert "python3-yaml" in control.split("Package: mandacaru", 1)[1]
    assert "python3-yaml" in control.split("Package: mandacaru", 1)[0]
    assert '"PyYAML>=6"' in (ROOT / "pyproject.toml").read_text().split("dependencies = [", 1)[1].split("]", 1)[0]


def test_icone_e_png_64_indexado_e_leve():
    png = (ROOT / "packaging" / "icons" / "64x64" / "mandacaru.png").read_bytes()
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    largura, altura, _, tipo_cor = struct.unpack(">IIBB", png[16:26])
    assert (largura, altura, tipo_cor) == (64, 64, 3)   # paleta: 1:1 no max-icon-size do mako
    assert b"tRNS" in png                                # fundo transparente
    assert len(png) <= 1024


def test_icone_vai_para_o_hicolor():
    install = (ROOT / "debian" / "mandacaru.install").read_text()
    assert "packaging/icons/64x64/mandacaru.png usr/share/icons/hicolor/64x64/apps/" in install


# --- quarentena (0.4.0) ---

ID_OK = "0123456789abcdef0123456789abcdef"
DECIDE = ROOT / "packaging" / "libexec" / "quarantine-decide"
RELEASE = ROOT / "packaging" / "libexec" / "quarantine-release"


def test_service_tem_state_directory_e_escrita_em_home():
    unit = (ROOT / "debian" / "mandacaru.service").read_text()
    assert "StateDirectory=mandacaru" in unit and "StateDirectoryMode=0755" in unit
    # ProtectHome=read-only venceria um ReadWritePaths=/home (mesmo caminho): /home fica gravavel e so
    # /root e /run/user ficam so leitura (verificado com systemd-run --user no systemd 259)
    linhas = unit.splitlines()
    assert "ProtectHome=no" in linhas and "ReadOnlyPaths=-/root -/run/user" in linhas
    assert not [linha for linha in linhas if linha.startswith(("ProtectHome=read-only", "ProtectHome=yes",
                                                                "ProtectHome=tmpfs", "ReadWritePaths="))]
    assert ("ExecStartPre=+/usr/bin/install -d -m 0750 -o root -g mandacaru /var/lib/mandacaru/quarantine"
            in unit)


def test_timer_de_limpeza_diario_persistente():
    timer = (ROOT / "debian" / "mandacaru.mandacaru-quarantine-clean.timer").read_text()
    assert "OnCalendar=daily" in timer and "Persistent=true" in timer
    assert "WantedBy=timers.target" in timer
    svc = (ROOT / "debian" / "mandacaru.mandacaru-quarantine-clean.service").read_text()
    assert "Type=oneshot" in svc
    assert "ExecStart=/usr/bin/mandacaru --config /etc/mandacaru/config.toml quarentena limpar" in svc
    assert "StateDirectory=mandacaru" in svc and "StateDirectoryMode=0755" in svc
    rules = (ROOT / "debian" / "rules").read_text()
    assert "dh_installsystemd --name=mandacaru-quarantine-clean" in rules


def _acoes_da_policy():
    import xml.etree.ElementTree as ET
    root = ET.parse(ROOT / "packaging" / "polkit" / "io.github.vandyckln.mandacaru.policy").getroot()
    return {a.get("id"): a for a in root.findall("action")}


def test_policy_release_exige_admin():
    acoes = _acoes_da_policy()
    assert set(acoes) == {"io.github.vandyckln.mandacaru.decide", "io.github.vandyckln.mandacaru.release",
                          "io.github.vandyckln.mandacaru.update"}
    for nome, aux in (("decide", "quarantine-decide"), ("release", "quarantine-release"),
                      ("update", "update-packages")):
        acao = acoes[f"io.github.vandyckln.mandacaru.{nome}"]
        for chave in ("allow_any", "allow_inactive", "allow_active"):
            assert acao.find(f"defaults/{chave}").text == "auth_admin"   # decide: so a regra libera o grupo
        exec_path = [a.text for a in acao.findall("annotate")
                     if a.get("key") == "org.freedesktop.policykit.exec.path"]
        assert exec_path == [f"/usr/libexec/mandacaru/{aux}"]


def test_regra_libera_so_decide_para_o_grupo():
    regra = (ROOT / "packaging" / "polkit" / "50-mandacaru.rules").read_text()
    assert 'subject.isInGroup("mandacaru")' in regra
    assert "subject.active" in regra and "subject.local" in regra
    assert "io.github.vandyckln.mandacaru.decide" in regra and "polkit.Result.YES" in regra
    assert "io.github.vandyckln.mandacaru.release" not in regra
    assert "io.github.vandyckln.mandacaru.update" not in regra   # atualizar sempre pede senha de admin


def _roda(script, *args):
    import os
    import subprocess
    env = dict(os.environ, MANDACARU_BIN="echo")
    return subprocess.run(["sh", str(script), *args], capture_output=True, text=True, env=env)


@pytest.mark.parametrize("script,args,codigo", [
    (RELEASE, ("manter", ID_OK), 1),
    (RELEASE, ("analisar", ID_OK), 1),
    (DECIDE, ("confiar", ID_OK), 1),
    (DECIDE, ("apagar", ID_OK), 1),
    (DECIDE, ("limpar",), 1),
    (DECIDE, (), 1),
    (DECIDE, ("manter", ID_OK, "--json"), 1),
    (DECIDE, ("analisar", ID_OK, "--enviar"), 1),
    (RELEASE, ("confiar", ID_OK, "--json"), 1),
    (DECIDE, ("manter", "0123"), 3),
    (DECIDE, ("analisar", ID_OK.upper()), 3),
    (DECIDE, ("analisar", "../../etc/passwd"), 3),
    (RELEASE, ("apagar", ID_OK + "0"), 3),
    (RELEASE, ("confiar", ""), 3),
])
def test_auxiliares_aceitam_so_seus_subcomandos(script, args, codigo):
    r = _roda(script, *args)
    assert r.returncode == codigo
    assert r.stdout == ""                       # nao chegou a chamar o mandacaru
    if codigo == 1:
        assert "uso:" in r.stderr


@pytest.mark.parametrize("script,args", [
    (DECIDE, ("analisar", ID_OK, "--json")),
    (DECIDE, ("analisar", ID_OK)),
    (DECIDE, ("manter", ID_OK)),
    (RELEASE, ("confiar", ID_OK)),
    (RELEASE, ("apagar", ID_OK)),
])
def test_auxiliares_repassam_para_o_mandacaru(script, args):
    r = _roda(script, *args)
    assert r.returncode == 0
    assert r.stdout.split() == ["--config", "/etc/mandacaru/config.toml", "quarentena", *args]


def test_auxiliares_usam_o_binario_instalado_por_padrao():
    for script in (DECIDE, RELEASE):
        texto = script.read_text()
        assert texto.startswith("#!/bin/sh")
        assert "${MANDACARU_BIN:-/usr/bin/mandacaru}" in texto
        assert script.stat().st_mode & 0o755 == 0o755


# --- atualizacoes (auxiliar root com rede, acao update) ---

UPDATE = ROOT / "packaging" / "libexec" / "update-packages"


@pytest.fixture
def stubs(tmp_path):
    """apt-get/snap/flatpak falsos: imprimem o proprio nome, os argumentos e o DEBIAN_FRONTEND."""
    for cmd in ("apt-get", "snap", "flatpak"):
        stub = tmp_path / cmd
        stub.write_text('#!/bin/sh\nprintf "%s\\n" "${0##*/}" "$@" "DF=${DEBIAN_FRONTEND-}"\n')
        stub.chmod(0o755)
    return tmp_path


def _update(stubs, *args):
    import os
    import subprocess
    env = {k: v for k, v in os.environ.items() if k != "DEBIAN_FRONTEND"}
    env["MANDACARU_UPDATE_BINDIR"] = str(stubs)
    return subprocess.run(["sh", str(UPDATE), *args], capture_output=True, text=True, env=env)


@pytest.mark.parametrize("args,esperado", [
    (("apt", "libssl3t64", "g++-13", "php8.3-cli"),
     ["apt-get", "install", "--only-upgrade", "-y", "--", "libssl3t64", "g++-13", "php8.3-cli",
      "DF=noninteractive"]),
    (("snap", "firefox", "core22", "firefox_beta"), ["snap", "refresh", "firefox", "core22", "firefox_beta", "DF="]),
    (("flatpak", "org.mozilla.firefox//stable", "org.freedesktop.Platform.GL.default//24.08", "org.videolan.VLC"),
     ["flatpak", "update", "--system", "-y", "org.mozilla.firefox//stable",
      "org.freedesktop.Platform.GL.default//24.08", "org.videolan.VLC", "DF="]),
])
def test_update_packages_monta_so_o_comando_do_gerenciador(stubs, args, esperado):
    r = _update(stubs, *args)
    assert r.returncode == 0, r.stderr
    assert r.stdout.splitlines() == esperado


@pytest.mark.parametrize("args,codigo", [
    ((), 1),
    (("apt",), 1),                                  # lista vazia
    (("yum", "x"), 1),
    (("apt-get", "x"), 1),
    (("APT", "x"), 1),
    (("apt", "-oAPT::Update::Pre-Invoke::=sh"), 3),
    (("apt", "--reinstall"), 3),
    (("apt", "libssl3", "-y"), 3),                  # um nome ruim no meio derruba a lista toda
    (("apt", "foo;rm"), 3),
    (("apt", "$(x)"), 3),
    (("apt", "`id`"), 3),
    (("apt", ""), 3),
    (("apt", "Libssl3"), 3),
    (("apt", "a b"), 3),
    (("apt", "foo\nbar"), 3),
    (("apt", "../x"), 3),
    (("apt", "x" * 129), 3),
    (("snap", "-a"), 3),
    (("snap", "a--b"), 3),
    (("snap", "a-"), 3),
    (("snap", "123"), 3),
    (("snap", "Firefox"), 3),
    (("snap", "a" * 41), 3),
    (("snap", "firefox_"), 3),
    (("snap", "firefox_a_b"), 3),
    (("snap", "firefox_" + "a" * 11), 3),
    (("flatpak", "org.mozilla"), 3),
    (("flatpak", "org.1x.y"), 3),
    (("flatpak", "-org.x.y"), 3),
    (("flatpak", "--user"), 3),
    (("flatpak", "org.x.y//-b"), 3),
    (("flatpak", "org.x.y//a/b"), 3),
    (("flatpak", "org.x.y//"), 3),
    (("flatpak", "org..x.y"), 3),
    (("flatpak", "org.x.y."), 3),
    (("flatpak", "org.x.$(id)"), 3),
])
def test_update_packages_recusa_nomes_e_uso_invalidos(stubs, args, codigo):
    r = _update(stubs, *args)
    assert r.returncode == codigo
    assert r.stdout == ""                       # nao chegou a chamar o gerenciador
    assert ("uso:" if codigo == 1 else "nome invalido") in r.stderr


def test_update_packages_mesmas_regras_do_python(stubs):
    # o auxiliar e o fontes.py precisam concordar: o que o listar mostra, o auxiliar aceita, e vice-versa
    from mandacaru.atualizacoes.fontes import nome_valido
    casos = {
        "apt": ["libssl3t64", "g++-13", "0ad", "a", "-x", "A", "a_b", "a:amd64", "x" * 128, "x" * 129],
        "snap": ["firefox", "core22", "a-b-c", "x_1", "1a", "a--b", "-a", "a-", "1", "_x", "a" * 40, "a" * 41,
                 "a_" + "b" * 10, "a_" + "b" * 11, "a_B"],
        "flatpak": ["org.x.y", "org.x.y//stable", "org.x.y//24.08", "_a.b.c", "a-b.c.d-e", "org.x", "1.x.y",
                    "org.x.y//", "org.x.y//.a", "org.x.y//_a", "org.x.y/stable", "org.-x.y", "a.b.c//x//y"],
    }
    for ger, nomes in casos.items():
        for nome in nomes:
            r = _update(stubs, ger, nome)
            assert (r.returncode == 0) is nome_valido(ger, nome), (ger, nome, r.stderr)


def test_update_packages_usa_caminhos_fixos_e_e_executavel():
    texto = UPDATE.read_text()
    assert texto.startswith("#!/bin/sh")
    assert "${MANDACARU_UPDATE_BINDIR:-/usr/bin}" in texto
    assert "PATH=/usr/sbin:/usr/bin:/sbin:/bin" in texto and "LC_ALL=C" in texto
    assert UPDATE.stat().st_mode & 0o755 == 0o755
    # so estes tres comandos sao executados
    assert sorted(re.findall(r'exec "\$BINDIR/([\w-]+)"', texto)) == ["apt-get", "flatpak", "snap"]


def test_logrotate_guarda_decisoes_um_ano():
    texto = (ROOT / "debian" / "mandacaru.logrotate").read_text()
    assert "*.jsonl" not in texto                         # senao o decisions.jsonl rodaria duas vezes
    blocos = dict(re.findall(r"(\S+)\s*\{([^}]*)\}", texto))
    assert set(blocos) == {"/var/log/mandacaru/alerts.jsonl", "/var/log/mandacaru/decisions.jsonl",
                           "/var/log/mandacaru/ml-shadow.jsonl"}
    assert "rotate 8" in blocos["/var/log/mandacaru/alerts.jsonl"]
    dec = blocos["/var/log/mandacaru/decisions.jsonl"].split()
    for diretiva in ("weekly", "compress"):
        assert diretiva in dec
    assert dec[dec.index("rotate") + 1] == "52"
    # o DecisionLog reabre o arquivo a cada linha: create basta, e copytruncate perderia linhas
    assert "copytruncate" not in dec
    assert "create 0640 root root" in blocos["/var/log/mandacaru/decisions.jsonl"]
    assert "copytruncate" in blocos["/var/log/mandacaru/alerts.jsonl"].split()


def test_install_leva_polkit_e_auxiliares():
    linhas = (ROOT / "debian" / "mandacaru.install").read_text().splitlines()
    assert "packaging/libexec/quarantine-decide usr/libexec/mandacaru/" in linhas
    assert "packaging/libexec/quarantine-release usr/libexec/mandacaru/" in linhas
    assert "packaging/libexec/update-packages usr/libexec/mandacaru/" in linhas
    assert "packaging/polkit/io.github.vandyckln.mandacaru.policy usr/share/polkit-1/actions/" in linhas
    assert "packaging/polkit/50-mandacaru.rules usr/share/polkit-1/rules.d/" in linhas
    rules = (ROOT / "debian" / "rules").read_text()
    assert "chmod 0755 debian/mandacaru/usr/libexec/mandacaru/quarantine-" in rules
    assert "debian/mandacaru/usr/libexec/mandacaru/update-packages" in rules.split("execute_after_dh_fixperms:")[1]
    assert "chmod 0640 debian/mandacaru/etc/mandacaru/config.toml" in rules


def test_depende_de_polkit():
    control = (ROOT / "debian" / "control").read_text().split("Package: mandacaru", 1)[1]
    assert "polkitd | policykit-1" in control


def test_postinst_fecha_o_config_de_quem_atualiza_de_antes_da_040():
    # o dpkg preserva as permissoes de um conffile modificado: o 0640 do pacote nao chegaria a quem atualiza
    post = (ROOT / "debian" / "mandacaru.postinst").read_text()
    assert 'dpkg --compare-versions "$2" lt 0.4.0~' in post
    assert "chmod 0640 /etc/mandacaru/config.toml" in post
    assert post.index("chmod 0640") < post.index("#DEBHELPER#")
    import subprocess
    assert subprocess.run(["sh", "-n", str(ROOT / "debian" / "mandacaru.postinst")]).returncode == 0


def test_postrm_purge_apaga_o_estado_do_pacote():
    post = (ROOT / "debian" / "mandacaru.postrm").read_text()
    assert post.startswith("#!/bin/sh\nset -e\n")
    assert '[ "$1" = purge ]' in post
    assert "rm -rf /var/lib/mandacaru /var/log/mandacaru" in post
    assert "#DEBHELPER#" in post
    import subprocess
    assert subprocess.run(["sh", "-n", str(ROOT / "debian" / "mandacaru.postrm")]).returncode == 0


def test_usuario_de_rede_consegue_ler_o_config():
    post = (ROOT / "debian" / "mandacaru.postinst").read_text()
    assert "chgrp _mandacaru-net /etc/mandacaru/config.toml" in post
    assert post.index("adduser --system") < post.index("chgrp _mandacaru-net") < post.index("#DEBHELPER#")
    rules = (ROOT / "debian" / "rules").read_text()
    assert "chmod 0640 debian/mandacaru/etc/mandacaru/config.toml" in rules


def test_unit_do_scan_de_cves():
    unit = (ROOT / "debian" / "mandacaru.mandacaru-vuln-scan.service").read_text()
    assert "User=_mandacaru-net" in unit
    assert "SuccessExitStatus=2" in unit                       # achar CVE alta nao e falha do servico
    assert "ExecStartPre=+/usr/bin/mandacaru" in unit and "snapshot-running --output " in unit
    start = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
    assert "--running-file /var/lib/mandacaru/vuln_cache/running.json" in start
    assert "--report /var/lib/mandacaru/vuln_cache/" in start
    assert "--emit-alerts" not in start                       # /var/log/mandacaru e so do root


def test_unit_da_telemetria_separa_fila_e_rede():
    unit = (ROOT / "debian" / "mandacaru.mandacaru-telemetry.service").read_text()
    assert "User=_mandacaru-net" in unit
    assert "ExecStartPre=+/usr/bin/mandacaru --config /etc/mandacaru/config.toml telemetry export" in unit
    assert "ExecStart=/usr/bin/mandacaru --config /etc/mandacaru/config.toml telemetry send" in unit
    assert "ExecStartPost=+/usr/bin/mandacaru --config /etc/mandacaru/config.toml telemetry import" in unit
    assert "StateDirectory=mandacaru/telemetry-spool" in unit  # nunca a pasta da fila do root
    timer = (ROOT / "debian" / "mandacaru.mandacaru-telemetry.timer").read_text()
    assert "WantedBy=timers.target" in timer
    rules = (ROOT / "debian" / "rules").read_text()
    assert "dh_installsystemd --no-enable --no-start --name=mandacaru-telemetry" in rules


def test_relatorio_do_scan_e_o_que_o_monitor_publica():
    from mandacaru.vuln.publish import DEFAULT_REPORT
    unit = (ROOT / "debian" / "mandacaru.mandacaru-vuln-scan.service").read_text()
    assert f"--report {DEFAULT_REPORT}" in unit


def test_instalacao_nao_roda_o_scan_dentro_do_apt():
    rules = (ROOT / "debian" / "rules").read_text()
    assert "dh_installsystemd --no-start --name=mandacaru-vuln-scan" in rules
    post = (ROOT / "debian" / "mandacaru.postinst").read_text()
    assert "deb-systemd-invoke start mandacaru-vuln-scan.timer" in post
    assert "mandacaru-vuln-scan.service" not in post


def test_config_traz_ml_com_modo_comentado():
    txt = (ROOT / "packaging" / "config.toml").read_text()
    assert "[ml]" in txt and '# mode = "shadow"' in txt
    assert load_config(ROOT / "packaging" / "config.toml").ml_mode == "shadow"


def test_logrotate_do_modo_sombra():
    assert "/var/log/mandacaru/ml-shadow.jsonl" in (ROOT / "debian" / "mandacaru.logrotate").read_text()
