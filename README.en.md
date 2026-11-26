[Português](README.md) | **English**

# Mandacaru 🌵

[![CI](https://github.com/VandyckLN/mandacaru/actions/workflows/ci.yml/badge.svg)](https://github.com/VandyckLN/mandacaru/actions/workflows/ci.yml)

Open-source antivirus/EDR (**GPLv3**) built for the new generation of attacks: malware that changes with every generation (written or rewritten by AI), tailor-made phishing, and abuse of AI agents and MCP servers.

> Status: **v0.4**, written in Python, aimed at Linux. It detects, logs, and quarantines detected files (HIGH or above); it does not yet block or kill processes. It also runs on Windows, but without eBPF, service, or quarantine.

## Why another antivirus?

Classic antivirus relies on signatures and hashes. An LLM can generate a thousand variants of the same malware, each with different bytes. Mandacaru relies on what doesn't change: **what the code needs to do** to cause damage.

| Layer | What it detects | How |
|---|---|---|
| Static | obfuscation + decoding + execution, download-and-execute, reverse shells, ransom notes, prompt injection in files | YARA + technique heuristics (not byte patterns) |
| Behavior | mass encryption (ransomware), shell opened by a web service/Office, binary running from `/tmp`, shell with a network connection | stateful rules over events |
| AI agents | agent/MCP server reading `~/.ssh`, `.env`, cloud credentials; agent opening a shell with `curl`/`nc` | process lineage |
| Kernel (Linux) | every `execve`, including processes that live for milliseconds | eBPF (BCC), optional |

## Installation

### Ubuntu 24.04+ / Debian 13+ (recommended: installs the service)

Download the `.deb` from the [Releases page](https://github.com/VandyckLN/mandacaru/releases) and install it:

```bash
sudo apt install ./mandacaru_0.4.0_all.deb
systemctl status mandacaru                      # the service starts on its own
sudo tail -f /var/log/mandacaru/alerts.jsonl    # real-time alerts
```

apt pulls in the dependencies (`python3-yara`, `python3-psutil`, `python3-watchdog`) and, as a recommended package, `python3-bpfcc` for the eBPF collector.

### Scanner only (any Linux)

```bash
pipx install mandacaru-edr
mandacaru scan ~/Downloads
```

On PyPI the package is called `mandacaru-edr`; the command is `mandacaru`. If `pip` needs to compile YARA and complains about `Python.h`, install `python3-dev libssl-dev`.

### Development

```bash
git clone https://github.com/VandyckLN/mandacaru && cd mandacaru
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
# optional, for the eBPF collector (Ubuntu/Debian):
sudo apt install bpfcc-tools python3-bpfcc
```

## Configuration

The service reads `/etc/mandacaru/config.toml`. After editing: `sudo systemctl restart mandacaru`.

```toml
[monitor]
# Without this key: each user's Downloads, Documents, and Desktop, plus /tmp and /dev/shm.
# paths = ["/home/ana/Downloads", "/srv/uploads"]
ebpf = true          # if it doesn't work, falls back to psutil automatically

[alerts]
min_severity = "LOW" # INFO | LOW | MEDIUM | HIGH | CRITICAL
json = "/var/log/mandacaru/alerts.jsonl"
socket = "/run/mandacaru/alerts.sock"  # real-time alerts; "" disables it

[rules]
dirs = ["/etc/mandacaru/rules.d"]   # your .yar rules

[exclude]
paths = []           # absolute-path globs, e.g. "/home/*/.cache/*"
```

Precedence is **command-line flag > file > default**. Use `--config PATH` for a different file. An unknown key or a wrong type makes the command exit with code `1` and a message saying which key.

## Usage

```bash
# scan folders (exit code 2 if there is a HIGH or CRITICAL alert: good for CI)
mandacaru scan ~/Downloads ./projeto

# monitor in real time (Downloads, Documents, /tmp...); with sudo, uses eBPF
mandacaru monitor
sudo mandacaru --json /var/log/mandacaru.jsonl monitor

# your own YARA rules
mandacaru --rules ./minhas-regras scan .
```

Alerts are printed to the terminal and, with `--json`, written as JSON Lines, already tagged with MITRE ATT&CK techniques. This format is suitable for forwarding to Wazuh, Loki, or Elastic.

## Real-time alerts

The service publishes each alert, instantly, on the Unix socket `/run/mandacaru/alerts.sock`. Only root and members of the `mandacaru` group can connect (`0660`). To listen as your own user: `sudo usermod -aG mandacaru $USER` and log in again.

Each alert is one JSON line (contract `v: 1`):

```json
{"v":1,"ts":1794872689.2,"severity":"HIGH","rule":"behavior.revshell","summary":"Shell bash com conexao de rede ativa","mitre":["T1059"]}
```

The `evidence` (command lines, PIDs) does not go out through the socket; it stays only in `alerts.jsonl`, readable by root. The socket is broadcast-only: whatever the client sends is ignored, and a client that doesn't read in time is disconnected.

```bash
socat - UNIX-CONNECT:/run/mandacaru/alerts.sock
```

## Quarantine

When the service sees a new or modified file in a watched folder and the static scan (YARA or heuristic) reports severity `HIGH` or above, the file is moved to `/var/lib/mandacaru/quarantine/`, scrambled so it doesn't trigger other antivirus tools. The alert includes the `quarantine_id`. Behavior alerts (ransomware, reverse shell, etc.) only alert; nothing is isolated because of them. A standalone `mandacaru scan` also only reports.

For each isolated file there are three choices:

| Choice | Popup button (`pkexec`) | Who can |
|---|---|---|
| **Analyze** (`analisar`): looks up the hash in public services and shows the verdict | `/usr/libexec/mandacaru/quarantine-decide analisar <id>` | `mandacaru` group, no password |
| **Keep isolated** (`manter`): records the decision; the file is deleted when the retention period ends | `/usr/libexec/mandacaru/quarantine-decide manter <id>` | `mandacaru` group, no password |
| **I trust it** (`confiar`): puts the file back in place and stops isolating that hash | `/usr/libexec/mandacaru/quarantine-release confiar <id>` | administrator password only |

With no answer, the safe side wins: the file stays isolated and a daily timer (`mandacaru-quarantine-clean.timer`) deletes it after `retention_days` (30 days by default). polkit asks for a password only where needed: malware running in your session can't release itself. The helpers accept only the subcommands for their level and an id of 32 hexadecimal characters. In the terminal, the same commands run with `sudo`:

```bash
mandacaru quarentena listar                       # mandacaru group: id, date, file, rule, days until deletion
sudo mandacaru quarentena analisar <id>           # only the hash leaves the machine
sudo mandacaru quarentena analisar <id> --enviar  # uploads the file to VirusTotal (asks for a key and confirmation)
sudo mandacaru quarentena manter <id>
sudo mandacaru quarentena confiar <id>            # restores and adds the hash to the trust list
sudo mandacaru quarentena apagar <id>             # deletes now, without waiting for the retention period
sudo mandacaru quarentena desconfiar <sha256>     # removes the hash from the trust list
```

Exit codes: `0` ok, `1` usage or configuration, `3` id does not exist or is already resolved, `4` quarantine tampered with. Every decision is written to `/var/log/mandacaru/decisions.jsonl` (readable only by root), including who made it.

Analysis works out of the box, with no setup, using Team Cymru MHR and CIRCL hashlookup (free, no key). With keys in the config, it also uses MalwareBazaar and VirusTotal:

```toml
[quarantine]
enabled = true
min_severity = "HIGH"
retention_days = 30
max_file_mb = 256
max_total_mb = 2048

[analysis]
cymru = true
# virustotal_key = ""
# malwarebazaar_key = ""
```

> **Warning:** Team Cymru MHR is free for **non-commercial use** only. In a company, turn it off with `analysis.cymru = false`.

`config.toml` is installed as `0640`, because it may hold API keys. A non-root user running without `--config` (for example `mandacaru scan` or `quarentena listar`) gets a warning and continues with the default configuration; an unreadable `--config` or an invalid config is still an error.

## Check a project (developers)

Before opening a downloaded repository in your editor or running `npm install`, see what it does on its own:

```bash
mandacaru dev ./project            # online: queries OSV.dev and CISA KEV
mandacaru dev ./project --sem-rede # files only, nothing leaves the machine
mandacaru --json findings.jsonl dev ./project
```

- **Instructions for AI agents**: `AGENTS.md`, `CLAUDE.md`, `.cursorrules` and friends containing prompt-injection phrases, requests to send secrets out, hidden HTML comments or invisible Unicode.
- **Runs when the folder is opened**: VS Code `folderOpen` tasks, MCP servers, Claude Code hooks and broad permissions, devcontainers and Git hooks.
- **Runs when dependencies are installed**: npm `postinstall`/`preinstall`, `setup.py` and local build backends.
- **Deceptive Unicode in code**: bidirectional characters and homoglyphs in source files (Trojan Source).
- **GitHub Actions**: unsafe `pull_request_target`, expression injection and steps that download and run remote code.
- **Libraries**: versions pinned in lockfiles (npm, pnpm, yarn, Poetry, uv, Pipenv, `requirements*.txt`) and MCP server packages, checked against OSV.dev and CISA KEV.

What leaves the machine: only the ecosystem, name and version of each library, sent to OSV.dev (the KEV catalog is downloaded whole). No paths, file contents or user names. With `--sem-rede` ("no network") nothing is sent and no cache is written; `--cache-dir` changes the cache folder.

Exit code: `0` when there is no `HIGH` or `CRITICAL` finding (medium findings and the "Para conhecimento" ones do not block), `2` when there is, and `1` for a usage error such as a missing folder.

## Vulnerabilities (CVEs)

> Full guide, with diagrams and FAQ (in Portuguese): [docs/novidades-0.5.md](docs/novidades-0.5.md).

A daily timer (`mandacaru-vuln-scan.timer`) cross-references the installed packages (`/var/lib/dpkg/status`) with [OSV.dev](https://osv.dev) and the CISA Known Exploited Vulnerabilities catalog (KEV). Only the name and version of source packages leave the machine; no user, path, or hostname.

| Priority | When |
|---|---|
| `CRITICAL_ACTIVE` | CVSS ≥ `alert_min_cvss` (or in KEV) **and** the package is loaded in some process right now |
| `HIGH` | CVSS ≥ `alert_min_cvss`, high distro priority, or CVE in KEV |
| `MEDIUM` | CVSS ≥ 4, medium distro priority, or a security advisory (USN/DSA) with a pending update |
| `LOW` | everything else |

New `HIGH` and `CRITICAL_ACTIVE` findings arrive as `vuln.cve_local` alerts in `alerts.jsonl` and on the socket (popup). A CVE that has already been reported isn't repeated the next day; more than 5 new ones at once become a single summary alert. The full report of the last run is in `/var/lib/mandacaru/vuln_cache/last-scan.json`.

```bash
mandacaru vuln scan --cache-dir ~/.cache/mandacaru     # right now, as your user (exits 2 if there is a HIGH)
mandacaru vuln scan --cache-dir ~/.cache/mandacaru --json > cves.json
sudo systemctl start mandacaru-vuln-scan.service       # forces the service to run
```

The network scan runs as the `_mandacaru-net` user, with no capabilities and a read-only filesystem. The only part that needs root, checking which libraries are loaded in `/proc`, runs beforehand, with no network, and hands over only the list of packages.

```toml
[vuln]
enabled = true
cache_ttl_hours = 24
kev_enrichment = true
correlate_running_procs = true
alert_min_cvss = 7.0
```

## Telemetry (opt-in)

Off by default. When on, each file isolated by the quarantine becomes a report in the local queue `/var/lib/mandacaru/telemetry/outbox.db` (root only): hash, size, type (ELF, script...), YARA rules, MITRE techniques, distro, and architecture. Never a path, user, hostname, `machine-id`, or internal IP. Nothing leaves until you approve it:

```bash
sudo mandacaru telemetry status
sudo mandacaru telemetry review             # what will be sent, item by item (--json shows everything)
sudo mandacaru telemetry approve <id>       # or reject <id>; a sent or rejected item does not return to the queue
sudo systemctl enable --now mandacaru-telemetry.timer   # hourly upload of what was approved
```

Destinations: your own MISP (compatible with CSIRTs such as CERT.br; the key lives only in `/etc/mandacaru/secrets.env`, as `MANDACARU_MISP_API_KEY=...`) and the Mandacaru Threat Hub. Uploading runs as `_mandacaru-net`: it receives only a copy of the approved items and returns the result, with no access to the queue or the quarantine.

```toml
[telemetry]
level = "off"              # off | iocs_only | samples_elf (marks ELF/scripts as eligible samples)
require_approval = true
tlp = "TLP:CLEAR"          # TLP:CLEAR | TLP:GREEN
max_sample_mb = 15
hub_enabled = false
hub_endpoint = ""
misp_enabled = false
misp_url = ""
misp_verify_tls = true
```

## AI classifier (in preparation)

A second judge, besides the rules: a small decision-tree model that runs **on the machine itself** (no internet, no cost, ~13 ms per file) and scores every new ELF program and script in the watched folders. Full guide, with examples (in Portuguese): [docs/novidades-0.6.md](docs/novidades-0.6.md).

This version ships the complete engine, but **no model is installed yet**: the model is trained in an isolated environment and will arrive in a later version. Until then, Mandacaru works exactly as before.

```toml
[ml]
enabled = true
# mode = "shadow"   # off | shadow (only logs what it would do) | alert (alerts) | isolate (isolates)
```

```bash
mandacaru ml status              # installed models, approved types, and mode
mandacaru ml avaliar ARQUIVO     # score, band, and reasons for a file (does not isolate)
sudo mandacaru ml sombra         # what the model would have isolated in shadow mode
```

The model **never releases anything**: it only adds suspicion. It doesn't override rules, doesn't touch the trust list, and doesn't take files out of quarantine; releasing still requires "I trust it" with an administrator password.

## Architecture

```
collectors (procmon | ebpf | fsmon) ──► queue ──► Engine ──► detectors (static | behavior) ──► sinks (console | jsonl | socket)
```

- `collectors/`: produce `Event`s. `procmon` uses psutil (cross-platform), `ebpf` uses an `execve` tracepoint (Linux, root), and `fsmon` uses watchdog (inotify/ReadDirectoryChanges).
- `detectors/static.py`: YARA + heuristics. It only flags obfuscation when encoded content, decoding, and dynamic execution appear **together**.
- `detectors/behavior.py`: rules with a time window and a *cooldown* so the user isn't flooded.
- `rules/yara/base.yar`: base rules.
- `vuln/`: dpkg inventory, OSV.dev client with SQLite cache, CISA KEV cache, local CVSS 3.1, and publishing of findings to the monitor.
- `ml/`: local classifier (content-based type detection, ELF reader, features, strict-JSON model, reasons, band-based decision, `ml` commands).
- `telemetry/`: sanitization (LGPD), queue with approval, producer wired to the quarantine, root ↔ `_mandacaru-net` spool, and upload to MISP/Threat Hub.

## Tests and false positives

```bash
pytest -q          # 408 tests (+1 optional performance test), with harmless samples that imitate the techniques
```

A scan of about 91,000 legitimate files (Python stdlib, dist-packages, and `/usr/share`): **0 HIGH/CRITICAL alerts**. That left 1 MEDIUM (documentation containing `curl | bash`) and 1 LOW (large JS bundle).

## Roadmap

- [ ] Response actions: suspend a process (`SIGSTOP`)
- [x] Quarantine of detected files, with the user's decision via polkit
- [ ] Local anomaly model (IsolationForest over lineage, network, and files), without sending data to the cloud
- [ ] eBPF for `openat` on sensitive files and `connect` (network)
- [ ] Classifier for LLM-generated scripts (AST features + entropy)
- [ ] Protection of the agent itself: Rust binary, rule signing
- [ ] Windows collector via ETW
- [x] systemd service + `.deb` package
- [x] Daily CVE audit of installed packages (OSV.dev + CISA KEV), prioritizing what is running
- [x] Opt-in telemetry with manual approval to MISP/Threat Hub
- [ ] Upload of ELF samples to the Threat Hub (today only the eligibility flag)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security flaws: [SECURITY.md](SECURITY.md).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE). Anyone who distributes modified versions must publish the source code.
