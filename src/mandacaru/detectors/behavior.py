"""Deteccao por comportamento: regras com estado sobre o fluxo de eventos.

Aqui mora a defesa contra malware polimorfico/gerado por IA: o codigo muda,
mas o que ele precisa *fazer* (criptografar em massa, abrir shell a partir
de um servico, ler credenciais) continua igual.
"""
from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from pathlib import PurePath

from ..events import Alert, Event, Severity

SHELLS = {"sh", "bash", "zsh", "dash", "fish", "cmd.exe", "powershell.exe", "pwsh", "pwsh.exe"}
SERVICE_PARENTS = {"nginx", "apache2", "httpd", "php-fpm", "node", "java", "tomcat", "w3wp.exe",
                   "winword.exe", "excel.exe", "outlook.exe", "postgres", "mysqld"}
AI_AGENT_HINTS = ("claude", "mcp", "ollama", "codex", "aider", "copilot", "cursor", "langchain", "autogen")
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "\\appdata\\local\\temp\\", "\\windows\\temp\\")
SENSITIVE = (".ssh/", ".aws/credentials", ".env", ".kube/config", ".docker/config.json",
             "login data", "cookies", "keychain", ".gnupg/", "id_rsa", "id_ed25519", ".netrc",
             ".git-credentials")


def _name(path_or_name: str | None) -> str:
    return PurePath(path_or_name or "").name.lower()


class BehaviorEngine:
    def __init__(self, burst_window: float = 10.0, burst_threshold: int = 25,
                 entropy_threshold: float = 7.2, cooldown: float = 60.0):
        self.burst_window = burst_window
        self.burst_threshold = burst_threshold
        self.entropy_threshold = entropy_threshold
        self.cooldown = cooldown
        self._writes: dict[str, deque] = defaultdict(deque)   # dir -> timestamps de escritas de alta entropia
        self._last_alert: dict[str, float] = {}

    # -- utilitario: evita inundar o usuario com o mesmo alerta
    def _fire(self, key: str, alert: Alert) -> list[Alert]:
        now = time.time()
        if now - self._last_alert.get(key, 0) < self.cooldown:
            return []
        self._last_alert[key] = now
        return [alert]

    def handle(self, ev: Event) -> list[Alert]:
        if ev.kind == "process_start":
            return self._on_process(ev)
        if ev.kind in ("file_write", "file_rename", "file_create"):
            return self._on_file(ev)
        return []

    # ----------------------------------------------------------- processos
    def _on_process(self, ev: Event) -> list[Alert]:
        d = ev.data
        exe = (d.get("exe") or "").lower()
        name = _name(d.get("name") or exe)
        parent = _name(d.get("parent_name"))
        cmd = " ".join(d.get("cmdline") or []).lower()
        ancestry = [_name(a) for a in d.get("ancestry", [])]
        out: list[Alert] = []

        # 1) shell aberto por servico/aplicativo de escritorio
        if name in SHELLS and parent in SERVICE_PARENTS:
            out += self._fire(f"svcshell:{d.get('pid')}", Alert(
                "behavior.service_spawned_shell", Severity.HIGH,
                f"{parent} abriu um shell ({name})",
                {"pid": d.get("pid"), "parent": parent, "cmdline": cmd}, ["T1059", "T1190"]))

        # 2) execucao a partir de diretorio temporario
        if exe and any(t in exe for t in TEMP_DIRS):
            out += self._fire(f"tmpexec:{exe}", Alert(
                "behavior.exec_from_temp", Severity.MEDIUM,
                f"Executavel rodando de pasta temporaria: {exe}",
                {"pid": d.get("pid"), "exe": exe, "cmdline": cmd}, ["T1204"]))

        # 3) shell com conexao de rede ativa (possivel shell reverso)
        if name in SHELLS and d.get("remote_conns"):
            out += self._fire(f"revshell:{d.get('pid')}", Alert(
                "behavior.shell_with_network", Severity.CRITICAL,
                f"Shell {name} com conexao de rede ativa",
                {"pid": d.get("pid"), "conns": d.get("remote_conns")}, ["T1059"]))

        # 4) agente de IA (ou servidor MCP) mexendo em credenciais
        if any(h in a for a in ancestry + [parent, name] for h in AI_AGENT_HINTS):
            hits = [s for s in SENSITIVE if s in cmd]
            if hits:
                out += self._fire(f"agentcred:{d.get('pid')}", Alert(
                    "behavior.ai_agent_credential_access", Severity.HIGH,
                    "Processo iniciado por agente de IA acessando credenciais",
                    {"pid": d.get("pid"), "ancestry": ancestry, "cmdline": cmd, "matched": hits},
                    ["T1552", "T1059"]))
            if name in SHELLS and any(k in cmd for k in ("curl", "wget", "invoke-webrequest", "nc ", "scp ")):
                out += self._fire(f"agentexfil:{d.get('pid')}", Alert(
                    "behavior.ai_agent_network_shell", Severity.MEDIUM,
                    "Agente de IA abriu shell com ferramenta de rede",
                    {"pid": d.get("pid"), "ancestry": ancestry, "cmdline": cmd}, ["T1041"]))
        return out

    # ------------------------------------------------------------ arquivos
    def _on_file(self, ev: Event) -> list[Alert]:
        d = ev.data
        path = d.get("dest") or d.get("path") or ""
        ent = d.get("entropy")
        if ent is None or ent < self.entropy_threshold:
            return []
        folder = os.path.dirname(path)
        q = self._writes[folder]
        q.append(ev.ts)
        while q and ev.ts - q[0] > self.burst_window:
            q.popleft()
        if len(q) >= self.burst_threshold:
            return self._fire(f"ransom:{folder}", Alert(
                "behavior.ransomware_burst", Severity.CRITICAL,
                f"{len(q)} arquivos reescritos com conteudo cifrado em {self.burst_window:.0f}s",
                {"folder": folder, "count": len(q), "last_file": path, "entropy": round(ent, 2)},
                ["T1486"]))
        return []
