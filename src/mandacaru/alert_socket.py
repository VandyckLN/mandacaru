"""Socket de alertas: transmite cada alerta, em tempo real, como uma linha JSON (contrato v1).

So transmite: nada do que o cliente manda e lido. Quem nao acompanha (buffer cheio,
conexao caida) e derrubado; o motor nunca espera nem ve excecao daqui.
A `evidence` fica de fora: traz linhas de comando e PIDs.
"""
from __future__ import annotations

import grp
import json
import os
import socket
import stat
import sys
import threading
from typing import Callable

from .engine import AlertSink
from .events import Alert, Severity

GROUP = "mandacaru"
CONTRACT_VERSION = 1


def _group_gid(name: str) -> int | None:
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        return None


def alert_line(alert: Alert) -> bytes:
    d = {"v": CONTRACT_VERSION, "ts": alert.ts, "severity": alert.severity.name,
         "rule": alert.rule, "summary": alert.summary, "mitre": list(alert.mitre)}
    return json.dumps(d, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"


def _prepare_path(path: str) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(st.st_mode):
        raise FileExistsError(f"{path} existe e nao e um socket")
    os.unlink(path)  # sobra de uma execucao que caiu


def _set_permissions(path: str) -> None:
    gid = _group_gid(GROUP)
    if gid is None:
        os.chmod(path, 0o600)
        print(f"[mandacaru] grupo {GROUP} ausente: socket so para root", file=sys.stderr)
        return
    try:
        os.chown(path, -1, gid)
    except PermissionError:
        os.chmod(path, 0o600)
        print(f"[mandacaru] sem permissao para dar o socket ao grupo {GROUP}: socket so para root", file=sys.stderr)
        return
    os.chmod(path, 0o660)


def socket_sink(path: str, min_sev: Severity) -> tuple[AlertSink, Callable[[], None]]:
    """Abre o socket em `path`. Levanta OSError se o caminho estiver ocupado ou o pai nao existir."""
    _prepare_path(path)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(path)
        _set_permissions(path)
        server.listen(16)
    except BaseException:
        server.close()
        raise
    # timeout: fechar o socket de outra thread nao acorda um accept() parado no Linux
    server.settimeout(0.5)

    clients: list[socket.socket] = []
    lock = threading.Lock()
    stopped = threading.Event()

    def _accept_loop():
        while not stopped.is_set():
            try:
                conn, _ = server.accept()
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                return
            conn.setblocking(False)
            with lock:
                if stopped.is_set():
                    conn.close()
                    return
                clients.append(conn)

    thread = threading.Thread(target=_accept_loop, name="mandacaru-alert-socket", daemon=True)
    thread.start()

    def _sink(alert: Alert):
        try:
            if alert.severity < min_sev or stopped.is_set():
                return
            line = alert_line(alert)
            with lock:
                for c in list(clients):
                    try:
                        c.sendall(line)
                    except OSError:
                        # inclui BlockingIOError: se uma parte da linha ja saiu, o cliente
                        # precisa cair agora para nunca receber meia linha colada na proxima
                        clients.remove(c)
                        c.close()
        except Exception as exc:  # o sink nunca derruba o motor
            print(f"[mandacaru] erro no socket de alertas: {exc}", file=sys.stderr)

    def _stop():
        if stopped.is_set():
            return
        stopped.set()
        thread.join(1.0)
        server.close()
        with lock:
            for c in clients:
                c.close()
            clients.clear()
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass

    return _sink, _stop
