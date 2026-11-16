"""Coletor de processos multiplataforma (psutil, por polling).

E o fallback universal. No Linux com root, o coletor eBPF ve processos de
vida curta que o polling pode perder.
"""
from __future__ import annotations

import queue
import threading
import time

import psutil

from ..events import Event


def describe(proc: psutil.Process) -> dict:
    with proc.oneshot():
        info = {"pid": proc.pid, "ppid": proc.ppid(), "name": proc.name()}
        for key, fn in (("exe", proc.exe), ("cmdline", proc.cmdline), ("user", proc.username)):
            try:
                info[key] = fn()
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                info[key] = None
    ancestry = []
    try:
        for p in proc.parents()[:6]:
            ancestry.append(p.name())
    except (psutil.Error, OSError):
        pass
    info["parent_name"] = ancestry[0] if ancestry else None
    info["ancestry"] = ancestry
    try:
        # net_connections so existe no psutil >= 6; antes disso (Ubuntu 24.04) e connections
        conns = getattr(proc, "net_connections", None) or proc.connections
        info["remote_conns"] = [f"{c.raddr.ip}:{c.raddr.port}" for c in conns(kind="inet") if c.raddr]
    except (psutil.Error, OSError, AttributeError):
        info["remote_conns"] = []
    return info


class ProcessMonitor(threading.Thread):
    def __init__(self, out: queue.Queue, interval: float = 0.5):
        super().__init__(daemon=True, name="procmon")
        self.out, self.interval = out, interval
        self._stop = threading.Event()
        self._seen = {p.pid: p.create_time() for p in psutil.process_iter(["create_time"])}

    def stop(self):
        self._stop.set()

    def run(self):
        while not self._stop.is_set():
            current = {}
            for p in psutil.process_iter(["create_time"]):
                ct = p.info.get("create_time")
                current[p.pid] = ct
                if self._seen.get(p.pid) == ct:
                    continue
                try:
                    self.out.put(Event("process_start", describe(p), source="procmon"))
                except psutil.Error:
                    pass
            self._seen = current
            time.sleep(self.interval)
