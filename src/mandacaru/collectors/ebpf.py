"""Coletor eBPF (Linux, root): captura todo execve direto do kernel.

Pega processos que vivem milissegundos, que o polling do psutil perde.
Requer o BCC do sistema: `sudo apt install bpfcc-tools python3-bpfcc`.
"""
from __future__ import annotations

import os
import queue
import threading

from ..events import Event

BPF_PROGRAM = r"""
#include <linux/sched.h>
struct data_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    char fname[256];
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t d = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    d.pid = bpf_get_current_pid_tgid() >> 32;
    d.ppid = t->real_parent->tgid;
    bpf_get_current_comm(&d.comm, sizeof(d.comm));
    bpf_probe_read_kernel_str(&d.pcomm, sizeof(d.pcomm), t->real_parent->comm);
    bpf_probe_read_user_str(&d.fname, sizeof(d.fname), args->filename);
    events.perf_submit(args, &d, sizeof(d));
    return 0;
}
"""


def available() -> bool:
    if os.name != "posix" or os.geteuid() != 0:
        return False
    try:
        import bcc  # noqa: F401
        return True
    except ImportError:
        return False


class ExecTracer(threading.Thread):
    def __init__(self, out: queue.Queue):
        super().__init__(daemon=True, name="ebpf-exec")
        from bcc import BPF
        self.out = out
        self.bpf = BPF(text=BPF_PROGRAM)
        self.bpf["events"].open_perf_buffer(self._on_event)
        self._stop = threading.Event()

    def _on_event(self, cpu, data, size):
        e = self.bpf["events"].event(data)
        exe = e.fname.decode(errors="replace")
        cmdline = []
        try:
            with open(f"/proc/{e.pid}/cmdline", "rb") as fh:
                cmdline = [c.decode(errors="replace") for c in fh.read().split(b"\0") if c]
        except OSError:
            pass
        parent = e.pcomm.decode(errors="replace")
        self.out.put(Event("process_start", {
            "pid": e.pid, "ppid": e.ppid, "exe": exe, "name": os.path.basename(exe),
            "cmdline": cmdline, "parent_name": parent, "ancestry": [parent], "remote_conns": [],
        }, source="ebpf"))

    def stop(self):
        self._stop.set()

    def run(self):
        while not self._stop.is_set():
            self.bpf.perf_buffer_poll(timeout=200)
