"""
KernelGuard eBPF Loader & Telemetry Dispatcher
Binds to Linux kernel tracepoints via BCC/libbpf if running on Linux with root privileges,
otherwise interfaces seamlessly with the high-fidelity Kernel Telemetry Emulation & Replay subsystem.
"""

import os
import sys
import time
import socket
import struct
from typing import Callable, Optional, Generator
from pydantic import BaseModel, Field

class KernelEvent(BaseModel):
    timestamp_ns: int
    pid: int
    tgid: int = 0
    ppid: int
    uid: int = 1000
    gid: int = 1000
    comm: str
    pcomm: str
    event_type: str
    target_path: Optional[str] = ""
    net_daddr: Optional[str] = ""
    net_dport: Optional[int] = 0
    mem_prot: Optional[str] = ""
    mem_addr: Optional[str] = ""
    ret_val: int = 0
    raw_syscall: str = ""

def format_ipv4(ip_int: int) -> str:
    try:
        return socket.inet_ntoa(struct.pack("<I", ip_int))
    except Exception:
        return "0.0.0.0"

class EBPFLoader:
    def __init__(self, bpf_source_path: Optional[str] = None):
        self.is_linux = sys.platform.startswith("linux")
        self.bpf = None
        self.running = False
        self.bpf_source_path = bpf_source_path or os.path.join(os.path.dirname(__file__), "kernelguard.bpf.c")

    def attach_probes(self, callback: Callable[[KernelEvent], None]) -> bool:
        """
        Attempts to compile and attach BPF tracepoints using BCC if on Linux with root.
        Returns True if successful, False if running on non-Linux or without CAP_BPF/root.
        """
        if not self.is_linux:
            print("[KernelGuard eBPF] Native Linux kernel not detected (running on Windows/Darwin).")
            print("[KernelGuard eBPF] Engaging Telemetry Simulation & Replay Engine.")
            return False

        try:
            from bcc import BPF
            print(f"[KernelGuard eBPF] Compiling and loading eBPF program: {self.bpf_source_path}")
            self.bpf = BPF(src_file=self.bpf_source_path)

            def handle_ringbuf_event(cpu, data, size):
                event_raw = self.bpf["events"].event(data)
                ev = KernelEvent(
                    timestamp_ns=event_raw.timestamp_ns,
                    pid=event_raw.pid,
                    tgid=event_raw.tgid,
                    ppid=event_raw.ppid,
                    uid=event_raw.uid,
                    gid=event_raw.gid,
                    comm=event_raw.comm.decode("utf-8", "replace").strip("\x00"),
                    pcomm=event_raw.pcomm.decode("utf-8", "replace").strip("\x00"),
                    event_type=str(event_raw.event_type),
                    target_path=event_raw.target_path.decode("utf-8", "replace").strip("\x00"),
                    net_daddr=format_ipv4(event_raw.net_daddr),
                    net_dport=event_raw.net_dport,
                    mem_prot=hex(event_raw.mem_prot),
                    mem_addr=hex(event_raw.mem_addr),
                    ret_val=event_raw.ret_val,
                    raw_syscall="ebpf_probe"
                )
                callback(ev)

            self.bpf["events"].open_ring_buffer(handle_ringbuf_event)
            self.running = True
            print("[KernelGuard eBPF] eBPF Ring Buffer attached successfully. Kernel telemetry active.")
            return True
        except ImportError:
            print("[KernelGuard eBPF] BCC (BPF Compiler Collection) not installed. Using emulation fallback.")
            return False
        except Exception as e:
            print(f"[KernelGuard eBPF] Failed to attach BPF probes (likely non-root or missing headers): {e}")
            return False

    def poll(self, timeout_ms: int = 100):
        if self.bpf and self.running:
            self.bpf.ring_buffer_poll(timeout_ms)

    def stop(self):
        self.running = False
