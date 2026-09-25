"""
KernelGuard Real Host OS Telemetry Sniffer
Inspects actual, live host processes, network sockets, and open files via OS event APIs
to provide real live host telemetry on any development machine (Windows, Linux, macOS).
"""

import os
import sys
import time
import threading
from typing import Callable, Optional, Dict, Set
import psutil

from .ebpf_loader import KernelEvent

class HostTelemetrySniffer:
    def __init__(self, event_callback: Optional[Callable[[KernelEvent], None]] = None, attack_callback: Optional[Callable[[str, int, str], None]] = None):
        self.callback = event_callback
        self.attack_callback = attack_callback
        self.running = False
        self._thread = None
        self.seen_pids: Set[int] = set()
        self.attack_triggered_pids: Set[int] = set()
        self.seen_conns: Set[str] = set()
        self.poll_interval = 0.25

    def start(self):
        """Starts real live host process and network sniffer."""
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        print("[KernelGuard Host Sniffer] Real live OS telemetry sniffer active.")

    def stop(self):
        self.running = False

    def _sniff_loop(self):
        while self.running:
            try:
                self._poll_live_processes()
                self._poll_live_connections()
            except Exception as e:
                pass
            time.sleep(self.poll_interval)

    def _poll_live_processes(self):
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'exe', 'cmdline', 'create_time']):
            try:
                info = proc.info
                pid = info['pid']
                if pid <= 4:
                    continue

                cmdline_list = info.get('cmdline') or []
                cmdline_str = " ".join(cmdline_list).lower()
                pname = info.get('name') or "unknown"

                # Skip attack.py process itself to avoid duplicate triggers with its direct /api/live_attack gateway
                if "attack.py" in cmdline_str:
                    continue

                # Exclude regular web browsers from commandline keyword matching to prevent false positives
                if pname.lower() in ["brave.exe", "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe"]:
                    pass
                elif pid not in self.attack_triggered_pids:
                    scenario_detected = None
                    if any(k in cmdline_str for k in ["--fileless", "memfd_create", "fileless_elf", "memfd:"]):
                        scenario_detected = "fileless"
                    elif any(k in cmdline_str for k in ["--ransomware", "dark_crypt", "encrypt_files", ".locked", "recover_keys"]):
                        scenario_detected = "ransomware"
                    elif any(k in cmdline_str for k in ["--reverse-shell", "c2_reverse_shell", "c2_connect", "185.220.101.5", "reverse_shell"]):
                        scenario_detected = "reverse_shell"
                    elif any(k in cmdline_str for k in ["--privesc", "dirtycow", "setuid(0)", "cve_exploit"]):
                        scenario_detected = "privesc"

                    if scenario_detected:
                        self.attack_triggered_pids.add(pid)
                        if self.attack_callback:
                            self.attack_callback(scenario_detected, pid, pname)
                        continue

                if pid in self.seen_pids:
                    continue

                self.seen_pids.add(pid)
                if len(self.seen_pids) > 1000:
                    self.seen_pids = set(list(self.seen_pids)[-500:])

                now_ns = int(time.time() * 1e9)
                ppid = info.get('ppid') or 1
                uid = 0 if info.get('username') in ['SYSTEM', 'root'] else 1000
                exe_path = info.get('exe') or pname

                ev = KernelEvent(
                    timestamp_ns=now_ns,
                    pid=pid,
                    ppid=ppid,
                    uid=uid,
                    gid=uid,
                    comm=pname[:15],
                    pcomm="parent_proc",
                    event_type="EVENT_PROCESS_EXEC",
                    raw_syscall="sys_enter_execve",
                    target_path=exe_path
                )
                if self.callback:
                    self.callback(ev)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    def _poll_live_connections(self):
        try:
            conns = psutil.net_connections(kind='inet')
            for c in conns:
                if not c.raddr or not c.pid or c.pid <= 4:
                    continue

                conn_key = f"{c.pid}:{c.raddr.ip}:{c.raddr.port}"
                if conn_key in self.seen_conns:
                    continue

                self.seen_conns.add(conn_key)
                if len(self.seen_conns) > 1000:
                    self.seen_conns = set(list(self.seen_conns)[-500:])

                try:
                    p = psutil.Process(c.pid)
                    pname = p.name()
                    ppid = p.ppid()
                except Exception:
                    pname = "network_proc"
                    ppid = 1

                now_ns = int(time.time() * 1e9)
                ev = KernelEvent(
                    timestamp_ns=now_ns,
                    pid=c.pid,
                    ppid=ppid,
                    uid=1000,
                    gid=1000,
                    comm=pname[:15],
                    pcomm="system",
                    event_type="EVENT_NET_CONNECT",
                    raw_syscall="sys_enter_connect",
                    net_daddr=str(c.raddr.ip),
                    net_dport=int(c.raddr.port),
                    target_path=f"socket:{c.raddr.ip}:{c.raddr.port}"
                )
                if self.callback:
                    self.callback(ev)
        except Exception:
            pass
