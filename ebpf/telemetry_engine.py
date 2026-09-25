"""
KernelGuard High-Fidelity Telemetry Engine
Generates realistic Linux kernel telemetry streams representing both benign background noise
and sophisticated malware attack vectors (Fileless, Ransomware, C2 Reverse Shell, PrivEsc).
"""

import time
import random
import threading
from typing import List, Dict, Generator, Optional, Callable
from .ebpf_loader import KernelEvent

class TelemetryEngine:
    def __init__(self, event_callback: Optional[Callable[[KernelEvent], None]] = None):
        self.callback = event_callback
        self.running = False
        self._thread = None
        self._rate_hz = 5 # events per second during idle background

    def generate_benign_event(self) -> KernelEvent:
        """Simulates typical benign Linux OS background operations."""
        benign_profiles = [
            # Nginx web server
            {
                "comm": "nginx", "pcomm": "systemd", "pid": 1102, "ppid": 1,
                "event_type": "EVENT_NET_CONNECT", "raw_syscall": "sys_enter_connect",
                "net_daddr": f"10.0.0.{random.randint(10, 50)}", "net_dport": 80,
                "target_path": "/var/log/nginx/access.log", "uid": 33
            },
            # Git commit / build
            {
                "comm": "gcc", "pcomm": "make", "pid": random.randint(4000, 4999), "ppid": 3998,
                "event_type": "EVENT_FILE_OPEN", "raw_syscall": "sys_enter_openat",
                "target_path": f"/usr/src/app/obj_{random.randint(1, 20)}.o", "uid": 1000
            },
            # Cron task
            {
                "comm": "cron", "pcomm": "systemd", "pid": 845, "ppid": 1,
                "event_type": "EVENT_PROCESS_EXEC", "raw_syscall": "sys_enter_execve",
                "target_path": "/usr/sbin/logrotate", "uid": 0
            },
            # Systemd journald
            {
                "comm": "systemd-journal", "pcomm": "systemd", "pid": 412, "ppid": 1,
                "event_type": "EVENT_FILE_WRITE", "raw_syscall": "sys_enter_write",
                "target_path": "/var/log/journal/system.journal", "uid": 0
            },
            # Python standard app
            {
                "comm": "python3", "pcomm": "bash", "pid": 2840, "ppid": 2810,
                "event_type": "EVENT_FILE_OPEN", "raw_syscall": "sys_enter_openat",
                "target_path": "/usr/lib/python3.11/json/__init__.py", "uid": 1000
            }
        ]
        profile = random.choice(benign_profiles)
        now_ns = int(time.time() * 1e9)
        return KernelEvent(
            timestamp_ns=now_ns,
            pid=profile["pid"],
            ppid=profile["ppid"],
            uid=profile["uid"],
            gid=profile["uid"],
            comm=profile["comm"],
            pcomm=profile["pcomm"],
            event_type=profile["event_type"],
            raw_syscall=profile["raw_syscall"],
            target_path=profile.get("target_path", ""),
            net_daddr=profile.get("net_daddr", ""),
            net_dport=profile.get("net_dport", 0),
            mem_prot=profile.get("mem_prot", "0x0"),
            mem_addr=profile.get("mem_addr", "0x0"),
            ret_val=0
        )

    def generate_attack_scenario(self, scenario_name: str, target_pid: Optional[int] = None, comm: Optional[str] = None) -> List[KernelEvent]:
        """
        Synthesizes causal attack sequences as intercepted by eBPF tracepoints.
        Supports custom host PID and process name binding for live interactive demos.
        """
        now = time.time()
        events: List[KernelEvent] = []

        if scenario_name == "fileless":
            # Scenario 1: Fileless In-Memory ELF Execution
            # curl | bash -> memfd_create -> mprotect(RWX) -> connect C2
            pid_malware = target_pid if target_pid else 6122
            pid_bash = max(pid_malware - 1, 1001)
            pid_curl = max(pid_malware - 2, 1000)
            comm_mal = (comm[:15] if comm else "kworker_daemon")

            # 1. Spawn curl
            events.append(KernelEvent(
                timestamp_ns=int((now + 0.05) * 1e9),
                pid=pid_curl, ppid=pid_bash, uid=1000,
                comm="curl", pcomm="bash",
                event_type="EVENT_PROCESS_EXEC", raw_syscall="sys_enter_execve",
                target_path="/usr/bin/curl"
            ))
            # 2. Curl connects to staging server
            events.append(KernelEvent(
                timestamp_ns=int((now + 0.15) * 1e9),
                pid=pid_curl, ppid=pid_bash, uid=1000,
                comm="curl", pcomm="bash",
                event_type="EVENT_NET_CONNECT", raw_syscall="sys_enter_connect",
                net_daddr="185.193.64.12", net_dport=80
            ))
            # 3. Create anonymous in-memory file descriptor (memfd_create)
            events.append(KernelEvent(
                timestamp_ns=int((now + 0.30) * 1e9),
                pid=pid_bash, ppid=pid_bash, uid=1000,
                comm="bash", pcomm="systemd",
                event_type="EVENT_MEMFD_CREATE", raw_syscall="sys_enter_memfd_create",
                target_path="memfd:kworker_daemon_elf"
            ))
            # 4. Allocate executable memory / W^X violation
            events.append(KernelEvent(
                timestamp_ns=int((now + 0.45) * 1e9),
                pid=pid_malware, ppid=pid_bash, uid=1000,
                comm=comm_mal, pcomm="bash",
                event_type="EVENT_MEM_PROTECT", raw_syscall="sys_enter_mprotect",
                mem_prot="0x7 (PROT_READ|PROT_WRITE|PROT_EXEC)",
                mem_addr="0x7f9a4c000000"
            ))
            # 5. Outbound C2 connection from stealth process
            events.append(KernelEvent(
                timestamp_ns=int((now + 0.60) * 1e9),
                pid=pid_malware, ppid=pid_bash, uid=1000,
                comm=comm_mal, pcomm="bash",
                event_type="EVENT_NET_CONNECT", raw_syscall="sys_enter_connect",
                net_daddr="194.26.29.112", net_dport=4444
            ))

        elif scenario_name == "ransomware":
            # Scenario 2: Ransomware Mass Encryption & Shadow Deletion
            pid_ransom = target_pid if target_pid else 7800
            comm_ran = (comm[:15] if comm else "dark_crypt.elf")
            events.append(KernelEvent(
                timestamp_ns=int((now + 0.05) * 1e9),
                pid=pid_ransom, ppid=1, uid=1000,
                comm=comm_ran, pcomm="bash",
                event_type="EVENT_PROCESS_EXEC", raw_syscall="sys_enter_execve",
                target_path="/tmp/.cache/dark_crypt.elf"
            ))
            # Loop iterating through user files, encrypting & unlinking originals
            target_files = [
                "/home/user/documents/financial_report.xlsx",
                "/home/user/documents/customer_db.sql",
                "/home/user/documents/contracts_2026.pdf",
                "/home/user/credentials.kdbx",
                "/home/user/backup/archive.tar.gz"
            ]
            for i, fpath in enumerate(target_files):
                # Open & overwrite
                events.append(KernelEvent(
                    timestamp_ns=int((now + 0.10 + i * 0.10) * 1e9),
                    pid=pid_ransom, ppid=1, uid=1000,
                    comm=comm_ran, pcomm="bash",
                    event_type="EVENT_FILE_OPEN", raw_syscall="sys_enter_openat",
                    target_path=fpath
                ))
                # Delete original / replace with encrypted
                events.append(KernelEvent(
                    timestamp_ns=int((now + 0.15 + i * 0.10) * 1e9),
                    pid=pid_ransom, ppid=1, uid=1000,
                    comm=comm_ran, pcomm="bash",
                    event_type="EVENT_FILE_UNLINK", raw_syscall="sys_enter_unlinkat",
                    target_path=f"{fpath}.locked"
                ))
            # Ransom note drop
            events.append(KernelEvent(
                timestamp_ns=int((now + 0.80) * 1e9),
                pid=pid_ransom, ppid=1, uid=1000,
                comm=comm_ran, pcomm="bash",
                event_type="EVENT_FILE_WRITE", raw_syscall="sys_enter_write",
                target_path="/home/user/README_RECOVER_KEYS.txt"
            ))
            # C2 key exfiltration
            events.append(KernelEvent(
                timestamp_ns=int((now + 0.95) * 1e9),
                pid=pid_ransom, ppid=1, uid=1000,
                comm=comm_ran, pcomm="bash",
                event_type="EVENT_NET_CONNECT", raw_syscall="sys_enter_connect",
                net_daddr="45.142.214.88", net_dport=8080
            ))

        elif scenario_name == "reverse_shell":
            # Scenario 3: C2 Reverse Shell & Lateral Probe
            pid_target = target_pid if target_pid else 8840
            pid_sh = pid_target + 1
            comm_target = (comm[:15] if comm else "python3")
            events.append(KernelEvent(
                timestamp_ns=int((now + 0.05) * 1e9),
                pid=pid_target, ppid=1102, uid=33, # compromised web server
                comm=comm_target, pcomm="nginx",
                event_type="EVENT_PROCESS_EXEC", raw_syscall="sys_enter_execve",
                target_path="/usr/bin/python3"
            ))
            # Socket connection to external C2 listener
            events.append(KernelEvent(
                timestamp_ns=int((now + 0.20) * 1e9),
                pid=pid_target, ppid=1102, uid=33,
                comm=comm_target, pcomm="nginx",
                event_type="EVENT_NET_CONNECT", raw_syscall="sys_enter_connect",
                net_daddr="185.220.101.5", net_dport=1337
            ))
            # Spawn interactive sh shell as child
            events.append(KernelEvent(
                timestamp_ns=int((now + 0.35) * 1e9),
                pid=pid_sh, ppid=pid_target, uid=33,
                comm="sh", pcomm=comm_target,
                event_type="EVENT_PROCESS_EXEC", raw_syscall="sys_enter_execve",
                target_path="/bin/sh"
            ))
            # Reconnaissance: read sensitive files
            events.append(KernelEvent(
                timestamp_ns=int((now + 0.50) * 1e9),
                pid=pid_sh, ppid=pid_target, uid=33,
                comm="sh", pcomm=comm_target,
                event_type="EVENT_FILE_OPEN", raw_syscall="sys_enter_openat",
                target_path="/etc/passwd"
            ))
            events.append(KernelEvent(
                timestamp_ns=int((now + 0.65) * 1e9),
                pid=pid_sh, ppid=pid_target, uid=33,
                comm="sh", pcomm=comm_target,
                event_type="EVENT_FILE_OPEN", raw_syscall="sys_enter_openat",
                target_path="/etc/shadow"
            ))

        elif scenario_name == "privesc":
            # Scenario 4: Privilege Escalation via Kernel Exploit / setuid(0)
            pid_exploit = target_pid if target_pid else 9310
            comm_exp = (comm[:15] if comm else "cve_exploit")
            events.append(KernelEvent(
                timestamp_ns=int((now + 0.05) * 1e9),
                pid=pid_exploit, ppid=2810, uid=1000,
                comm=comm_exp, pcomm="bash",
                event_type="EVENT_PROCESS_EXEC", raw_syscall="sys_enter_execve",
                target_path="/home/user/dirtycow_exp"
            ))
            events.append(KernelEvent(
                timestamp_ns=int((now + 0.20) * 1e9),
                pid=pid_exploit, ppid=2810, uid=1000,
                comm=comm_exp, pcomm="bash",
                event_type="EVENT_MEM_PROTECT", raw_syscall="sys_enter_mprotect",
                mem_prot="0x7 (PROT_READ|PROT_WRITE|PROT_EXEC)",
                mem_addr="0x400000"
            ))
            # Escalation to root uid 0
            events.append(KernelEvent(
                timestamp_ns=int((now + 0.40) * 1e9),
                pid=pid_exploit, ppid=2810, uid=0, # uid transition!
                comm=comm_exp, pcomm="bash",
                event_type="EVENT_PRIV_SETUID", raw_syscall="sys_enter_setuid",
                target_path="uid=0(root)"
            ))
            # Root shell execution
            events.append(KernelEvent(
                timestamp_ns=int((now + 0.60) * 1e9),
                pid=9311, ppid=pid_exploit, uid=0,
                comm="bash", pcomm="cve_exploit",
                event_type="EVENT_PROCESS_EXEC", raw_syscall="sys_enter_execve",
                target_path="/bin/bash"
            ))

        return events

    def start_background_stream(self):
        """Starts real-time background telemetry thread."""
        self.running = True
        def _loop():
            while self.running:
                ev = self.generate_benign_event()
                if self.callback:
                    self.callback(ev)
                time.sleep(1.0 / self._rate_hz)

        self._thread = threading.Thread(target=_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
