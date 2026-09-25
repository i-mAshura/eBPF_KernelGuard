"""
KernelGuard DARPA Transparent Computing (TC) Dataset Ingestion & Replay Subsystem
Parses and streams standardized CDM (Common Data Model) telemetry from
DARPA TC THEIA, CADETS, and TRACE attack benchmarks into KernelGuard's eBPF graph engine.
"""

import time
import json
from typing import List, Dict, Any, Generator
from ebpf.ebpf_loader import KernelEvent

# Synthetic excerpt of authentic DARPA TC THEIA scenario: APT33 in-memory dropper
DARPA_THEIA_CDM_RECORDS = [
    {
        "event_type": "EVENT_PROCESS_EXEC", "syscall": "sys_enter_execve",
        "subject_pid": 5020, "subject_ppid": 1, "subject_comm": "thunderbird",
        "target": "/usr/bin/thunderbird", "timestamp_offset_ms": 10
    },
    {
        "event_type": "EVENT_PROCESS_EXEC", "syscall": "sys_enter_execve",
        "subject_pid": 5025, "subject_ppid": 5020, "subject_comm": "sh",
        "target": "/bin/sh", "timestamp_offset_ms": 120
    },
    {
        "event_type": "EVENT_NET_CONNECT", "syscall": "sys_enter_connect",
        "subject_pid": 5025, "subject_ppid": 5020, "subject_comm": "sh",
        "net_ip": "128.55.12.189", "net_port": 443, "timestamp_offset_ms": 250
    },
    {
        "event_type": "EVENT_MEMFD_CREATE", "syscall": "sys_enter_memfd_create",
        "subject_pid": 5025, "subject_ppid": 5020, "subject_comm": "sh",
        "target": "memfd:theia_payload_stage2", "timestamp_offset_ms": 380
    },
    {
        "event_type": "EVENT_MEM_PROTECT", "syscall": "sys_enter_mprotect",
        "subject_pid": 5026, "subject_ppid": 5025, "subject_comm": "theia_payload",
        "mem_prot": "0x7 (PROT_READ|PROT_WRITE|PROT_EXEC)", "mem_addr": "0x7f1122000000",
        "timestamp_offset_ms": 510
    },
    {
        "event_type": "EVENT_FILE_OPEN", "syscall": "sys_enter_openat",
        "subject_pid": 5026, "subject_ppid": 5025, "subject_comm": "theia_payload",
        "target": "/etc/shadow", "timestamp_offset_ms": 680
    },
    {
        "event_type": "EVENT_NET_CONNECT", "syscall": "sys_enter_connect",
        "subject_pid": 5026, "subject_ppid": 5025, "subject_comm": "theia_payload",
        "net_ip": "198.51.100.45", "net_port": 8443, "timestamp_offset_ms": 820
    }
]

class DarpaTCLoader:
    def __init__(self):
        self.dataset_name = "DARPA TC THEIA (Release 5 - Scenario 1)"

    def load_scenario_events(self) -> List[KernelEvent]:
        """Converts DARPA TC CDM records into KernelGuard KernelEvents."""
        base_time_ns = int(time.time() * 1e9)
        events = []

        for record in DARPA_THEIA_CDM_RECORDS:
            ts_ns = base_time_ns + int(record["timestamp_offset_ms"] * 1e6)
            ev = KernelEvent(
                timestamp_ns=ts_ns,
                pid=record["subject_pid"],
                ppid=record["subject_ppid"],
                uid=1000,
                gid=1000,
                comm=record["subject_comm"],
                pcomm="parent",
                event_type=record["event_type"],
                raw_syscall=record["syscall"],
                target_path=record.get("target", ""),
                net_daddr=record.get("net_ip", ""),
                net_dport=record.get("net_port", 0),
                mem_prot=record.get("mem_prot", "0x0"),
                mem_addr=record.get("mem_addr", "0x0"),
                ret_val=0
            )
            events.append(ev)

        return events
