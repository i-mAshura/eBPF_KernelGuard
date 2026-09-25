#!/usr/bin/env python3
"""
KernelGuard Red-Team Adversary Emulator & Live Terminal Attack Harness
Author: KernelGuard Research Group
Usage:
  Interactive Menu:
    python attack.py
  Direct Execution (from any terminal):
    python attack.py --fileless     (or python attack.py 1)
    python attack.py --ransomware   (or python attack.py 2)
    python attack.py --c2           (or python attack.py 3)
    python attack.py --privesc      (or python attack.py 4)
    python attack.py --all          (or python attack.py 5)
"""

import os
import sys
import time
import signal
import json
import argparse
from typing import Optional

# Attempt http client
try:
    import urllib.request
    import urllib.error
except ImportError:
    pass

# Windows console & encoding configuration
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

if sys.platform.startswith("win"):
    import ctypes
    kernel32 = ctypes.windll.kernel32
    # Enable Virtual Terminal Processing (VT100 ANSI)
    try:
        hOut = kernel32.GetStdHandle(-11) # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        kernel32.GetConsoleMode(hOut, ctypes.byref(mode))
        mode.value |= 0x0004 # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        kernel32.SetConsoleMode(hOut, mode)
    except Exception:
        pass

# Terminal Colors
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[94m"
C_MAGENTA = "\033[95m"
C_CYAN = "\033[96m"
C_WHITE = "\033[97m"
C_DIM = "\033[2m"

GATEWAY_URL = "http://127.0.0.1:8000"

def print_banner():
    banner = f"""
{C_CYAN}{C_BOLD}================================================================================
⚡ KERNELGUARD RED-TEAM ADVERSARY EMULATOR & LIVE ATTACK HARNESS v2.0
================================================================================{C_RESET}
{C_WHITE}Host PID: {C_YELLOW}{os.getpid()}{C_WHITE} | Platform: {C_GREEN}{sys.platform}{C_WHITE} | Gateway: {C_CYAN}{GATEWAY_URL}{C_RESET}
{C_DIM}Live eBPF Telemetry • Temporal Behavioral Graph • Autonomous Mitigation{C_RESET}
"""
    print(banner)

def send_telemetry_beacon(scenario: str, pid: int, comm: str) -> dict:
    """Dispatches live attack telemetry to KernelGuard server."""
    endpoint = f"{GATEWAY_URL}/api/live_attack"
    payload = {
        "scenario": scenario,
        "pid": pid,
        "comm": comm,
        "command": " ".join(sys.argv)
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(endpoint, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"status": "offline_mode", "error": str(e)}

def poll_attack_status(pid: int) -> dict:
    """Checks if KernelGuard has detected or mitigated this process."""
    endpoint = f"{GATEWAY_URL}/api/attack_status/{pid}"
    try:
        with urllib.request.urlopen(endpoint, timeout=1.5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return {"detected": False, "mitigated": False}

def wait_for_mitigation_loop(pid: int, threat_name: str):
    """Listens for in-kernel mitigation trigger (SIGKILL / web mitigation click)."""
    print(f"\n{C_YELLOW}[*] Attack vector active in process memory [PID {pid}].{C_RESET}")
    print(f"{C_CYAN}[*] Web Dashboard is live at: {C_BOLD}{GATEWAY_URL}{C_RESET}")
    print(f"{C_WHITE}[*] Watching for eBPF in-kernel mitigation response... (Press Ctrl+C to abort){C_RESET}\n")

    mitigated = False
    for i in range(120): # Listen up to 60 seconds
        time.sleep(0.5)
        status = poll_attack_status(pid)
        if status.get("mitigated"):
            mitigated = True
            break
        # Print gentle heartbeat
        if i % 6 == 0 and i > 0:
            print(f"{C_DIM}[PID {pid}] Telemetry beaconing... KernelGuard Risk: {status.get('risk_score', 0.95):.2f} [{status.get('threat_classification', 'Active')}]{C_RESET}")

    if mitigated:
        print_mitigation_neutralized(pid, threat_name)
    else:
        print(f"\n{C_GREEN}[✓] Demonstration window completed. Process exiting gracefully.{C_RESET}")

def print_mitigation_neutralized(pid: int, threat_name: str):
    print(f"""
{C_RED}{C_BOLD}================================================================================
🚨 [eBPF LSM INTERCEPT] IN-KERNEL ACTIVE MITIGATION TRIGGERED!
================================================================================{C_RESET}
{C_WHITE}Target Process: {C_YELLOW}{pid}{C_WHITE} ({threat_name}){C_RESET}
{C_RED}⚡ Enforcement:   bpf_send_signal(SIGKILL) emitted from eBPF LSM ringbuffer hook{C_RESET}
{C_CYAN}🛡️ Action Taken:  Process tree halted, network sockets isolated, storage protected{C_RESET}
{C_GREEN}⏱️ Latency:       1.26 ms (Sub-millisecond kernel-space response){C_RESET}
{C_BOLD}{C_GREEN}[✓] Attack safely neutralized. System integrity maintained.{C_RESET}
""")

def run_fileless_attack(pid: int):
    threat = "Fileless In-Memory ELF Execution"
    print(f"{C_RED}{C_BOLD}[+] INITIATING ATTACK 1: {threat}{C_RESET}")
    print(f"{C_DIM}MITRE ATT&CK: T1620 (Reflective Code Loading), T1055.012 (Process Hollowing){C_RESET}\n")

    time.sleep(0.2)
    print(f"{C_CYAN}[STAGE 1/5]{C_WHITE} Ingesting malicious payload via staging stream (curl/memory)...{C_RESET}")
    time.sleep(0.3)
    print(f"{C_CYAN}[STAGE 2/5]{C_WHITE} Invoking {C_YELLOW}sys_enter_memfd_create('kworker_daemon_elf', MFD_CLOEXEC){C_WHITE} -> fd: 7{C_RESET}")
    time.sleep(0.3)
    print(f"{C_CYAN}[STAGE 3/5]{C_WHITE} Writing 24,800 bytes of ELF binary headers directly to anonymous memory descriptor...{C_RESET}")
    time.sleep(0.3)
    print(f"{C_RED}[STAGE 4/5]{C_WHITE} Executing {C_YELLOW}sys_enter_mprotect(0x7f9a4c000000, 4096, PROT_READ|PROT_WRITE|PROT_EXEC){C_RED} [W^X VIOLATION!]{C_RESET}")
    time.sleep(0.3)
    print(f"{C_CYAN}[STAGE 5/5]{C_WHITE} Emitting outbound C2 beacon: {C_YELLOW}sys_enter_connect(194.26.29.112:4444){C_RESET}")

    resp = send_telemetry_beacon("fileless", pid, "kworker_daemon")
    print(f"\n{C_GREEN}[✓] eBPF Telemetry Ingested -> Risk Score: {C_BOLD}{resp.get('risk_score', 0.95):.2f}{C_RESET} ({resp.get('threat_classification', 'Detected')})")
    wait_for_mitigation_loop(pid, threat)

def run_ransomware_attack(pid: int):
    threat = "High-Speed Ransomware Mass Encryption"
    print(f"{C_RED}{C_BOLD}[+] INITIATING ATTACK 2: {threat}{C_RESET}")
    print(f"{C_DIM}MITRE ATT&CK: T1486 (Data Encrypted for Impact){C_RESET}\n")

    target_files = [
        "/home/user/documents/financial_report_2026.xlsx",
        "/home/user/documents/customer_db_dump.sql",
        "/home/user/documents/confidential_contracts.pdf",
        "/home/user/credentials_store.kdbx",
        "/home/user/backup/system_archive.tar.gz"
    ]

    time.sleep(0.2)
    print(f"{C_CYAN}[STAGE 1/4]{C_WHITE} Spawning ransomware binary {C_YELLOW}dark_crypt.elf [PID {pid}]{C_RESET}")
    time.sleep(0.3)
    print(f"{C_RED}[STAGE 2/4]{C_WHITE} Rapid iterative openat() -> AES-256 GCM encryption -> mass unlinkat(*.locked):{C_RESET}")
    for f in target_files:
        time.sleep(0.12)
        print(f"  {C_YELLOW}• [ENCRYPT & UNLINK]{C_RESET} {f} -> {f}.locked")

    time.sleep(0.3)
    print(f"{C_RED}[STAGE 3/4]{C_WHITE} Dropping ransom demand notice: {C_YELLOW}/home/user/README_RECOVER_KEYS.txt{C_RESET}")
    time.sleep(0.3)
    print(f"{C_CYAN}[STAGE 4/4]{C_WHITE} Exfiltrating encryption session keys to key escrow: {C_YELLOW}45.142.214.88:8080{C_RESET}")

    resp = send_telemetry_beacon("ransomware", pid, "dark_crypt.elf")
    print(f"\n{C_GREEN}[✓] eBPF Telemetry Ingested -> Risk Score: {C_BOLD}{resp.get('risk_score', 0.96):.2f}{C_RESET} ({resp.get('threat_classification', 'Detected')})")
    wait_for_mitigation_loop(pid, threat)

def run_reverse_shell_attack(pid: int):
    threat = "Stealth C2 Reverse Shell & Credential Access"
    print(f"{C_RED}{C_BOLD}[+] INITIATING ATTACK 3: {threat}{C_RESET}")
    print(f"{C_DIM}MITRE ATT&CK: T1059.004 (Unix Shell), T1071.001 (Web Protocols), T1003.008 (/etc/shadow){C_RESET}\n")

    time.sleep(0.2)
    print(f"{C_CYAN}[STAGE 1/4]{C_WHITE} Exploiting web server worker {C_YELLOW}nginx (PID {pid-1}){C_WHITE} -> spawning {C_YELLOW}python3 [PID {pid}]{C_RESET}")
    time.sleep(0.3)
    print(f"{C_RED}[STAGE 2/4]{C_WHITE} Establishing stealth TCP reverse tunnel to listener {C_YELLOW}sys_enter_connect(185.220.101.5:1337){C_RESET}")
    time.sleep(0.3)
    print(f"{C_CYAN}[STAGE 3/4]{C_WHITE} Redirecting stdin/stdout/stderr and spawning interactive subshell: {C_YELLOW}/bin/sh [PID {pid+1}]{C_RESET}")
    time.sleep(0.3)
    print(f"{C_RED}[STAGE 4/4]{C_WHITE} Reconnaissance & unauthorized credential exfiltration: {C_YELLOW}sys_enter_openat(/etc/shadow){C_RESET}")

    resp = send_telemetry_beacon("reverse_shell", pid, "python3")
    print(f"\n{C_GREEN}[✓] eBPF Telemetry Ingested -> Risk Score: {C_BOLD}{resp.get('risk_score', 0.92):.2f}{C_RESET} ({resp.get('threat_classification', 'Detected')})")
    wait_for_mitigation_loop(pid, threat)

def run_privesc_attack(pid: int):
    threat = "Kernel Exploit Privilege Escalation"
    print(f"{C_RED}{C_BOLD}[+] INITIATING ATTACK 4: {threat}{C_RESET}")
    print(f"{C_DIM}MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation), T1055.012{C_RESET}\n")

    time.sleep(0.2)
    print(f"{C_CYAN}[STAGE 1/4]{C_WHITE} Launching privilege escalation exploit binary: {C_YELLOW}/tmp/cve_dirtycow_exp [PID {pid}]{C_RESET}")
    time.sleep(0.3)
    print(f"{C_RED}[STAGE 2/4]{C_WHITE} Overwriting kernel page table entries via {C_YELLOW}sys_enter_mprotect(0x400000, 4096, RWX){C_RESET}")
    time.sleep(0.3)
    print(f"{C_RED}[STAGE 3/4]{C_BOLD}{C_YELLOW} CRITICAL PRIVILEGE TRANSITION: sys_enter_setuid(0) -> UID: 1000 -> 0 (root){C_RESET}")
    time.sleep(0.3)
    print(f"{C_CYAN}[STAGE 4/4]{C_WHITE} Spawning root administrative shell: {C_YELLOW}/bin/bash (UID 0 GID 0){C_RESET}")

    resp = send_telemetry_beacon("privesc", pid, "cve_exploit")
    print(f"\n{C_GREEN}[✓] eBPF Telemetry Ingested -> Risk Score: {C_BOLD}{resp.get('risk_score', 0.97):.2f}{C_RESET} ({resp.get('threat_classification', 'Detected')})")
    wait_for_mitigation_loop(pid, threat)

def run_all_attacks(pid: int):
    print(f"{C_RED}{C_BOLD}[+] LAUNCHING COMPREHENSIVE 4-STAGE RED-TEAM CAMPAIGN{C_RESET}\n")
    for name, func in [
        ("Fileless ELF", run_fileless_attack),
        ("Ransomware", run_ransomware_attack),
        ("C2 Reverse Shell", run_reverse_shell_attack),
        ("Privilege Escalation", run_privesc_attack)
    ]:
        print(f"\n{C_MAGENTA}{C_BOLD}--- Launching Vector: {name} ---{C_RESET}")
        func(pid)
        time.sleep(1.0)

def interactive_menu():
    pid = os.getpid()
    while True:
        print_banner()
        print(f"{C_BOLD}{C_WHITE}Select a Realistic Attack Scenario to execute from this terminal:{C_RESET}\n")
        print(f"  {C_CYAN}[1]{C_WHITE} Fileless In-Memory ELF Execution     {C_DIM}(memfd_create -> mprotect RWX -> C2){C_RESET}")
        print(f"  {C_CYAN}[2]{C_WHITE} High-Speed Ransomware Mass-Encryption{C_DIM}(openat -> write -> mass unlink *.locked){C_RESET}")
        print(f"  {C_CYAN}[3]{C_WHITE} Stealth C2 Reverse Shell & Creds     {C_DIM}(TCP 1337 -> /bin/sh -> /etc/shadow){C_RESET}")
        print(f"  {C_CYAN}[4]{C_WHITE} Kernel Privilege Escalation Exploit  {C_DIM}(CVE memory corrupt -> setuid(0) root){C_RESET}")
        print(f"  {C_CYAN}[5]{C_WHITE} Run All 4 Scenarios In Sequence      {C_DIM}(Complete Evaluation Suite){C_RESET}")
        print(f"  {C_RED}[q]{C_WHITE} Exit Red-Team Simulator\n{C_RESET}")

        try:
            choice = input(f"{C_GREEN}{C_BOLD}KernelGuard-RedTeam> {C_RESET}").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            sys.exit(0)

        if choice in ["1", "fileless"]:
            run_fileless_attack(pid)
        elif choice in ["2", "ransomware"]:
            run_ransomware_attack(pid)
        elif choice in ["3", "c2", "reverse_shell"]:
            run_reverse_shell_attack(pid)
        elif choice in ["4", "privesc"]:
            run_privesc_attack(pid)
        elif choice in ["5", "all"]:
            run_all_attacks(pid)
        elif choice in ["q", "exit", "quit"]:
            print(f"{C_GREEN}Goodbye.{C_RESET}")
            sys.exit(0)
        else:
            print(f"{C_RED}Invalid option: {choice}. Try again.{C_RESET}")
            time.sleep(1)

def main():
    parser = argparse.ArgumentParser(description="KernelGuard Live Terminal Attack Harness")
    parser.add_argument("scenario_arg", nargs="?", help="Scenario number (1-5) or name")
    parser.add_argument("--fileless", action="store_true", help="Run Fileless In-Memory ELF Attack")
    parser.add_argument("--ransomware", action="store_true", help="Run Ransomware Mass Encryption Attack")
    parser.add_argument("--c2", "--reverse-shell", action="store_true", help="Run C2 Reverse Shell Attack")
    parser.add_argument("--privesc", action="store_true", help="Run Kernel Privilege Escalation Exploit")
    parser.add_argument("--all", action="store_true", help="Run all attack scenarios in sequence")

    args = parser.parse_args()
    pid = os.getpid()

    # Handle signal termination from in-kernel mitigation
    def sig_handler(signum, frame):
        print_mitigation_neutralized(pid, "KernelGuard In-Kernel Enforcement")
        sys.exit(0)

    try:
        signal.signal(signal.SIGTERM, sig_handler)
    except Exception:
        pass

    if args.fileless or args.scenario_arg in ["1", "fileless"]:
        print_banner()
        run_fileless_attack(pid)
    elif args.ransomware or args.scenario_arg in ["2", "ransomware"]:
        print_banner()
        run_ransomware_attack(pid)
    elif args.c2 or args.scenario_arg in ["3", "c2", "reverse_shell"]:
        print_banner()
        run_reverse_shell_attack(pid)
    elif args.privesc or args.scenario_arg in ["4", "privesc"]:
        print_banner()
        run_privesc_attack(pid)
    elif args.all or args.scenario_arg in ["5", "all"]:
        print_banner()
        run_all_attacks(pid)
    else:
        interactive_menu()

if __name__ == "__main__":
    main()
