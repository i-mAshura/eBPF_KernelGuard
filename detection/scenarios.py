"""
KernelGuard Scenario Catalog & Metadata
Defines scenario profiles, target attack techniques, and detection expectations.
"""

SCENARIOS_META = {
    "fileless": {
        "id": "fileless",
        "title": "Fileless In-Memory ELF Execution",
        "description": "Adversary leverages curl piping into memory, creating an anonymous memfd descriptor without touching the disk, altering memory protection to RWX, and initiating an outbound C2 shell.",
        "category": "Defense Evasion & Execution",
        "attack_vector": "curl -> memfd_create -> mprotect(PROT_EXEC) -> sys_enter_connect",
        "expected_detection": "Fileless In-Memory Malware",
        "mitre_ids": ["T1620", "T1055.012", "T1071.001"]
    },
    "ransomware": {
        "id": "ransomware",
        "title": "Rapid Multi-File Ransomware Attack",
        "description": "Adversary process initiates mass-iteration over user documents, overwriting target content with encrypted ciphertext, unlinking originals, dropping a ransom note, and reaching out to a C2 key server.",
        "category": "Impact",
        "attack_vector": "openat -> write -> unlinkat(*.locked) -> write(README) -> connect",
        "expected_detection": "Ransomware Mass Encryption",
        "mitre_ids": ["T1486", "T1071.001"]
    },
    "reverse_shell": {
        "id": "reverse_shell",
        "title": "Stealth C2 Reverse Shell & Lateral Probe",
        "description": "Compromised web server child initiates TCP connection to external listener, spawns an interactive /bin/sh shell, and attempts unauthorized exfiltration of /etc/shadow credentials.",
        "category": "Initial Access & Command and Control",
        "attack_vector": "nginx -> python3 -> sys_enter_connect(1337) -> sh -> openat(/etc/shadow)",
        "expected_detection": "C2 Reverse Shell & Exfiltration",
        "mitre_ids": ["T1059.004", "T1071.001", "T1003.008"]
    },
    "privesc": {
        "id": "privesc",
        "title": "Kernel Exploit Privilege Escalation",
        "description": "Local non-privileged attacker executes vulnerability exploit, modifies code memory segments, elevates credentials via setuid(0) transition, and launches an unauthorized root shell.",
        "category": "Privilege Escalation",
        "attack_vector": "exploit -> mprotect(RWX) -> sys_enter_setuid(0) -> execve(/bin/bash)",
        "expected_detection": "Privilege Escalation Exploit",
        "mitre_ids": ["T1068", "T1055.012"]
    },
    "benign": {
        "id": "benign",
        "title": "Standard Baseline Workload",
        "description": "Typical enterprise Linux production activity: web server servicing requests, compiler building binaries, cron log rotation, and system journal updates.",
        "category": "Normal Operations",
        "attack_vector": "nginx/gcc/cron standard syscall patterns",
        "expected_detection": "Benign System Activity",
        "mitre_ids": []
    }
}
