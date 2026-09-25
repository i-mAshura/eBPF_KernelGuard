"""
KernelGuard Adaptive Risk-Scorer & Security Analyst Explainability Engine
Combines GNN-Transformer output, syscall semantic profiling, process lineage anomalies,
and MITRE ATT&CK technique mapping to produce actionable, interpretable detection reports.
"""

from typing import Dict, List, Any, Optional
import math

MITRE_MAPPINGS = {
    "memfd": {
        "id": "T1620",
        "name": "Reflective Code Loading / Fileless Execution",
        "tactic": "Defense Evasion",
        "severity": "CRITICAL"
    },
    "mprotect_rwx": {
        "id": "T1055.012",
        "name": "Process Injection / Memory Allocation (W^X Violation)",
        "tactic": "Privilege Escalation / Defense Evasion",
        "severity": "HIGH"
    },
    "ransomware": {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "severity": "CRITICAL"
    },
    "reverse_shell": {
        "id": "T1059.004",
        "name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "Execution",
        "severity": "HIGH"
    },
    "c2_connect": {
        "id": "T1071.001",
        "name": "Application Layer Protocol: External C2 Channel",
        "tactic": "Command and Control",
        "severity": "HIGH"
    },
    "credential_access": {
        "id": "T1003.008",
        "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "tactic": "Credential Access",
        "severity": "CRITICAL"
    },
    "privilege_escalation": {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "severity": "CRITICAL"
    }
}

class AdaptiveRiskScorer:
    def __init__(self, high_risk_threshold: float = 0.70):
        self.high_risk_threshold = high_risk_threshold

    def evaluate(self, model_prediction: Dict[str, Any], subgraph: Dict[str, Any], target_pid: int) -> Dict[str, Any]:
        """
        Computes multi-factor adaptive risk score and contextual analysis.
        """
        model_risk = model_prediction.get("risk_score", 0.0)
        threat_class = model_prediction.get("threat_class", "Benign System Activity")

        nodes = subgraph.get("nodes", [])
        edges = subgraph.get("edges", [])

        # 1. Syscall Semantic Risk Analysis
        semantic_score = 0.0
        mitre_detected = []
        anomaly_reasons = []

        # Check for memfd fileless loading
        has_memfd = any(n.get("type") == "memory" and n.get("properties", {}).get("is_fileless") for n in nodes)
        if has_memfd:
            semantic_score += 0.45
            mitre_detected.append(MITRE_MAPPINGS["memfd"])
            anomaly_reasons.append("Process initiated anonymous fileless memory descriptor (`memfd_create`).")

        # Check for W^X memory violation (RWX memory)
        has_rwx = any(n.get("properties", {}).get("is_rwx") for n in nodes)
        if has_rwx:
            semantic_score += 0.35
            mitre_detected.append(MITRE_MAPPINGS["mprotect_rwx"])
            anomaly_reasons.append("Executable and writable memory segment allocated (`mprotect PROT_READ|PROT_WRITE|PROT_EXEC`).")

        # Check for mass file encryption/deletion (Ransomware)
        unlink_count = sum(1 for e in edges if e.get("edge_type") == "unlink" or "unlink" in e.get("syscall", ""))
        has_ransom_file = any(n.get("properties", {}).get("is_ransom_ext") for n in nodes)
        if unlink_count >= 2 or has_ransom_file:
            semantic_score += 0.50
            mitre_detected.append(MITRE_MAPPINGS["ransomware"])
            anomaly_reasons.append(f"Rapid mass file unlinking/encryption ({unlink_count} sensitive files unlinked, ransomware extensions detected).")

        # Check for external C2 socket connection
        ext_sockets = [n for n in nodes if n.get("type") == "socket" and n.get("properties", {}).get("is_external")]
        if ext_sockets:
            sock_info = ext_sockets[0].get("properties", {})
            semantic_score += 0.25
            mitre_detected.append(MITRE_MAPPINGS["c2_connect"])
            anomaly_reasons.append(f"External connection initiated to non-standard remote C2 socket `{sock_info.get('ip')}:{sock_info.get('port')}`.")

        # Check for credential dumping
        sensitive_files = [n for n in nodes if n.get("properties", {}).get("is_sensitive")]
        if sensitive_files:
            file_names = ", ".join([n.get("properties", {}).get("path", "") for n in sensitive_files])
            semantic_score += 0.40
            mitre_detected.append(MITRE_MAPPINGS["credential_access"])
            anomaly_reasons.append(f"Direct unauthorized access to sensitive credential store: {file_names}")

        # Check for privilege escalation
        has_root_transition = any(n.get("properties", {}).get("is_root_escalation") for n in nodes)
        if has_root_transition:
            semantic_score += 0.50
            mitre_detected.append(MITRE_MAPPINGS["privilege_escalation"])
            anomaly_reasons.append("Abrupt privilege transition to UID 0 (root) detected.")

        semantic_score = min(semantic_score, 1.0)

        # 2. Lineage Anomaly Analysis
        lineage_score = 0.0
        proc_nodes = [n for n in nodes if n.get("type") == "process"]
        comms = [n.get("properties", {}).get("comm", "") for n in proc_nodes]
        pcomms = [n.get("properties", {}).get("pcomm", "") for n in proc_nodes]

        # Web server (nginx) spawning shell/python is highly anomalous
        if "nginx" in pcomms and any(c in ["bash", "sh", "python3"] for c in comms):
            lineage_score += 0.45
            mitre_detected.append(MITRE_MAPPINGS["reverse_shell"])
            anomaly_reasons.append("Compromised parent: Web service (`nginx`) directly spawned an interactive command shell.")

        if len(proc_nodes) >= 3:
            lineage_score += 0.15

        lineage_score = min(lineage_score, 1.0)

        # 3. Adaptive Composite Risk Score Calculation
        # Dynamically weights model vs semantic anomalies
        if semantic_score > 0.6:
            composite_risk = 0.50 * model_risk + 0.35 * semantic_score + 0.15 * lineage_score
        else:
            composite_risk = 0.70 * model_risk + 0.20 * semantic_score + 0.10 * lineage_score

        composite_risk = round(min(max(composite_risk, 0.0), 1.0), 4)
        is_malicious = composite_risk >= self.high_risk_threshold

        # Unique MITRE techniques
        unique_mitre = []
        seen_ids = set()
        for m in mitre_detected:
            if m["id"] not in seen_ids:
                seen_ids.add(m["id"])
                unique_mitre.append(m)

        # Confidence level
        if composite_risk >= 0.85:
            confidence = "HIGH CONFIDENCE"
        elif composite_risk >= 0.65:
            confidence = "MEDIUM CONFIDENCE"
        else:
            confidence = "LOW / BENIGN"

        # Remediation recommendations
        recommendations = []
        if is_malicious:
            recommendations.append(f"Immediately SIGKILL process tree under PID {target_pid}.")
            if ext_sockets:
                recommendations.append(f"Block remote endpoint `{ext_sockets[0].get('properties', {}).get('ip')}` on perimeter firewall.")
            if has_memfd:
                recommendations.append("Dump in-memory ELF image from `/proc/{PID}/fd` for forensic reverse engineering.")
            if unlink_count > 0:
                recommendations.append("Trigger read-only lock on file storage volume to mitigate further ransomware destruction.")
        else:
            recommendations.append("No active intervention required; telemetry consistent with baseline system operations.")

        return {
            "target_pid": target_pid,
            "composite_risk_score": composite_risk,
            "is_malicious": is_malicious,
            "confidence": confidence,
            "threat_classification": threat_class if is_malicious else "Benign System Activity",
            "component_scores": {
                "gnn_transformer_model": round(model_risk, 4),
                "syscall_semantics": round(semantic_score, 4),
                "lineage_anomaly": round(lineage_score, 4)
            },
            "mitre_attack_techniques": unique_mitre,
            "causal_anomaly_explanations": anomaly_reasons,
            "recommended_actions": recommendations,
            "attention_subgraph_edges": model_prediction.get("subgraph_attention_edges", [])
        }
