"""
KernelGuard Dataset Exporter
Generates, packages, and exports all raw telemetry, DARPA TC benchmark datasets,
attack scenarios, and training graph samples into structured JSON and CSV files.
"""

import os
import sys
import csv
import json
import random
import time
from typing import List, Dict, Any

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ebpf.ebpf_loader import KernelEvent
from ebpf.telemetry_engine import TelemetryEngine
from datasets.darpa_tc_loader import DarpaTCLoader, DARPA_THEIA_CDM_RECORDS
from graph.temporal_graph import TemporalBehavioralGraph
from graph.feature_extractor import GraphFeatureExtractor

def event_to_dict(ev: KernelEvent) -> Dict[str, Any]:
    if hasattr(ev, "model_dump"):
        return ev.model_dump()
    return ev.dict()

def export_all():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    raw_dir = os.path.join(base_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    print(f"[*] Exporting KernelGuard datasets to: {raw_dir}")

    telemetry = TelemetryEngine()
    darpa = DarpaTCLoader()

    all_csv_rows = []

    # 1. Export DARPA TC THEIA APT33 Scenario
    darpa_events = darpa.load_scenario_events()
    darpa_export = {
        "dataset_name": "DARPA Transparent Computing (TC) THEIA Release 5",
        "description": "Standardized Common Data Model (CDM) provenance events representing APT33 in-memory dropper, credential dumping, and C2 exfiltration.",
        "schema": "DARPA TC Common Data Model (CDM) / Linux Kernel Tracepoints",
        "total_events": len(darpa_events),
        "raw_cdm_records": DARPA_THEIA_CDM_RECORDS,
        "normalized_ebpf_events": [event_to_dict(e) for e in darpa_events]
    }
    darpa_path = os.path.join(raw_dir, "darpa_tc_theia_apt33.json")
    with open(darpa_path, "w", encoding="utf-8") as f:
        json.dump(darpa_export, f, indent=2)
    print(f"  [+] Saved DARPA TC benchmark trace: {darpa_path}")

    for e in darpa_events:
        d = event_to_dict(e)
        d["dataset_source"] = "DARPA_TC_THEIA"
        d["threat_label"] = "APT33_Fileless_Dropper"
        all_csv_rows.append(d)

    # 2. Export 4 Advanced Malware Attack Scenarios
    scenarios = ["fileless", "ransomware", "reverse_shell", "privesc"]
    attack_export = {
        "dataset_name": "KernelGuard High-Fidelity Linux Malware Behavioral Scenarios",
        "description": "Synthesized causal attack sequences intercepted via eBPF tracepoints across 4 critical threat classes.",
        "scenarios": {}
    }

    for sc in scenarios:
        events = telemetry.generate_attack_scenario(sc)
        attack_export["scenarios"][sc] = {
            "scenario_name": sc,
            "event_count": len(events),
            "events": [event_to_dict(e) for e in events]
        }
        for e in events:
            d = event_to_dict(e)
            d["dataset_source"] = "KernelGuard_Attack_Telemetry"
            d["threat_label"] = sc
            all_csv_rows.append(d)

    attack_path = os.path.join(raw_dir, "malware_attack_scenarios.json")
    with open(attack_path, "w", encoding="utf-8") as f:
        json.dump(attack_export, f, indent=2)
    print(f"  [+] Saved malware attack scenarios: {attack_path}")

    # 3. Export Benign Baseline Production Samples
    benign_events = [telemetry.generate_benign_event() for _ in range(100)]
    benign_export = {
        "dataset_name": "KernelGuard Benign Linux Production Baselines",
        "description": "Background multi-threaded kernel telemetry representing Nginx web servers, GCC builds, cron jobs, systemd-journald, and Python standard runtime.",
        "total_samples": len(benign_events),
        "events": [event_to_dict(e) for e in benign_events]
    }
    benign_path = os.path.join(raw_dir, "benign_baseline_samples.json")
    with open(benign_path, "w", encoding="utf-8") as f:
        json.dump(benign_export, f, indent=2)
    print(f"  [+] Saved benign baseline samples: {benign_path}")

    for e in benign_events:
        d = event_to_dict(e)
        d["dataset_source"] = "Benign_Production_Telemetry"
        d["threat_label"] = "Benign"
        all_csv_rows.append(d)

    # 4. Export Training Graph Tensor Metadata (250 Samples)
    extractor = GraphFeatureExtractor()
    graph_samples_meta = []
    classes = [("benign", 0, 0.05), ("fileless", 1, 0.95), ("ransomware", 2, 0.98), ("reverse_shell", 3, 0.90), ("privesc", 4, 0.92)]
    
    for sc_name, class_idx, target_risk in classes:
        for sample_i in range(50):
            g = TemporalBehavioralGraph()
            for _ in range(random.randint(4, 9)):
                g.ingest_event(telemetry.generate_benign_event())
            if sc_name != "benign":
                evs = telemetry.generate_attack_scenario(sc_name)
                for ev in evs:
                    g.ingest_event(ev)
                target_pid = evs[-1].pid
            else:
                target_pid = list(g.pid_to_node_id.keys())[0] if g.pid_to_node_id else 1000

            sub = g.get_process_subgraph(target_pid)
            n_f, e_i, e_f = extractor.extract_subgraph_tensors(sub)
            graph_samples_meta.append({
                "sample_id": len(graph_samples_meta) + 1,
                "threat_class": sc_name,
                "class_index": class_idx,
                "ground_truth_risk": target_risk,
                "node_count": int(n_f.shape[0]),
                "edge_count": int(e_i.shape[1]),
                "node_feature_dim": int(n_f.shape[1]),
                "edge_feature_dim": int(e_f.shape[1]),
                "target_pid": target_pid
            })

    graphs_path = os.path.join(raw_dir, "training_graphs_metadata.json")
    with open(graphs_path, "w", encoding="utf-8") as f:
        json.dump({
            "dataset_name": "KernelGuard Calibrated Behavioral Graph Dataset",
            "total_graphs": len(graph_samples_meta),
            "classes": [c[0] for c in classes],
            "samples": graph_samples_meta
        }, f, indent=2)
    print(f"  [+] Saved training graph metadata (250 graphs): {graphs_path}")

    # 5. Export Unified CSV Table
    csv_path = os.path.join(raw_dir, "all_telemetry_events.csv")
    fieldnames = [
        "dataset_source", "threat_label", "timestamp_ns", "pid", "ppid", "uid", "gid",
        "comm", "pcomm", "event_type", "raw_syscall", "target_path",
        "net_daddr", "net_dport", "mem_prot", "mem_addr", "ret_val"
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in all_csv_rows:
            writer.writerow(r)
    print(f"  [+] Saved unified events CSV table: {csv_path}")

    print(f"\n[+] Dataset export complete! Total events exported: {len(all_csv_rows)}")

if __name__ == "__main__":
    export_all()
