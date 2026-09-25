"""
KernelGuard Model Pre-training & Calibration Script
Trains the Hybrid GNN-Transformer on synthesized temporal behavioral graphs
representing diverse Linux malware vectors and benign production baselines.
Saves calibrated model checkpoint to `models/kernelguard_gnn.pt`.
"""

import os
import random
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np

from ebpf.telemetry_engine import TelemetryEngine
from graph.temporal_graph import TemporalBehavioralGraph
from graph.feature_extractor import GraphFeatureExtractor
from models.gnn_transformer import HybridGNNTransformer, THREAT_CLASSES

def generate_dataset(num_samples: int = 200):
    telemetry = TelemetryEngine()
    extractor = GraphFeatureExtractor()
    dataset = []

    scenarios = [
        ("benign", 0, 0.05),
        ("fileless", 1, 0.95),
        ("ransomware", 2, 0.98),
        ("reverse_shell", 3, 0.90),
        ("privesc", 4, 0.92)
    ]

    for sc_name, class_idx, target_risk in scenarios:
        for _ in range(num_samples // len(scenarios)):
            graph = TemporalBehavioralGraph()
            # Mix benign background
            for _ in range(random.randint(3, 8)):
                graph.ingest_event(telemetry.generate_benign_event())

            if sc_name != "benign":
                events = telemetry.generate_attack_scenario(sc_name)
                for e in events:
                    graph.ingest_event(e)
                target_pid = events[-1].pid
            else:
                target_pid = list(graph.pid_to_node_id.keys())[0] if graph.pid_to_node_id else 1000

            sub = graph.get_process_subgraph(target_pid)
            n_feats, e_idx, e_feats = extractor.extract_subgraph_tensors(sub)
            if n_feats.shape[0] > 0:
                dataset.append((
                    torch.from_numpy(n_feats).float(),
                    torch.from_numpy(e_idx).long(),
                    torch.from_numpy(e_feats).float(),
                    torch.tensor([target_risk], dtype=torch.float32),
                    torch.tensor(class_idx, dtype=torch.long)
                ))
    random.shuffle(dataset)
    return dataset

def train_and_save():
    print("[*] Generating behavioral graph training dataset...")
    dataset = generate_dataset(num_samples=250)
    print(f"[+] Dataset created with {len(dataset)} behavioral graph samples.")

    model = HybridGNNTransformer(node_dim=16, edge_dim=12, hidden_dim=32, num_classes=5)
    criterion_risk = nn.MSELoss()
    criterion_class = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.005, weight_decay=1e-4)

    print("[*] Training Hybrid GNN-Transformer for 25 epochs...")
    model.train()
    for epoch in range(1, 26):
        total_loss = 0.0
        for n_feats, e_idx, e_feats, target_risk, target_class in dataset:
            optimizer.zero_grad()
            res = model(n_feats, e_idx, e_feats)
            risk_pred = res["risk_tensor"]
            logits = res["logits_tensor"]

            loss_risk = criterion_risk(risk_pred, target_risk)
            loss_class = criterion_class(logits, target_class.unsqueeze(0))
            loss = loss_risk + loss_class

            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        if epoch % 5 == 0 or epoch == 25:
            print(f"    Epoch {epoch:02d}/25 - Loss: {total_loss / len(dataset):.4f}")

    # Save model weights
    save_path = os.path.join(os.path.dirname(__file__), "models", "kernelguard_gnn.pt")
    torch.save(model.state_dict(), save_path)
    print(f"[+] Model checkpoint successfully saved to: {save_path}")

if __name__ == "__main__":
    train_and_save()
