"""
KernelGuard Feature Extractor
Transforms dynamic behavioral graphs and temporal event sequences into numerical tensors
for the Hybrid GNN-Temporal Transformer model.
"""

import math
from typing import Dict, List, Any, Tuple
import numpy as np

NODE_TYPES = ["process", "file", "socket", "memory"]
SYSCALL_TYPES = [
    "sys_enter_execve", "sys_enter_fork", "sys_enter_openat", "sys_enter_unlinkat",
    "sys_enter_write", "sys_enter_connect", "sys_enter_mprotect", "sys_enter_memfd_create",
    "sys_enter_setuid"
]

class GraphFeatureExtractor:
    def __init__(self, node_feat_dim: int = 16, edge_feat_dim: int = 12):
        self.node_feat_dim = node_feat_dim
        self.edge_feat_dim = edge_feat_dim

    def encode_node(self, node: Dict[str, Any], in_degree: int = 0, out_degree: int = 0) -> np.ndarray:
        """
        Encodes node into a fixed-size feature vector:
        - [0:4]: Node type one-hot (process, file, socket, memory)
        - [4]: Root privilege flag (uid == 0)
        - [5]: In-degree (normalized)
        - [6]: Out-degree (normalized)
        - [7]: Sensitive file flag (e.g. /etc/shadow)
        - [8]: Ransomware extension / deletion indicator
        - [9]: External network socket flag
        - [10]: High-risk port flag (4444, 1337, etc.)
        - [11]: RWX memory violation flag
        - [12]: Fileless memfd indicator
        - [13:16]: Reserved / Structural centrality
        """
        feats = np.zeros(self.node_feat_dim, dtype=np.float32)
        ntype = node.get("type", "process")
        if ntype in NODE_TYPES:
            feats[NODE_TYPES.index(ntype)] = 1.0

        props = node.get("properties", {})
        if props.get("is_root", False) or props.get("uid", 1000) == 0:
            feats[4] = 1.0

        feats[5] = min(in_degree / 10.0, 1.0)
        feats[6] = min(out_degree / 10.0, 1.0)

        if props.get("is_sensitive", False):
            feats[7] = 1.0
        if props.get("is_ransom_ext", False):
            feats[8] = 1.0
        if props.get("is_external", False):
            feats[9] = 1.0
        if props.get("port", 0) in [4444, 1337, 8080, 9001]:
            feats[10] = 1.0
        if props.get("is_rwx", False):
            feats[11] = 1.0
        if props.get("is_fileless", False):
            feats[12] = 1.0

        # Base node risk score
        feats[13] = float(node.get("risk_score", 0.0))
        return feats

    def encode_edge(self, edge: Dict[str, Any], time_delta_sec: float = 0.0) -> np.ndarray:
        """
        Encodes an edge syscall operation and temporal gap:
        - [0:9]: Syscall type one-hot
        - [9]: Log normalized temporal delta
        - [10]: Causal lineage flag (process -> child process)
        - [11]: Edge weight / frequency
        """
        feats = np.zeros(self.edge_feat_dim, dtype=np.float32)
        syscall = edge.get("syscall", "")
        for idx, sc in enumerate(SYSCALL_TYPES):
            if sc in syscall:
                feats[idx] = 1.0
                break
        else:
            # Fallback based on edge_type
            etype = edge.get("edge_type", "")
            mapping = {
                "exec": 0, "open": 2, "unlink": 3, "file_io": 4,
                "connect": 5, "mprotect": 6, "memfd": 7, "setuid": 8
            }
            if etype in mapping:
                feats[mapping[etype]] = 1.0

        # Log temporal delta
        feats[9] = min(math.log1p(max(0.0, time_delta_sec)), 5.0) / 5.0
        feats[10] = 1.0 if edge.get("edge_type") == "exec" else 0.0
        feats[11] = float(edge.get("weight", 1.0))
        return feats

    def extract_subgraph_tensors(self, subgraph: Dict[str, Any]) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Converts subgraph into:
        - node_features: [num_nodes, node_feat_dim]
        - edge_index: [2, num_edges] (source_idx, target_idx)
        - edge_features: [num_edges, edge_feat_dim]
        """
        nodes = subgraph.get("nodes", [])
        edges = subgraph.get("edges", [])

        if not nodes:
            return np.zeros((1, self.node_feat_dim), dtype=np.float32), np.zeros((2, 0), dtype=np.int64), np.zeros((0, self.edge_feat_dim), dtype=np.float32)

        node_id_map = {n["id"]: idx for idx, n in enumerate(nodes)}
        num_nodes = len(nodes)

        # Calculate degrees
        in_deg = [0] * num_nodes
        out_deg = [0] * num_nodes
        for e in edges:
            s_idx = node_id_map.get(e["source"])
            t_idx = node_id_map.get(e["target"])
            if s_idx is not None and t_idx is not None:
                out_deg[s_idx] += 1
                in_deg[t_idx] += 1

        node_feats = np.stack([
            self.encode_node(n, in_deg[i], out_deg[i]) for i, n in enumerate(nodes)
        ], axis=0)

        edge_sources = []
        edge_targets = []
        edge_feats_list = []

        last_ts = edges[0].get("timestamp_ns", 0) if edges else 0
        for e in edges:
            s_idx = node_id_map.get(e["source"])
            t_idx = node_id_map.get(e["target"])
            if s_idx is not None and t_idx is not None:
                edge_sources.append(s_idx)
                edge_targets.append(t_idx)
                cur_ts = e.get("timestamp_ns", 0)
                dt = max(0.0, (cur_ts - last_ts) / 1e9)
                last_ts = cur_ts
                edge_feats_list.append(self.encode_edge(e, dt))

        if edge_sources:
            edge_index = np.array([edge_sources, edge_targets], dtype=np.int64)
            edge_features = np.stack(edge_feats_list, axis=0)
        else:
            edge_index = np.zeros((2, 0), dtype=np.int64)
            edge_features = np.zeros((0, self.edge_feat_dim), dtype=np.float32)

        return node_feats, edge_index, edge_features
