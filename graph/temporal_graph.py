"""
KernelGuard Temporal Behavioral Graph Engine
Maintains dynamic multi-entity behavioral graph:
Processes, Files, Sockets, and Memory allocations linked by directed, timestamped syscall edges.
Supports temporal windowing and suspicious lineage subgraph extraction.
"""

import time
import math
from typing import Dict, List, Any, Optional, Set, Tuple
from pydantic import BaseModel

class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # "process", "file", "socket", "memory"
    properties: Dict[str, Any]
    risk_score: float = 0.0

class GraphEdge(BaseModel):
    source: str
    target: str
    syscall: str
    timestamp_ns: int
    edge_type: str  # "exec", "open", "unlink", "connect", "mprotect", "memfd", "setuid"
    weight: float = 1.0
    properties: Dict[str, Any] = {}

class TemporalBehavioralGraph:
    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = window_seconds
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self.process_tree: Dict[int, Set[int]] = {} # ppid -> set of pids
        self.pid_to_node_id: Dict[int, str] = {}
        self.max_edges = 2000

    def ingest_event(self, ev) -> Tuple[Optional[str], Optional[GraphEdge]]:
        """
        Ingests a KernelEvent and updates the temporal multi-graph.
        Returns the affected process node ID and the newly created GraphEdge.
        """
        proc_id = f"proc:{ev.pid}"
        self.pid_to_node_id[ev.pid] = proc_id

        # Update process tree
        if ev.ppid not in self.process_tree:
            self.process_tree[ev.ppid] = set()
        self.process_tree[ev.ppid].add(ev.pid)

        # 1. Ensure or update source Process Node
        if proc_id not in self.nodes:
            self.nodes[proc_id] = GraphNode(
                id=proc_id,
                label=f"{ev.comm} (PID {ev.pid})",
                type="process",
                properties={
                    "pid": ev.pid,
                    "ppid": ev.ppid,
                    "comm": ev.comm,
                    "pcomm": ev.pcomm,
                    "uid": ev.uid,
                    "is_root": ev.uid == 0,
                    "created_at_ns": ev.timestamp_ns
                }
            )
        else:
            # Update dynamic properties like uid transitions
            self.nodes[proc_id].properties["uid"] = ev.uid
            self.nodes[proc_id].properties["is_root"] = (ev.uid == 0)

        # 2. Process parent link if parent node exists
        if ev.ppid in self.pid_to_node_id:
            parent_id = self.pid_to_node_id[ev.ppid]
            if parent_id not in self.nodes:
                self.nodes[parent_id] = GraphNode(
                    id=parent_id,
                    label=f"{ev.pcomm} (PID {ev.ppid})",
                    type="process",
                    properties={"pid": ev.ppid, "comm": ev.pcomm, "created_at_ns": ev.timestamp_ns}
                )

        target_id = None
        edge_type = "unknown"

        # 3. Create target node and edge based on event_type
        if ev.event_type in ("EVENT_PROCESS_EXEC", "1"):
            target_id = proc_id
            edge_type = "exec"
            source_id = self.pid_to_node_id.get(ev.ppid, f"proc:{ev.ppid}")
            if source_id not in self.nodes:
                self.nodes[source_id] = GraphNode(
                    id=source_id,
                    label=f"{ev.pcomm} (PID {ev.ppid})",
                    type="process",
                    properties={"pid": ev.ppid, "comm": ev.pcomm}
                )
            edge = GraphEdge(
                source=source_id,
                target=target_id,
                syscall=ev.raw_syscall or "sys_enter_execve",
                timestamp_ns=ev.timestamp_ns,
                edge_type=edge_type,
                properties={"path": ev.target_path}
            )
            self.edges.append(edge)
            self._trim_window()
            return proc_id, edge

        elif ev.event_type in ("EVENT_MEMFD_CREATE", "10"):
            target_id = f"memfd:{ev.pid}:{ev.target_path or 'anon'}"
            edge_type = "memfd"
            if target_id not in self.nodes:
                self.nodes[target_id] = GraphNode(
                    id=target_id,
                    label=f"memfd: {ev.target_path}",
                    type="memory",
                    properties={"is_fileless": True, "name": ev.target_path},
                    risk_score=0.75
                )

        elif ev.event_type in ("EVENT_MEM_PROTECT", "9"):
            target_id = f"mem:{ev.pid}:{ev.mem_addr}"
            edge_type = "mprotect"
            is_rwx = "PROT_EXEC" in str(ev.mem_prot) and ("PROT_WRITE" in str(ev.mem_prot) or "0x7" in str(ev.mem_prot))
            if target_id not in self.nodes:
                self.nodes[target_id] = GraphNode(
                    id=target_id,
                    label=f"mem: {ev.mem_addr} ({ev.mem_prot})",
                    type="memory",
                    properties={"prot": ev.mem_prot, "is_rwx": is_rwx, "addr": ev.mem_addr},
                    risk_score=0.85 if is_rwx else 0.2
                )

        elif ev.event_type in ("EVENT_FILE_OPEN", "EVENT_FILE_UNLINK", "EVENT_FILE_WRITE", "4", "5", "6"):
            target_id = f"file:{ev.target_path}"
            edge_type = "unlink" if "UNLINK" in ev.event_type or ev.event_type == "5" else "file_io"
            is_sensitive = any(s in ev.target_path for s in ["/etc/shadow", "/etc/passwd", "credentials", "id_rsa", ".kdbx"])
            is_ransom_ext = any(ev.target_path.endswith(ext) for ext in [".locked", ".crypted", ".enc", "README"])
            if target_id not in self.nodes:
                self.nodes[target_id] = GraphNode(
                    id=target_id,
                    label=ev.target_path.split("/")[-1] or ev.target_path,
                    type="file",
                    properties={
                        "path": ev.target_path,
                        "is_sensitive": is_sensitive,
                        "is_ransom_ext": is_ransom_ext
                    },
                    risk_score=0.9 if is_sensitive or is_ransom_ext else 0.05
                )

        elif ev.event_type in ("EVENT_NET_CONNECT", "EVENT_NET_BIND", "7", "8"):
            target_id = f"sock:{ev.net_daddr}:{ev.net_dport}"
            edge_type = "connect"
            is_external = not (ev.net_daddr.startswith("127.") or ev.net_daddr.startswith("10.") or ev.net_daddr.startswith("192.168."))
            if target_id not in self.nodes:
                self.nodes[target_id] = GraphNode(
                    id=target_id,
                    label=f"{ev.net_daddr}:{ev.net_dport}",
                    type="socket",
                    properties={
                        "ip": ev.net_daddr,
                        "port": ev.net_dport,
                        "is_external": is_external
                    },
                    risk_score=0.6 if is_external and ev.net_dport in [4444, 1337, 8080, 9001] else 0.1
                )

        elif ev.event_type in ("EVENT_PRIV_SETUID", "11"):
            target_id = f"priv:uid_{ev.uid}"
            edge_type = "setuid"
            if target_id not in self.nodes:
                self.nodes[target_id] = GraphNode(
                    id=target_id,
                    label=f"Privilege: UID={ev.uid}",
                    type="memory",
                    properties={"target_uid": ev.uid, "is_root_escalation": ev.uid == 0},
                    risk_score=0.95 if ev.uid == 0 else 0.1
                )

        edge = None
        if target_id:
            edge = GraphEdge(
                source=proc_id,
                target=target_id,
                syscall=ev.raw_syscall or "syscall",
                timestamp_ns=ev.timestamp_ns,
                edge_type=edge_type,
                properties={"comm": ev.comm, "uid": ev.uid}
            )
            self.edges.append(edge)

        self._trim_window()
        return proc_id, edge

    def _trim_window(self):
        """Trims old events outside the temporal sliding window or exceeding max limit."""
        if len(self.edges) > self.max_edges:
            self.edges = self.edges[-self.max_edges:]

    def get_process_subgraph(self, pid: int, depth: int = 3) -> Dict[str, Any]:
        """
        Extracts causal subgraph centered around a target process,
        including parents, children, and all connected entities (files, sockets, memory).
        """
        start_id = f"proc:{pid}"
        if start_id not in self.nodes:
            return {"nodes": [], "edges": []}

        relevant_nodes: Set[str] = {start_id}
        frontier: Set[str] = {start_id}

        for _ in range(depth):
            next_frontier = set()
            for edge in self.edges:
                if edge.source in frontier and edge.target not in relevant_nodes:
                    relevant_nodes.add(edge.target)
                    next_frontier.add(edge.target)
                elif edge.target in frontier and edge.source not in relevant_nodes:
                    relevant_nodes.add(edge.source)
                    next_frontier.add(edge.source)
            frontier = next_frontier

        sub_nodes = [self.nodes[nid].model_dump() for nid in relevant_nodes if nid in self.nodes]
        sub_edges = [e.model_dump() for e in self.edges if e.source in relevant_nodes and e.target in relevant_nodes]

        return {"nodes": sub_nodes, "edges": sub_edges}

    def to_dict(self) -> Dict[str, Any]:
        """Exports full active graph state for visualizer and inference."""
        return {
            "nodes": [n.model_dump() for n in self.nodes.values()],
            "edges": [e.model_dump() for e in self.edges]
        }

    def clear(self):
        self.nodes.clear()
        self.edges.clear()
        self.process_tree.clear()
        self.pid_to_node_id.clear()
