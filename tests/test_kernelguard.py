"""
Unit and Integration Tests for KernelGuard Framework
Validates:
1. eBPF Telemetry serialization & generation
2. Temporal Behavioral Graph dynamic ingestion & windowing
3. Feature Extractor numerical vectorization
4. Hybrid GNN-Transformer forward pass & attention attribution
5. Adaptive Risk Scorer & MITRE ATT&CK mapping
6. REST API Endpoints
"""

import unittest
from ebpf.telemetry_engine import TelemetryEngine
from graph.temporal_graph import TemporalBehavioralGraph
from graph.feature_extractor import GraphFeatureExtractor
from models.gnn_transformer import AdaptiveInferenceEngine
from detection.risk_scorer import AdaptiveRiskScorer
from fastapi.testclient import TestClient
from web.app import app

class TestKernelGuard(unittest.TestCase):
    def setUp(self):
        self.telemetry = TelemetryEngine()
        self.graph = TemporalBehavioralGraph()
        self.extractor = GraphFeatureExtractor()
        self.model = AdaptiveInferenceEngine()
        self.scorer = AdaptiveRiskScorer(high_risk_threshold=0.70)
        self.client = TestClient(app)

    def test_01_telemetry_generation(self):
        ev = self.telemetry.generate_benign_event()
        self.assertIsNotNone(ev.pid)
        self.assertTrue(ev.comm)
        self.assertTrue(ev.timestamp_ns > 0)

        # Test attack scenario generation
        fileless_events = self.telemetry.generate_attack_scenario("fileless")
        self.assertTrue(len(fileless_events) >= 4)
        has_memfd = any(e.event_type == "EVENT_MEMFD_CREATE" for e in fileless_events)
        self.assertTrue(has_memfd)

    def test_02_graph_ingestion(self):
        events = self.telemetry.generate_attack_scenario("ransomware")
        for e in events:
            proc_id, edge = self.graph.ingest_event(e)
            self.assertTrue(proc_id.startswith("proc:"))
        
        self.assertTrue(len(self.graph.nodes) > 3)
        self.assertTrue(len(self.graph.edges) >= len(events) - 1)

        # Test subgraph extraction
        target_pid = events[-1].pid
        sub = self.graph.get_process_subgraph(target_pid)
        self.assertTrue(len(sub["nodes"]) > 0)

    def test_03_feature_extraction(self):
        events = self.telemetry.generate_attack_scenario("privesc")
        for e in events:
            self.graph.ingest_event(e)
        
        target_pid = events[-1].pid
        sub = self.graph.get_process_subgraph(target_pid)
        n_feats, e_idx, e_feats = self.extractor.extract_subgraph_tensors(sub)

        self.assertEqual(n_feats.shape[1], 16)
        self.assertEqual(e_feats.shape[1], 12)
        self.assertEqual(e_idx.shape[0], 2)

    def test_04_gnn_inference_and_attribution(self):
        events = self.telemetry.generate_attack_scenario("fileless")
        for e in events:
            self.graph.ingest_event(e)
        target_pid = events[-1].pid
        sub = self.graph.get_process_subgraph(target_pid)
        n, idx, e = self.extractor.extract_subgraph_tensors(sub)
        pred = self.model.predict(n, idx, e, sub)

        self.assertIn("risk_score", pred)
        self.assertIn("threat_class", pred)
        self.assertEqual(pred["threat_class"], "Fileless In-Memory Malware")
        self.assertGreater(pred["risk_score"], 0.70)
        self.assertTrue(len(pred["subgraph_attention_edges"]) > 0)

    def test_05_risk_scorer_and_mitre_mapping(self):
        events = self.telemetry.generate_attack_scenario("reverse_shell")
        for e in events:
            self.graph.ingest_event(e)
        target_pid = events[-1].pid
        sub = self.graph.get_process_subgraph(target_pid)
        n, idx, e = self.extractor.extract_subgraph_tensors(sub)
        pred = self.model.predict(n, idx, e, sub)
        assessment = self.scorer.evaluate(pred, sub, target_pid)

        self.assertTrue(assessment["is_malicious"])
        self.assertGreater(assessment["composite_risk_score"], 0.70)
        self.assertTrue(len(assessment["mitre_attack_techniques"]) > 0)
        self.assertTrue(len(assessment["causal_anomaly_explanations"]) > 0)

    def test_06_fastapi_endpoints(self):
        res_status = self.client.get("/api/status")
        self.assertEqual(res_status.status_code, 200)
        self.assertEqual(res_status.json()["status"], "online")

        res_scenario = self.client.post("/api/scenario/fileless")
        self.assertEqual(res_scenario.status_code, 200)
        self.assertEqual(res_scenario.json()["status"], "ok")

        res_graph = self.client.get("/api/graph")
        self.assertEqual(res_graph.status_code, 200)
        self.assertIn("nodes", res_graph.json())

        res_benchmark = self.client.get("/api/benchmark")
        self.assertEqual(res_benchmark.status_code, 200)
        self.assertIn("metrics", res_benchmark.json())

if __name__ == "__main__":
    unittest.main()
