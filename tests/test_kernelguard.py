"""
Comprehensive Unit & Integration Test Suite for KernelGuard Framework
Validates all 7 major capabilities:
1. Real Host OS Sniffer (psutil)
2. In-Kernel Active Mitigation (SIGKILL / LSM simulation)
3. Causal Provenance Slicing (Backward & Forward)
4. GNNExplainer & Edge Saliency Heatmap
5. DARPA Transparent Computing (TC) Ingestion
6. Interactive Terminal Simulator & Sandbox API
7. Automated LaTeX Publication Exporter
"""

import unittest
from ebpf.telemetry_engine import TelemetryEngine
from ebpf.host_sniffer import HostTelemetrySniffer
from graph.temporal_graph import TemporalBehavioralGraph
from graph.feature_extractor import GraphFeatureExtractor
from models.gnn_transformer import AdaptiveInferenceEngine
from models.gnn_explainer import GNNExplainerEngine
from detection.risk_scorer import AdaptiveRiskScorer
from detection.mitigation import MitigationEngine
from datasets.darpa_tc_loader import DarpaTCLoader
from export.latex_exporter import LatexExporter
from fastapi.testclient import TestClient
from web.app import app

class TestKernelGuardComprehensive(unittest.TestCase):
    def setUp(self):
        self.telemetry = TelemetryEngine()
        self.graph = TemporalBehavioralGraph()
        self.extractor = GraphFeatureExtractor()
        self.model = AdaptiveInferenceEngine()
        self.scorer = AdaptiveRiskScorer(high_risk_threshold=0.70)
        self.mitigation = MitigationEngine()
        self.explainer = GNNExplainerEngine(model_wrapper=self.model)
        self.darpa = DarpaTCLoader()
        self.client = TestClient(app)

    # 1. Host OS Sniffer
    def test_01_host_sniffer(self):
        events = []
        sniffer = HostTelemetrySniffer(event_callback=lambda e: events.append(e))
        sniffer._poll_live_processes()
        self.assertTrue(len(events) > 0)
        self.assertTrue(events[0].pid > 0)
        self.assertTrue(len(events[0].comm) > 0)

    # 2. Active Mitigation
    def test_02_active_mitigation(self):
        result = self.mitigation.execute_mitigation(
            pid=9999,
            threat_class="Ransomware Mass Encryption",
            remote_ip="45.142.214.88",
            target_path="/home/user/docs.locked"
        )
        self.assertEqual(result["status"], "SUCCESS")
        self.assertGreater(len(result["actions_executed"]), 0)
        self.assertIn("SIGKILL", result["actions_executed"][0])
        self.assertTrue(result["mitigation_latency_ms"] > 0)

    # 3. Provenance Slicing (Backward & Forward)
    def test_03_provenance_slicing(self):
        events = self.telemetry.generate_attack_scenario("fileless")
        for e in events:
            self.graph.ingest_event(e)

        target_pid = events[-1].pid
        target_id = f"proc:{target_pid}"

        # Backward slice: traces back to initial curl / bash
        bw_slice = self.graph.backward_slice(target_id)
        self.assertEqual(bw_slice["direction"], "backward")
        self.assertGreater(len(bw_slice["slice_nodes"]), 0)
        self.assertIn("Backward provenance", bw_slice["narrative"])

        # Forward slice: blast radius
        fw_slice = self.graph.forward_slice(f"proc:{events[0].pid}")
        self.assertEqual(fw_slice["direction"], "forward")
        self.assertGreater(len(fw_slice["slice_nodes"]), 0)
        self.assertIn("Forward blast radius", fw_slice["narrative"])

    # 4. GNNExplainer & Saliency Heatmap
    def test_04_gnn_explainer(self):
        events = self.telemetry.generate_attack_scenario("fileless")
        for e in events:
            self.graph.ingest_event(e)

        sub = self.graph.get_process_subgraph(events[-1].pid)
        n, idx, e = self.extractor.extract_subgraph_tensors(sub)
        expl = self.explainer.explain_subgraph(n, idx, e, sub)

        self.assertIn("edge_saliency", expl)
        self.assertIn("critical_path", expl)
        self.assertGreater(len(expl["critical_path"]), 0)
        self.assertTrue(expl["max_saliency_pct"] > 50.0)

    # 5. DARPA Transparent Computing Replay
    def test_05_darpa_tc_ingestion(self):
        darpa_events = self.darpa.load_scenario_events()
        self.assertEqual(len(darpa_events), 7)
        for e in darpa_events:
            self.graph.ingest_event(e)

        sub = self.graph.get_process_subgraph(darpa_events[-1].pid)
        n, idx, e = self.extractor.extract_subgraph_tensors(sub)
        pred = self.model.predict(n, idx, e, sub)
        self.assertGreater(pred["risk_score"], 0.70)

    # 6. Interactive Terminal API
    def test_06_terminal_execution_api(self):
        res = self.client.post("/api/terminal/exec", json={"command": "whoami"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("output", data)
        self.assertIn("pid", data)

    # 7. Automated LaTeX Exporter
    def test_07_latex_exporter(self):
        bundle = LatexExporter.export_full_bundle()
        self.assertIn("benchmark_table_tex", bundle)
        self.assertIn("ablation_table_tex", bundle)
        self.assertIn(r"\begin{table}", bundle["benchmark_table_tex"])
        self.assertIn("KernelGuard", bundle["benchmark_table_tex"])
        self.assertIn("Ablation Study", bundle["ablation_table_tex"])

        # Test HTTP export
        res = self.client.get("/api/export/latex")
        self.assertEqual(res.status_code, 200)
        self.assertIn(r"\begin{table}", res.text)

if __name__ == "__main__":
    unittest.main()
