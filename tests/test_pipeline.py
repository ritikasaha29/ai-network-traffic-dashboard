"""
Unit and Integration Test Suite for AI-Driven Network Traffic Intelligence Dashboard.
Verifies packet capture, flow extraction, machine learning classification,
forensics parsing, and defensive rule generation.
"""

import os
import sys
import unittest

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.traffic_generator import TrafficGenerator
from core.sniffer import PacketDissector, PacketSnifferManager
from core.feature_extractor import FlowAggregator
from core.ai_engine import AIEngine
from core.forensics import ForensicsAnalyzer

class TestNetworkIntelligencePipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_pcap_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "pcap_samples"))
        TrafficGenerator.create_sample_pcaps(cls.test_pcap_dir)
        cls.ai_engine = AIEngine()
        cls.forensics = ForensicsAnalyzer()

    def test_01_pcap_files_generated(self):
        """Verifies synthetic PCAP samples are created on disk."""
        files = [
            "normal_traffic.pcap",
            "syn_flood_attack.pcap",
            "port_scan_recon.pcap",
            "dns_tunneling_exfiltration.pcap",
            "multicast_chatter.pcap",
            "arp_spoofing.pcap",
            "slowloris_attack.pcap",
            "comprehensive_enterprise_trace.pcap"
        ]
        for f in files:
            path = os.path.join(self.test_pcap_dir, f)
            self.assertTrue(os.path.exists(path), f"Missing PCAP file: {path}")
            self.assertGreater(os.path.getsize(path), 100, f"PCAP file is empty: {path}")

    def test_02_packet_dissection(self):
        """Tests parsing of raw packets into forensic dictionary."""
        pcap_path = os.path.join(self.test_pcap_dir, "normal_traffic.pcap")
        sniffer = PacketSnifferManager()
        records = sniffer.load_pcap(pcap_path)
        
        self.assertGreater(len(records), 0)
        sample = records[0]
        self.assertIn("timestamp", sample)
        self.assertIn("src_ip", sample)
        self.assertIn("dst_ip", sample)
        self.assertIn("protocol", sample)
        self.assertIn("info", sample)

    def test_03_flow_feature_extraction(self):
        """Tests aggregation of packets into flows and feature calculation."""
        pcap_path = os.path.join(self.test_pcap_dir, "comprehensive_enterprise_trace.pcap")
        sniffer = PacketSnifferManager()
        records = sniffer.load_pcap(pcap_path)

        aggregator = FlowAggregator()
        for rec in records:
            aggregator.process_packet(rec)

        flows = aggregator.get_all_flow_features()
        self.assertGreater(len(flows), 0)
        
        flow_sample = flows[0]
        required_keys = [
            "flow_id", "duration", "total_packets", "total_bytes",
            "packet_rate", "byte_rate", "pkt_len_mean", "iat_mean",
            "syn_ratio", "payload_entropy_mean"
        ]
        for k in required_keys:
            self.assertIn(k, flow_sample, f"Missing flow feature: {k}")

    def test_04_ai_inference_and_anomaly_detection(self):
        """Tests AI multi-class prediction and Isolation Forest zero-day anomaly score."""
        pcap_path = os.path.join(self.test_pcap_dir, "syn_flood_attack.pcap")
        sniffer = PacketSnifferManager()
        records = sniffer.load_pcap(pcap_path)

        aggregator = FlowAggregator()
        for rec in records:
            aggregator.process_packet(rec)

        flows = aggregator.get_all_flow_features()
        self.assertGreater(len(flows), 0)

        for flow in flows:
            result = self.ai_engine.predict_flow(flow)
            self.assertIn("prediction", result)
            self.assertIn("confidence", result)
            self.assertIn("is_anomaly", result)
            self.assertIn("severity", result)

    def test_05_benchmarking_results(self):
        """Verifies multi-model benchmark metrics for Bloom's Taxonomy Evaluate Level [10 marks]."""
        benchmarks = self.ai_engine.benchmark_results
        self.assertIn("Random Forest", benchmarks)
        self.assertIn("Decision Tree", benchmarks)
        self.assertIn("Logistic Regression", benchmarks)
        self.assertIn("Isolation Forest (Zero-Day)", benchmarks)

        rf = benchmarks["Random Forest"]
        self.assertGreater(rf["accuracy"], 90.0)
        self.assertGreater(rf["f1_score"], 90.0)

    def test_06_forensics_and_mitigation_generation(self):
        """Tests Wireshark display filter emulation and firewall rule creation."""
        pcap_path = os.path.join(self.test_pcap_dir, "comprehensive_enterprise_trace.pcap")
        sniffer = PacketSnifferManager()
        records = sniffer.load_pcap(pcap_path)

        forensic_stats = self.forensics.analyze_stream(records)
        self.assertIn("total_packets", forensic_stats)
        self.assertIn("protocol_counts", forensic_stats)
        self.assertIn("tcp_vs_udp", forensic_stats)

        # Wireshark filter test
        filtered_dns = self.forensics.apply_filter(records, "dns")
        for p in filtered_dns:
            self.assertTrue(p["protocol"] == "DNS" or p.get("dns_query") is not None)

        # Mitigation test
        dummy_threat = {"src_ip": "10.0.0.99", "dst_port": 80, "protocol": "TCP", "prediction": "SYN_FLOOD"}
        rules = self.forensics.generate_mitigation_rules(dummy_threat)
        self.assertIn("iptables", rules)
        self.assertIn("windows_netsh", rules)
        self.assertIn("DROP", rules["iptables"])

if __name__ == "__main__":
    unittest.main()
