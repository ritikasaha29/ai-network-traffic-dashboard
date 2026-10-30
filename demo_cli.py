"""
Terminal Demonstration CLI for AI-Driven Network Traffic Intelligence Dashboard.
Course: BCSE308P - Computer Networks Lab (Class ID: VL2026270103216)
School of Computer Science and Engineering, VIT Vellore
Faculty Incharge: Dr. S. Ebenezer Juliet
"""

import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.traffic_generator import TrafficGenerator
from core.sniffer import PacketDissector, PacketSnifferManager
from core.feature_extractor import FlowAggregator
from core.ai_engine import AIEngine
from core.forensics import ForensicsAnalyzer
from core.session import CaptureSession

def print_banner():
    print("=" * 80)
    print("      AI-DRIVEN NETWORK TRAFFIC INTELLIGENCE DASHBOARD - TERMINAL DEMO")
    print("      Course: BCSE308P Computer Networks Lab | VIT Vellore (2026-2027)")
    print("      Faculty Incharge: Dr. S. Ebenezer Juliet, Professor Grade 1, SCOPE")
    print("=" * 80)

def run_full_demo():
    print_banner()

    pcap_dir = os.path.join(os.path.dirname(__file__), "pcap_samples")
    os.makedirs(pcap_dir, exist_ok=True)
    pcap_path = os.path.join(pcap_dir, "comprehensive_enterprise_trace.pcap")

    print("\n[STEP 1: BLOOM'S TAXONOMY - APPLY LEVEL]")
    print(">>> Generating Synthetic Multi-Protocol Traffic & Weaponized PCAP Traces...")
    TrafficGenerator.create_sample_pcaps(pcap_dir)
    print(f"[+] PCAPs generated successfully in: {pcap_dir}")
    for f in os.listdir(pcap_dir):
        if f.endswith(".pcap"):
            sz = os.path.getsize(os.path.join(pcap_dir, f))
            print(f"    - {f} ({sz} bytes)")

    print("\n[STEP 2: PACKET DISSECTION & FLOW FEATURE EXTRACTION]")
    print(f">>> Loading & Dissecting Trace: {os.path.basename(pcap_path)} ...")
    session = CaptureSession()
    info = session.load_pcap(pcap_path)            # streamed packet by packet; flows + detectors see every packet
    records = session.sniffer.get_records()
    print(f"[+] Successfully parsed {info['packets_read']} raw frames.")

    flows = session.aggregator.get_all_flow_features()
    print(f"[+] Reconstructed {len(flows)} bidirectional conversation flows with NetFlow/IPFIX features.")

    print("\n[STEP 3: BLOOM'S TAXONOMY - ANALYSIS LEVEL (WIRESHARK FORENSICS)]")
    forensics = ForensicsAnalyzer()
    stats = forensics.analyze_stream(records)

    print("--- PROTOCOL DISTRIBUTION ---")
    for proto, count in stats["protocol_counts"].items():
        pct = (count / len(records)) * 100
        print(f"    * {proto:<10}: {count:>4} packets ({pct:.1f}%)")

    print("\n--- COMPARATIVE ANALYSIS: TCP vs UDP (Problem Statement IV) ---")
    t_v_u = stats["tcp_vs_udp"]
    print(f"    * TCP Packets         : {t_v_u['tcp_packet_count']}")
    print(f"    * UDP Packets         : {t_v_u['udp_packet_count']}")
    print(f"    * TCP Total Bytes     : {t_v_u['tcp_total_bytes']} bytes (Avg: {t_v_u['tcp_avg_packet_size']} B/pkt)")
    print(f"    * UDP Total Bytes     : {t_v_u['udp_total_bytes']} bytes (Avg: {t_v_u['udp_avg_packet_size']} B/pkt)")
    print(f"    * Completed Handshakes: {t_v_u['tcp_handshakes_completed']}")
    print(f"    * Half-Open SYNs      : {t_v_u['tcp_half_open_syn']} (SYN Flood anomaly indicator)")
    print(f"    * Retransmission Count: {stats['retransmission_count']}")
    print(f"    * Estimated Avg RTT   : {stats['avg_rtt_ms']} ms")

    print("\n[STEP 4: BLOOM'S TAXONOMY - EVALUATE LEVEL (AI BENCHMARKING)]")
    print(">>> Initializing AI Multi-Model Inference & Benchmarking Suite...")
    ai = AIEngine()
    benchmarks = ai.benchmark_results

    print(f"{'Model Architecture':<30} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Latency (ms)':<12}")
    print("-" * 92)
    for model_name, m in benchmarks.items():
        print(f"{model_name:<30} | {m['accuracy']:>9.2f}% | {m['precision']:>9.2f}% | {m['recall']:>9.2f}% | {m['f1_score']:>9.2f}% | {m['inference_latency_ms']:>10.4f} ms")

    print("\n--- FEATURE IMPORTANCE RANKING (Top 5 Discriminants) ---")
    feat_imp = list(ai.get_feature_importances().items())[:5]
    for feat, imp in feat_imp:
        print(f"    * {feat:<24}: {imp:.2f}%")

    print("\n[STEP 5: INCIDENT DETECTION, CONFIDENCE THRESHOLD & MITIGATION SYNTHESIS]")
    analysis = session.analyze(ai, threshold=70.0)
    sup = analysis["suppression"]
    print(f"[+] {len(analysis['flow_predictions'])} flows analysed -> {len(analysis['confirmed'])} confirmed incident(s), "
          f"{len(analysis['needs_review'])} needing review (threshold 70%)")
    print(f"    {sup['flows_guardrailed']} flow(s) judged benign by the multicast/broadcast/L2 guardrail")

    for inc in analysis["incidents"][:8]:
        conf = f"{inc['confidence']:g}%" if inc["confidence"] is not None else "n/a"
        print(f"\n  [{inc['incident_id']}] {inc['type']}  status={inc['status']}  severity={inc['severity']}  confidence={conf}")
        print(f"    {inc['summary']}")
        if inc["status"] == "CONFIRMED":
            rules = ForensicsAnalyzer.generate_incident_mitigation(inc)
            print(f"    [Linux]   {rules['iptables'].splitlines()[0]}")
        else:
            print(f"    not raised: {inc['review_reason']}")

    print("\n" + "=" * 80)
    print("  [SUCCESS] All pipeline stages executed successfully.")
    print("  To launch the interactive GUI dashboard, run:")
    print("      streamlit run dashboard/app.py")
    print("=" * 80)

if __name__ == "__main__":
    run_full_demo()
