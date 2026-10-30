"""
Tests for the multicast fix, incidents / confidence threshold, allowlist, streaming loader,
ARP spoofing + Slowloris detectors, and the PDF / Markdown report.
"""

import os
import random
import sys
import tempfile
import unittest
import warnings

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scapy.all import wrpcap

import core.ai_engine as ai_mod
from core.ai_engine import AIEngine
from core.allowlist import Allowlist, normalize_entry
from core.detectors import ARPSpoofDetector, SlowlorisDetector
from core.feature_extractor import is_group_address, is_group_mac
from core.forensics import ForensicsAnalyzer
from core.incidents import build_incidents, CONFIRMED, NEEDS_REVIEW
from core.report import build_report, render_markdown, render_pdf
from core.session import CaptureSession
from core.sniffer import PacketSnifferManager, PacketDissector
from core.traffic_generator import TrafficGenerator as G


def flow(pred="PORT_SCAN", conf=90.0, src="192.168.1.99", dst="192.168.1.50", dport=22, pkts=2, **kw):
    base = {"flow_id": f"{src}->{dst}:{dport}", "src_ip": src, "dst_ip": dst, "src_port": 40000, "dst_port": dport, "protocol": "TCP",
            "prediction": pred, "confidence": conf, "severity": "HIGH", "mitigation_required": True, "is_anomaly": False,
            "total_packets": pkts, "total_bytes": pkts * 60, "packet_rate": 10.0, "syn_ratio": 0.5, "rst_ratio": 0.5,
            "payload_entropy_mean": 0.0, "dns_query_len_mean": 0.0, "dns_entropy_mean": 0.0,
            "start_time": 100.0, "end_time": 101.0, "guardrail": None}
    base.update(kw)
    return base


def packets_to_pcap(pkts, tmpdir, name="t.pcap"):
    path = os.path.join(tmpdir, name)
    wrpcap(path, pkts)
    return path


class SharedEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ai = AIEngine()


class TestMulticastFix(SharedEngine):
    def test_group_address_helpers(self):
        for ip in ("224.0.0.251", "239.255.255.250", "255.255.255.255", "192.168.1.255", "ff02::fb"):
            self.assertTrue(is_group_address(ip), ip)
        for ip in ("192.168.1.10", "8.8.8.8", "2001:db8::1", "not-an-ip"):
            self.assertFalse(is_group_address(ip), ip)
        self.assertTrue(is_group_mac("ff:ff:ff:ff:ff:ff"))
        self.assertTrue(is_group_mac("01:00:5e:00:00:fb"))
        self.assertFalse(is_group_mac("02:00:c0:a8:01:0a"))

    def test_multicast_chatter_raises_no_incident(self):
        """The reported bug: mDNS / SSDP chatter was classified as UDP DDoS / tunnelling."""
        random.seed(11)
        with tempfile.TemporaryDirectory() as d:
            path = packets_to_pcap(G.generate_multicast_chatter(count=120, storm_probability=0.1), d)
            s = CaptureSession(); s.load_pcap(path)
            a = s.analyze(self.ai)
        self.assertGreater(len(a["flow_predictions"]), 10)
        self.assertEqual(a["confirmed"], [])
        self.assertEqual(sum(1 for f in a["flow_predictions"] if f["mitigation_required"]), 0)

    def test_every_multicast_flow_is_marked(self):
        random.seed(12)
        pkts = G.generate_multicast_chatter(count=40)
        s = CaptureSession(); s.inject(pkts)
        group_flows = [f for f in s.aggregator.get_all_flow_features() if is_group_address(f["dst_ip"])]
        self.assertTrue(group_flows)
        self.assertTrue(all(f["is_multicast_dst"] == 1 for f in group_flows))

    def test_guardrail_blocks_flood_verdict_only_for_group_destinations(self):
        random.seed(13)
        s = CaptureSession(); s.inject(G.generate_syn_flood(count=40))
        f = s.aggregator.get_all_flow_features()[0]
        self.assertEqual(self.ai.predict_flow(f)["prediction"], "SYN_FLOOD")
        as_multicast = dict(f, is_multicast_dst=1)
        r = self.ai.predict_flow(as_multicast)
        self.assertEqual(r["prediction"], "NORMAL")
        self.assertFalse(r["mitigation_required"])
        self.assertIsNotNone(r["guardrail"])
        self.assertEqual(r["model_prediction"], "SYN_FLOOD")      # the bare model still says flood: the rule is what overrides it
        self.ai.guardrails_enabled = False
        try:
            off = self.ai.predict_flow(as_multicast)
            self.assertIsNone(off["guardrail"])
            self.assertEqual(off["prediction"], "SYN_FLOOD")      # and the switch really turns the rule off
        finally:
            self.ai.guardrails_enabled = True

    def test_real_attacks_still_detected(self):
        random.seed(14)
        pkts = G.generate_syn_flood(80) + G.generate_port_scan() + G.generate_dns_tunneling(40) + G.generate_udp_ddos(60)
        s = CaptureSession(); s.inject(pkts)
        types = {i["type"] for i in s.analyze(self.ai)["confirmed"]}
        self.assertTrue({"SYN_FLOOD", "PORT_SCAN", "DNS_TUNNELING", "UDP_DDOS"} <= types, types)

    def test_changed_feature_list_forces_retrain(self):
        """Models saved with a different feature list must not be reused."""
        import pandas as pd
        calls = {"n": 0}
        orig_rows, orig_hold = AIEngine._generator_training_rows, AIEngine._evaluate_holdout

        def small_rows(cls, n_batches=24, seed_base=1000):
            calls["n"] += 1
            return orig_rows.__func__(cls, n_batches=2, seed_base=seed_base)

        AIEngine._generator_training_rows = classmethod(small_rows)
        AIEngine._evaluate_holdout = lambda self: {}
        try:
            with tempfile.TemporaryDirectory() as d:
                AIEngine(model_dir=d)
                self.assertEqual(calls["n"], 1)
                AIEngine(model_dir=d)                       # same features: loaded from disk
                self.assertEqual(calls["n"], 1)
                import joblib
                meta = joblib.load(os.path.join(d, "model_meta.joblib"))
                meta["feature_columns"] = meta["feature_columns"][:-1]    # pretend the feature list changed
                joblib.dump(meta, os.path.join(d, "model_meta.joblib"))
                AIEngine(model_dir=d)
                self.assertEqual(calls["n"], 2)             # retrained
                os.remove(os.path.join(d, "model_meta.joblib"))             # models from before metadata existed
                AIEngine(model_dir=d)
                self.assertEqual(calls["n"], 3)
        finally:
            AIEngine._generator_training_rows, AIEngine._evaluate_holdout = orig_rows, orig_hold


class TestIncidentsAndThreshold(unittest.TestCase):
    def test_low_confidence_is_needs_review_not_confirmed(self):
        flows = [flow(conf=55.5, dport=p) for p in range(20, 32)]       # the 55.5% port-scan case
        inc, _ = build_incidents(flows, threshold=70.0)
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["status"], NEEDS_REVIEW)
        self.assertEqual(inc[0]["confidence"], 55.5)
        self.assertIn("below", inc[0]["review_reason"])

    def test_threshold_is_adjustable(self):
        flows = [flow(conf=55.5, dport=p) for p in range(20, 32)]
        self.assertEqual(build_incidents(flows, threshold=50.0)[0][0]["status"], CONFIRMED)
        self.assertEqual(build_incidents([flow(conf=70.0, dport=p) for p in range(20, 32)], threshold=70.0)[0][0]["status"], CONFIRMED)

    def test_too_little_evidence_is_not_raised(self):
        inc, _ = build_incidents([flow(pred="SYN_FLOOD", conf=100.0, pkts=1)], threshold=70.0)
        self.assertEqual(inc[0]["status"], NEEDS_REVIEW)
        self.assertIn("needs", inc[0]["review_reason"])

    def test_flood_of_many_sources_is_one_incident(self):
        flows = [flow(pred="SYN_FLOOD", conf=100.0, src=f"10.0.{i // 250}.{i % 250 + 1}", dst="192.168.1.100", dport=80, pkts=1) for i in range(60)]
        inc, _ = build_incidents(flows)
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["flows"], 60)
        self.assertEqual(inc[0]["status"], CONFIRMED)

    def test_anomaly_only_is_always_review(self):
        f = flow(pred="NORMAL", conf=99.0, is_anomaly=True)
        inc, _ = build_incidents([f] * 5)
        self.assertEqual(inc[0]["type"], "ANOMALY")
        self.assertEqual(inc[0]["status"], NEEDS_REVIEW)
        self.assertIsNone(inc[0]["confidence"])

    def test_guardrailed_flows_are_counted_not_silently_dropped(self):
        f = flow(pred="NORMAL", mitigation_required=False, guardrail="multicast")
        inc, stats = build_incidents([f, f])
        self.assertEqual(inc, [])
        self.assertEqual(stats["flows_guardrailed"], 2)


class TestAllowlist(unittest.TestCase):
    def test_parsing_and_matching(self):
        al = Allowlist()
        added, rejected = al.add_many("192.168.1.1, 224.0.0.0/4  ff00::/8\n02:00:DE:AD:BE:EF bogus 999.1.1.1")
        self.assertEqual(len(added), 4)
        self.assertEqual(sorted(rejected), ["999.1.1.1", "bogus"])
        self.assertEqual(al.match_ip("224.0.0.251"), "224.0.0.0/4")
        self.assertEqual(al.match_ip("ff02::fb"), "ff00::/8")
        self.assertEqual(al.match_ip("192.168.1.1"), "192.168.1.1")
        self.assertIsNone(al.match_ip("192.168.1.2"))
        self.assertEqual(al.match_mac("02:00:de:ad:be:ef"), "02:00:de:ad:be:ef")
        self.assertEqual(normalize_entry("10.1.2.3/8"), "10.0.0.0/8")

    def test_persistence_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "allowlist.json")
            al = Allowlist(["192.168.1.1", "224.0.0.0/4"], path=path)
            al.save()
            self.assertEqual(sorted(Allowlist.load(path).entries), sorted(al.entries))
            self.assertEqual(Allowlist.load(os.path.join(d, "missing.json")).entries, [])

    def test_trusted_address_excluded_from_incidents(self):
        flows = [flow(conf=95.0, dport=p) for p in range(20, 32)]
        self.assertEqual(len(build_incidents(flows)[0]), 1)
        inc, stats = build_incidents(flows, allowlist=Allowlist(["192.168.1.99"]))
        self.assertEqual(inc, [])
        self.assertEqual(stats["flows_allowlisted"], 12)

    def test_match_modes(self):
        flows = [flow(conf=95.0, dport=p) for p in range(20, 32)]        # src .99 -> dst .50
        al = Allowlist(["192.168.1.50"])
        self.assertEqual(build_incidents(flows, allowlist=al, allowlist_mode="destination")[0], [])
        self.assertEqual(build_incidents(flows, allowlist=al, allowlist_mode="either")[0], [])
        self.assertEqual(len(build_incidents(flows, allowlist=al, allowlist_mode="source")[0]), 1)

    def test_arp_spoofing_only_silenced_by_mac_not_ip(self):
        random.seed(21)
        s = CaptureSession(); s.inject(G.generate_arp_spoofing())
        findings = s.detectors.findings()
        by_ip, _ = build_incidents([], findings, allowlist=Allowlist(["192.168.1.1", "192.168.1.20"]))
        self.assertEqual(len(by_ip), 1, "trusting the spoofed router IP must not hide the attack")
        by_mac, stats = build_incidents([], findings, allowlist=Allowlist(["02:00:de:ad:be:ef"]))
        self.assertEqual(by_mac, [])
        self.assertEqual(stats["findings_allowlisted"], 1)


class TestStreamingLoader(unittest.TestCase):
    def test_max_packets_limit_and_truncation_flag(self):
        random.seed(31)
        with tempfile.TemporaryDirectory() as d:
            path = packets_to_pcap(G.generate_normal_traffic(count=150), d)
            total = len(__import__("scapy.all", fromlist=["rdpcap"]).rdpcap(path))
            m = PacketSnifferManager()
            m.load_pcap(path, max_packets=100)
            self.assertEqual(m.last_load["packets_read"], 100)
            self.assertTrue(m.last_load["truncated"])
            m2 = PacketSnifferManager()
            m2.load_pcap(path, max_packets=None)
            self.assertEqual(m2.last_load["packets_read"], total)
            self.assertFalse(m2.last_load["truncated"])

    def test_small_display_window_does_not_limit_analysis(self):
        random.seed(32)
        with tempfile.TemporaryDirectory() as d:
            path = packets_to_pcap(G.generate_syn_flood(count=300), d)
            s = CaptureSession(display_window=50)
            s.load_pcap(path, max_packets=None)
            self.assertEqual(len(s.sniffer.packet_buffer), 50)             # window bounded
            self.assertEqual(s.total_packets, 300)                         # everything counted
            self.assertEqual(len(s.aggregator.flows), 300)                 # every packet reached flow aggregation
            self.assertEqual(len(s.sniffer.raw_packets), 0)                # raw packets not retained for file loads

    def test_default_limit_is_above_old_10k_cap(self):
        from core.sniffer import DEFAULT_MAX_PACKETS
        self.assertGreater(DEFAULT_MAX_PACKETS, 10_000)

    def test_forensics_is_stateless_across_reruns(self):
        random.seed(33)
        s = CaptureSession(); s.inject(G.generate_normal_traffic(count=80))
        recs = s.sniffer.get_records()
        fa = ForensicsAnalyzer()
        first = fa.analyze_stream(recs)["retransmission_count"]
        second = fa.analyze_stream(recs)["retransmission_count"]
        self.assertEqual(first, second)


class TestARPDetector(unittest.TestCase):
    def run_arp(self, pkts):
        d = ARPSpoofDetector()
        for p in pkts:
            d.process(PacketDissector.dissect(p))
        return d.findings()

    def test_detects_poisoning(self):
        random.seed(41)
        f = self.run_arp(G.generate_arp_spoofing(count=15))
        self.assertEqual(len(f), 1)
        self.assertGreaterEqual(f[0]["confidence"], 70)
        self.assertIn("02:00:de:ad:be:ef", f[0]["summary"])

    def test_benign_arp_is_silent(self):
        random.seed(42)
        self.assertEqual(self.run_arp(G.generate_benign_arp(count=40)), [])

    def test_lone_conflict_is_only_needs_review(self):
        """DHCP reassigning an address looks like a binding change but is not an attack."""
        from scapy.all import Ether, ARP
        asker, old, new = "02:00:cc:cc:cc:03", "02:00:aa:aa:aa:01", "02:00:bb:bb:bb:02"

        def exchange(t, owner_mac):
            q = Ether(src=asker, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=asker, psrc="192.168.1.30", pdst="192.168.1.40")
            r = Ether(src=owner_mac, dst=asker) / ARP(op=2, hwsrc=owner_mac, psrc="192.168.1.40", hwdst=asker, pdst="192.168.1.30")
            q.time, r.time = t, t + 0.01
            return [q, r]

        # a properly solicited reply from the old owner, an hour later a solicited reply from a new NIC (e.g. DHCP lease reassigned)
        pkts = exchange(1000.0, old) + exchange(4600.0, new)
        f = self.run_arp(pkts)
        self.assertEqual(len(f), 1)
        self.assertLess(f[0]["confidence"], 70)
        inc, _ = build_incidents([], f)
        self.assertEqual(inc[0]["status"], NEEDS_REVIEW)


class TestSlowlorisDetector(unittest.TestCase):
    def run_sl(self, pkts):
        d = SlowlorisDetector()
        for p in pkts:
            d.process(PacketDissector.dissect(p))
        return d.findings()

    def test_detects_slowloris(self):
        random.seed(51)
        f = self.run_sl(G.generate_slowloris(connections=30, duration=45))
        self.assertEqual(len(f), 1)
        self.assertGreaterEqual(f[0]["confidence"], 70)
        self.assertEqual(f[0]["src_ip"], "192.168.1.77")

    def test_normal_web_sessions_are_silent(self):
        random.seed(52)
        self.assertEqual(self.run_sl(G.generate_benign_web_sessions(connections=60, duration=60)), [])

    def test_few_unfinished_requests_are_not_enough(self):
        random.seed(53)
        self.assertEqual(self.run_sl(G.generate_slowloris(connections=4, duration=45)), [])


class TestReports(SharedEngine):
    def make(self):
        random.seed(61)
        s = CaptureSession()
        s.inject(G.generate_syn_flood(80) + G.generate_arp_spoofing() + G.generate_slowloris(connections=20, duration=30)
                 + G.generate_multicast_chatter(30))
        a = s.analyze(self.ai)
        return build_report(s, a, {"threshold": 70.0, "allowlist": ["224.0.0.0/4"], "allowlist_mode": "either"})

    def test_pdf_and_markdown(self):
        rep = self.make()
        pdf = render_pdf(rep)
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assertGreater(len(pdf), 3000)
        md = render_markdown(rep)
        self.assertIn("INC-001", md)
        self.assertIn("Limitations", md)
        self.assertIn("224.0.0.0/4", md)

    def test_untrusted_text_cannot_break_the_pdf(self):
        rep = self.make()
        rep["incidents"][0]["summary"] = "<b>unclosed & <script>alert(1)</script> </para>"
        rep["incidents"][0]["evidence"] = ["<font color=red>x", "a & b"]
        rep["capture"]["name"] = "evil<name>&.pcap"
        self.assertTrue(render_pdf(rep).startswith(b"%PDF"))

    def test_scan_rule_blocks_the_host_not_one_port(self):
        inc = {"type": "PORT_SCAN", "src_ip": "192.168.1.99", "example_flow": {"src_ip": "192.168.1.99", "dst_port": 21}}
        rules = ForensicsAnalyzer.generate_incident_mitigation(inc)
        self.assertIn("-s 192.168.1.99 -j DROP", rules["iptables"])
        self.assertNotIn("--dport", rules["iptables"])

    def test_mitigation_rules_reject_injected_addresses(self):
        evil = {"type": "ARP_SPOOFING", "src_mac": "02:00:de:ad:be:ef; rm -rf /", "example_flow": {},
                "conflicts": [{"ip": "1.2.3.4; reboot", "legit_mac": "aa:bb:cc:dd:ee:ff"}]}
        rules = ForensicsAnalyzer.generate_incident_mitigation(evil)
        for text in rules.values():
            self.assertNotIn("rm -rf", text)
            self.assertNotIn("reboot", text)


if __name__ == "__main__":
    unittest.main()
