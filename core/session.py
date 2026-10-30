"""
CaptureSession: one packet stream feeding every analysis stage.

    pcap / injected packets -> dissector -> +-> display window (last N packets, for the packet table)
                                            +-> flow aggregator (every packet)
                                            +-> attack detectors (every packet: ARP spoofing, Slowloris)

Because flows and detectors see every packet as it streams past, a capture far larger than the
display window is still analysed completely (up to `max_packets`), while memory for the packet
table stays bounded.
"""

from typing import Dict, Any, List, Optional

from core.sniffer import (PacketSnifferManager, PacketDissector,
                          DEFAULT_MAX_PACKETS, DEFAULT_DISPLAY_WINDOW)
from core.feature_extractor import FlowAggregator
from core.detectors import DetectorSuite
from core.forensics import ForensicsAnalyzer
from core.incidents import build_incidents, DEFAULT_CONFIDENCE_THRESHOLD
from core.allowlist import Allowlist


class CaptureSession:
    def __init__(self, display_window: int = DEFAULT_DISPLAY_WINDOW):
        self.aggregator = FlowAggregator()
        self.detectors = DetectorSuite()
        self.sniffer = PacketSnifferManager(callback=self._on_record, max_buffer_size=display_window)
        self.forensics = ForensicsAnalyzer()
        self.total_bytes = 0
        self.source_name = ""
        self.version = 0          # bumped whenever the data changes (cache key for analysis results)

    # ---------------------------------------------------------------- ingestion
    def _on_record(self, rec: Dict[str, Any]):
        self.total_bytes += rec.get("length", 0)
        self.aggregator.process_packet(rec)
        self.detectors.process(rec)

    @property
    def total_packets(self) -> int:
        return self.sniffer.total_packets_seen

    def clear(self):
        self.sniffer.clear()
        self.aggregator.clear()
        self.detectors.reset()
        self.total_bytes = 0
        self.source_name = ""
        self.version += 1

    def load_pcap(self, path: str, max_packets: Optional[int] = DEFAULT_MAX_PACKETS,
                  display_window: Optional[int] = None) -> Dict[str, Any]:
        """Replaces the session contents with a streamed capture. Returns load statistics."""
        self.clear()
        if display_window:
            self.sniffer.set_buffer_size(display_window)
        self.sniffer.load_pcap(path, max_packets=max_packets)
        self.source_name = self.sniffer.last_load.get("file", "")
        self.version += 1
        return self.sniffer.last_load

    def inject(self, packets: List[Any], label: Optional[str] = None):
        """Adds scapy packets (simulation lab) to the current session."""
        for p in packets:
            self.sniffer.add_packet_record(PacketDissector.dissect(p), p)
        if label:
            self.source_name = label
        self.version += 1

    # ---------------------------------------------------------------- analysis
    def analyze(self, ai_engine, allowlist: Optional[Allowlist] = None,
                threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
                allowlist_mode: str = "either") -> Dict[str, Any]:
        """Runs forensics + classification + incident grouping on everything seen so far."""
        window = self.sniffer.get_records()
        forensic_stats = self.forensics.analyze_stream(window)
        flows = self.aggregator.get_all_flow_features()
        preds = ai_engine.predict_flows(flows)
        flow_predictions = [{**f, **p} for f, p in zip(flows, preds)]
        incidents, stats = build_incidents(flow_predictions, self.detectors.findings(),
                                           threshold=threshold, allowlist=allowlist, allowlist_mode=allowlist_mode)
        return {
            "window_records": window,
            "forensic_stats": forensic_stats,
            "flow_predictions": flow_predictions,
            "incidents": incidents,
            "suppression": stats,
            "confirmed": [i for i in incidents if i["status"] == "CONFIRMED"],
            "needs_review": [i for i in incidents if i["status"] != "CONFIRMED"],
        }
