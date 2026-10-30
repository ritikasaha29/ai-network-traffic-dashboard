"""
Flow Feature Extraction Engine for AI-Driven Network Traffic Intelligence.
Extracts bidirectional session flows and statistical features adhering to
CIC-IDS / NetFlow / IPFIX engineering standards.
"""

import time
import math
import ipaddress
import numpy as np
from functools import lru_cache
from collections import defaultdict
from typing import Dict, List, Any, Optional, Tuple


@lru_cache(maxsize=65536)
def is_group_address(ip: str) -> bool:
    """True for multicast / broadcast destinations that are one-to-many by design.

    Covers IPv4 multicast 224.0.0.0/4, IPv6 multicast ff00::/8, the limited broadcast
    255.255.255.255, and the common directed-broadcast convention x.x.x.255.

    Note: the x.x.x.255 test is a heuristic. Without the subnet mask a host such as
    10.0.1.255 inside a /23 is a normal unicast address. It errs on the side of
    treating the address as broadcast, which is the safe side for false alarms but
    means an attacker aiming at a .255 unicast host would be missed by the models.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_multicast:
        return True
    if addr.version == 4:
        return ip == "255.255.255.255" or ip.endswith(".255")
    return False


def is_group_mac(mac: str) -> bool:
    """True for the Ethernet broadcast address or any group (multicast) MAC (I/G bit set)."""
    if not mac:
        return False
    try:
        return bool(int(mac.split(":")[0], 16) & 1)
    except (ValueError, IndexError):
        return False

def calculate_shannon_entropy(data: bytes) -> float:
    """Computes Shannon entropy of binary payload to detect tunneling/encryption."""
    if not data or len(data) == 0:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = defaultdict(int)
    for byte in data:
        counts[byte] += 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)


class NetworkFlow:
    """Represents a bidirectional network conversation flow."""
    def __init__(self, flow_id: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str):
        self.flow_id = flow_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        self.start_time: float = 0.0
        self.last_time: float = 0.0
        
        # Packet and Byte counts
        self.fwd_packets: int = 0
        self.bwd_packets: int = 0
        self.fwd_bytes: int = 0
        self.bwd_bytes: int = 0
        
        # Lengths and Timings
        self.packet_lengths: List[int] = []
        self.arrival_times: List[float] = []
        
        # TCP specific metrics
        self.syn_count: int = 0
        self.fin_count: int = 0
        self.rst_count: int = 0
        self.psh_count: int = 0
        self.ack_count: int = 0
        self.urg_count: int = 0
        self.window_sizes: List[int] = []
        
        # Application layer forensics
        self.dns_queries: List[str] = []
        self.payload_entropies: List[float] = []
        self.http_methods: List[str] = []

        # Destination is a multicast / broadcast group (one-to-many by design)
        self.l2_group_dst: bool = False
        
    def add_packet(self, pkt_time: float, pkt_len: int, is_fwd: bool, 
                   tcp_flags: Optional[Dict[str, bool]] = None,
                   window_size: int = 0,
                   dns_query: Optional[str] = None,
                   http_method: Optional[str] = None,
                   payload_bytes: bytes = b"",
                   l2_group_dst: bool = False):
        if self.start_time == 0.0:
            self.start_time = pkt_time
        self.last_time = pkt_time
        self.arrival_times.append(pkt_time)
        self.packet_lengths.append(pkt_len)
        
        if is_fwd:
            self.fwd_packets += 1
            self.fwd_bytes += pkt_len
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt_len
            
        if tcp_flags:
            if tcp_flags.get("S", False): self.syn_count += 1
            if tcp_flags.get("F", False): self.fin_count += 1
            if tcp_flags.get("R", False): self.rst_count += 1
            if tcp_flags.get("P", False): self.psh_count += 1
            if tcp_flags.get("A", False): self.ack_count += 1
            if tcp_flags.get("U", False): self.urg_count += 1
            
        if window_size > 0:
            self.window_sizes.append(window_size)
            
        if dns_query:
            self.dns_queries.append(dns_query)
            
        if http_method:
            self.http_methods.append(http_method)

        if is_fwd and l2_group_dst:
            self.l2_group_dst = True
            
        if payload_bytes and len(payload_bytes) > 0:
            self.payload_entropies.append(calculate_shannon_entropy(payload_bytes))

    @property
    def duration(self) -> float:
        return max(0.0001, self.last_time - self.start_time)

    def extract_features(self) -> Dict[str, Any]:
        """Calculates statistical vector used by ML and Deep Forensic engines."""
        dur = self.duration
        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes
        
        # Inter-arrival time statistics
        if len(self.arrival_times) > 1:
            iats = np.diff(self.arrival_times)
            iat_mean = float(np.mean(iats))
            iat_std = float(np.std(iats))
            iat_min = float(np.min(iats))
            iat_max = float(np.max(iats))
        else:
            iat_mean = 0.0
            iat_std = 0.0
            iat_min = 0.0
            iat_max = 0.0
            
        # Packet length statistics
        if len(self.packet_lengths) > 0:
            pkt_len_mean = float(np.mean(self.packet_lengths))
            pkt_len_std = float(np.std(self.packet_lengths))
            pkt_len_min = float(np.min(self.packet_lengths))
            pkt_len_max = float(np.max(self.packet_lengths))
        else:
            pkt_len_mean = pkt_len_std = pkt_len_min = pkt_len_max = 0.0
            
        # TCP Window size stats
        win_mean = float(np.mean(self.window_sizes)) if self.window_sizes else 0.0
        win_std = float(np.std(self.window_sizes)) if self.window_sizes else 0.0
        
        # Payload entropy stats
        entropy_mean = float(np.mean(self.payload_entropies)) if self.payload_entropies else 0.0
        
        # DNS query metrics
        dns_query_count = len(self.dns_queries)
        dns_query_len_mean = float(np.mean([len(q) for q in self.dns_queries])) if self.dns_queries else 0.0
        dns_entropy_mean = float(np.mean([calculate_shannon_entropy(q.encode()) for q in self.dns_queries])) if self.dns_queries else 0.0

        # Ratios & Rates
        fwd_pkt_ratio = (self.fwd_packets / total_packets) if total_packets > 0 else 0.0
        bwd_pkt_ratio = (self.bwd_packets / total_packets) if total_packets > 0 else 0.0
        syn_ratio = (self.syn_count / total_packets) if total_packets > 0 else 0.0
        rst_ratio = (self.rst_count / total_packets) if total_packets > 0 else 0.0
        
        if dur > 0.01:
            packet_rate = total_packets / dur
            byte_rate = total_bytes / dur
        else:
            packet_rate = float(total_packets)
            byte_rate = float(total_bytes)

        # 1 when the flow's destination is a multicast / broadcast group address.
        # Flows to a group are one-to-many chatter (mDNS, SSDP, DHCP, NetBIOS...), not floods.
        is_multicast_dst = 1 if (is_group_address(self.dst_ip) or self.l2_group_dst) else 0

        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "end_time": self.last_time,
            "duration": round(dur, 4),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "fwd_packets": self.fwd_packets,
            "bwd_packets": self.bwd_packets,
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            "pkt_len_mean": round(pkt_len_mean, 2),
            "pkt_len_std": round(pkt_len_std, 2),
            "pkt_len_min": pkt_len_min,
            "pkt_len_max": pkt_len_max,
            "iat_mean": round(iat_mean, 6),
            "iat_std": round(iat_std, 6),
            "iat_min": round(iat_min, 6),
            "iat_max": round(iat_max, 6),
            "packet_rate": round(packet_rate, 2),
            "byte_rate": round(byte_rate, 2),
            "fwd_pkt_ratio": round(fwd_pkt_ratio, 4),
            "bwd_pkt_ratio": round(bwd_pkt_ratio, 4),
            "syn_count": self.syn_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "psh_count": self.psh_count,
            "ack_count": self.ack_count,
            "urg_count": self.urg_count,
            "syn_ratio": round(syn_ratio, 4),
            "rst_ratio": round(rst_ratio, 4),
            "win_mean": round(win_mean, 2),
            "win_std": round(win_std, 2),
            "payload_entropy_mean": round(entropy_mean, 3),
            "dns_query_count": dns_query_count,
            "dns_query_len_mean": round(dns_query_len_mean, 2),
            "dns_entropy_mean": round(dns_entropy_mean, 3),
            "is_multicast_dst": is_multicast_dst,
        }


class FlowAggregator:
    """Manages active network flows, aggregation, and session expiration."""
    def __init__(self, flow_timeout: float = 30.0):
        self.flow_timeout = flow_timeout
        self.flows: Dict[str, NetworkFlow] = {}

    def _get_flow_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> (str, bool):
        fwd_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}#{proto}"
        bwd_key = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}#{proto}"
        if fwd_key in self.flows:
            return fwd_key, True
        elif bwd_key in self.flows:
            return bwd_key, False
        else:
            return fwd_key, True

    def process_packet(self, pkt_dict: Dict[str, Any]) -> str:
        """Processes raw parsed packet dict and updates the corresponding flow."""
        src_ip = pkt_dict.get("src_ip", "0.0.0.0")
        dst_ip = pkt_dict.get("dst_ip", "0.0.0.0")
        src_port = pkt_dict.get("src_port", 0)
        dst_port = pkt_dict.get("dst_port", 0)
        proto = pkt_dict.get("protocol", "OTHER")
        pkt_time = pkt_dict.get("timestamp", time.time())
        pkt_len = pkt_dict.get("length", 64)
        
        flow_key, is_fwd = self._get_flow_key(src_ip, dst_ip, src_port, dst_port, proto)
        
        if flow_key not in self.flows:
            self.flows[flow_key] = NetworkFlow(
                flow_id=flow_key,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto
            )
            
        flow = self.flows[flow_key]
        flow.add_packet(
            pkt_time=pkt_time,
            pkt_len=pkt_len,
            is_fwd=is_fwd,
            tcp_flags=pkt_dict.get("tcp_flags"),
            window_size=pkt_dict.get("window_size", 0),
            dns_query=pkt_dict.get("dns_query"),
            http_method=pkt_dict.get("http_method"),
            payload_bytes=pkt_dict.get("payload_bytes", b""),
            l2_group_dst=bool(pkt_dict.get("l2_group_dst", False))
        )
        return flow_key

    def get_all_flow_features(self) -> List[Dict[str, Any]]:
        return [flow.extract_features() for flow in self.flows.values()]

    def clear(self):
        self.flows.clear()
