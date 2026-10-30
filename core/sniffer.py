"""
Packet Sniffer & PCAP Forensic Ingestion Engine.
Supports live sniffing via Scapy AsyncSniffer, raw PCAP ingestion,
and deep protocol layer dissection for TCP, UDP, ICMP, DNS, HTTP, DHCP, ARP.
"""

import time
import os
import threading
from collections import deque
from typing import Dict, Any, List, Optional, Callable, Deque
from scapy.all import (
    PcapReader, wrpcap, Packet, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw, ARP, Ether
)
from core.feature_extractor import is_group_mac

# Default limits. Both are user-adjustable in the dashboard sidebar.
DEFAULT_MAX_PACKETS = 200_000     # packets read from a capture file and fed to flow/attack analysis
DEFAULT_DISPLAY_WINDOW = 20_000   # most-recent packets kept in memory for the packet table / inspector

class PacketDissector:
    """Dissects raw packets into structured forensic records."""

    @staticmethod
    def dissect(packet: Packet, with_summary: bool = False) -> Dict[str, Any]:
        """Turns one scapy packet into a flat record.

        `with_summary` adds scapy's one-line summary. It is slow (it re-walks every layer) and
        nothing in the dashboard displays it, so it is off by default.
        """
        pkt_time = float(packet.time) if hasattr(packet, "time") else time.time()
        pkt_len = len(packet)
        
        record: Dict[str, Any] = {
            "timestamp": pkt_time,
            "length": pkt_len,
            "protocol": "OTHER",
            "src_ip": "0.0.0.0",
            "dst_ip": "0.0.0.0",
            "src_port": 0,
            "dst_port": 0,
            "tcp_flags": {},
            "tcp_flags_str": "",
            "seq_num": 0,
            "ack_num": 0,
            "window_size": 0,
            "dns_query": None,
            "dns_qtype": None,
            "http_method": None,
            "http_host": None,
            "http_uri": None,
            "payload_bytes": b"",
            "summary": packet.summary() if (with_summary and hasattr(packet, "summary")) else "",
            "info": "",
            "src_mac": "",
            "dst_mac": "",
            "l2_group_dst": False,
        }

        # Ethernet layer (MAC addresses; broadcast / multicast frames)
        if packet.haslayer(Ether):
            eth = packet[Ether]
            record["src_mac"] = str(eth.src).lower()
            record["dst_mac"] = str(eth.dst).lower()
            record["l2_group_dst"] = is_group_mac(record["dst_mac"])

        # ARP Analysis
        if packet.haslayer(ARP):
            arp = packet[ARP]
            record["protocol"] = "ARP"
            record["src_ip"] = arp.psrc
            record["dst_ip"] = arp.pdst
            record["arp_op"] = int(arp.op)
            record["arp_hwsrc"] = str(arp.hwsrc).lower()
            record["arp_hwdst"] = str(arp.hwdst).lower()
            record["arp_psrc"] = arp.psrc
            record["arp_pdst"] = arp.pdst
            record["info"] = f"ARP Who has {arp.pdst}? Tell {arp.psrc}" if arp.op == 1 else f"ARP {arp.psrc} is-at {arp.hwsrc}"
            return record

        # IP Layer
        if packet.haslayer(IP):
            ip = packet[IP]
            record["src_ip"] = ip.src
            record["dst_ip"] = ip.dst
            record["ttl"] = ip.ttl
            record["ip_proto"] = ip.proto
        elif packet.haslayer(IPv6):
            ipv6 = packet[IPv6]
            record["src_ip"] = ipv6.src
            record["dst_ip"] = ipv6.dst
            record["protocol"] = "IPv6"

        # ICMP Layer
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            record["protocol"] = "ICMP"
            record["src_port"] = 0
            record["dst_port"] = 0
            record["info"] = f"ICMP Type {icmp.type} Code {icmp.code}"
            return record

        # TCP Layer
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            record["protocol"] = "TCP"
            record["src_port"] = tcp.sport
            record["dst_port"] = tcp.dport
            record["seq_num"] = tcp.seq
            record["ack_num"] = tcp.ack
            record["window_size"] = tcp.window
            
            # Flags parsing: F=FIN, S=SYN, R=RST, P=PSH, A=ACK, U=URG, E=ECE, C=CWR
            flags = str(tcp.flags)
            record["tcp_flags_str"] = flags
            record["tcp_flags"] = {
                "F": "F" in flags,
                "S": "S" in flags,
                "R": "R" in flags,
                "P": "P" in flags,
                "A": "A" in flags,
                "U": "U" in flags
            }
            
            flag_desc = []
            if "S" in flags: flag_desc.append("SYN")
            if "A" in flags: flag_desc.append("ACK")
            if "F" in flags: flag_desc.append("FIN")
            if "R" in flags: flag_desc.append("RST")
            if "P" in flags: flag_desc.append("PSH")
            flags_joined = ",".join(flag_desc) if flag_desc else flags
            record["info"] = f"TCP {tcp.sport} -> {tcp.dport} [{flags_joined}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"

            # Check HTTP payload
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                record["payload_bytes"] = payload
                try:
                    text_head = payload[:100].decode("utf-8", errors="ignore")
                    for method in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]:
                        if text_head.startswith(method):
                            record["protocol"] = "HTTP"
                            record["http_method"] = method
                            parts = text_head.split(" ")
                            if len(parts) > 1:
                                record["http_uri"] = parts[1]
                            record["info"] = f"HTTP {method} {record.get('http_uri', '')}"
                            break
                    if "HTTP/1." in text_head:
                        record["protocol"] = "HTTP"
                        first_line = text_head.split("\r\n")[0]
                        record["info"] = f"HTTP Response: {first_line}"
                except Exception:
                    pass

        # UDP Layer
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            record["protocol"] = "UDP"
            record["src_port"] = udp.sport
            record["dst_port"] = udp.dport
            record["info"] = f"UDP {udp.sport} -> {udp.dport} Len={udp.len}"

            # Check DNS
            if packet.haslayer(DNS):
                dns = packet[DNS]
                record["protocol"] = "DNS"
                if dns.qr == 0 and dns.qd:  # Query
                    qname = dns.qd.qname.decode("utf-8", errors="ignore") if hasattr(dns.qd.qname, "decode") else str(dns.qd.qname)
                    record["dns_query"] = qname.rstrip(".")
                    record["info"] = f"Standard query 0x{dns.id:04x} A {record['dns_query']}"
                elif dns.qr == 1:  # Response
                    record["info"] = f"Standard query response 0x{dns.id:04x}"

            # Check DHCP / BootP
            if udp.sport in (67, 68) or udp.dport in (67, 68):
                record["protocol"] = "DHCP"
                record["info"] = "DHCP / BOOTP Exchange"

            if packet.haslayer(Raw):
                record["payload_bytes"] = bytes(packet[Raw].load)

        return record


class PacketSnifferManager:
    """Manages PCAP reading and packet stream processing.

    Large captures are streamed one packet at a time (scapy `PcapReader`), so a multi-hundred-MB
    file never has to fit in memory at once. Every packet is dissected and handed to `callback`
    (flow aggregation, attack detectors), but only the most recent `max_buffer_size` records are
    kept for the packet table. Raw scapy packets are only retained when explicitly requested.
    """

    def __init__(self, callback: Optional[Callable[[Dict[str, Any]], None]] = None,
                 max_buffer_size: int = DEFAULT_DISPLAY_WINDOW):
        self.callback = callback
        self.max_buffer_size = max(1, int(max_buffer_size))
        self.packet_buffer: Deque[Dict[str, Any]] = deque(maxlen=self.max_buffer_size)
        self.raw_packets: Deque[Packet] = deque(maxlen=self.max_buffer_size)
        self.is_sniffing = False
        self._sniffer_thread: Optional[threading.Thread] = None
        self._async_sniffer = None
        # Updated by load_pcap / add_packet_record
        self.total_packets_seen = 0      # every packet processed, including ones that scrolled out of the window
        self.last_load: Dict[str, Any] = {}

    def set_buffer_size(self, size: int):
        """Changes the display window, keeping the newest records."""
        size = max(1, int(size))
        if size == self.max_buffer_size:
            return
        self.max_buffer_size = size
        self.packet_buffer = deque(self.packet_buffer, maxlen=size)
        self.raw_packets = deque(self.raw_packets, maxlen=size)

    def get_records(self) -> List[Dict[str, Any]]:
        """The retained display window as a list (oldest first)."""
        return list(self.packet_buffer)

    def add_packet_record(self, record: Dict[str, Any], raw_pkt: Optional[Packet] = None):
        self.packet_buffer.append(record)   # deque(maxlen) drops the oldest in O(1)
        if raw_pkt is not None:
            self.raw_packets.append(raw_pkt)
        self.total_packets_seen += 1
        if self.callback:
            self.callback(record)

    def load_pcap(self, file_path: str, max_packets: Optional[int] = DEFAULT_MAX_PACKETS,
                  keep_raw: bool = False) -> List[Dict[str, Any]]:
        """Streams a PCAP / PCAPNG file. Returns the records still held in the display window.

        max_packets: stop after this many packets (None = read everything). `last_load` records
                     how many were read and whether the file had more packets than the limit.
        keep_raw:    also keep the scapy packet objects (needed only for save_pcap).
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"PCAP file not found: {file_path}")

        read = 0
        truncated = False
        t0 = time.time()
        with PcapReader(file_path) as reader:
            for pkt in reader:
                if max_packets is not None and read >= max_packets:
                    truncated = True
                    break
                rec = PacketDissector.dissect(pkt)
                self.add_packet_record(rec, pkt if keep_raw else None)
                read += 1

        self.last_load = {
            "file": os.path.basename(file_path),
            "file_bytes": os.path.getsize(file_path),
            "packets_read": read,
            "truncated": truncated,
            "max_packets": max_packets,
            "seconds": round(time.time() - t0, 2),
        }
        return self.get_records()

    def save_pcap(self, file_path: str):
        """Saves retained raw packets (see keep_raw) to disk as a standard PCAP."""
        if self.raw_packets:
            wrpcap(file_path, list(self.raw_packets))

    def clear(self):
        self.packet_buffer.clear()
        self.raw_packets.clear()
        self.total_packets_seen = 0
        self.last_load = {}
