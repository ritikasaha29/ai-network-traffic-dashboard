"""
Network Packet Forensics & Protocol Analysis Engine.
Implements deep packet forensics, Wireshark filter emulation, TCP handshake state tracking,
RTT and retransmission estimation, TCP vs UDP comparative analysis, and automated mitigation rule synthesis.
Aligned with Syllabus Problem Statement IV and Rubrics Analysis Level [7 marks].
"""

import re
import time
import ipaddress
from collections import defaultdict
from typing import Dict, Any, List, Optional, Tuple

class TCPHandshakeTracker:
    """Tracks TCP connection lifecycle: 3-way handshake (SYN -> SYN-ACK -> ACK) and teardown (FIN/RST)."""
    
    def __init__(self):
        # state per session key (src_ip:port -> dst_ip:port)
        self.sessions: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "state": "CLOSED",
            "syn_time": 0.0,
            "synack_time": 0.0,
            "ack_time": 0.0,
            "fin_time": 0.0,
            "rtt_handshake_ms": 0.0,
            "syn_seq": 0,
            "ack_seq": 0,
            "client_ip": "",
            "server_ip": "",
            "client_port": 0,
            "server_port": 0,
            "retransmissions": 0,
            "seen_seqs": set()
        })

    def process_packet(self, pkt: Dict[str, Any]):
        if pkt.get("protocol") != "TCP":
            return

        src_ip = pkt.get("src_ip", "")
        dst_ip = pkt.get("dst_ip", "")
        sport = pkt.get("src_port", 0)
        dport = pkt.get("dst_port", 0)
        flags = pkt.get("tcp_flags", {})
        seq = pkt.get("seq_num", 0)
        pkt_time = pkt.get("timestamp", 0.0)

        # Standard canonical key (lower IP/port first)
        key = f"{min(src_ip, dst_ip)}:{min(sport, dport)}<->{max(src_ip, dst_ip)}:{max(sport, dport)}"
        sess = self.sessions[key]

        # Retransmission check
        if seq in sess["seen_seqs"] and pkt.get("length", 0) > 54:
            sess["retransmissions"] += 1
        sess["seen_seqs"].add(seq)

        # 1. Client SYN (SYN=1, ACK=0)
        if flags.get("S") and not flags.get("A"):
            sess["state"] = "SYN_SENT"
            sess["syn_time"] = pkt_time
            sess["syn_seq"] = seq
            sess["client_ip"] = src_ip
            sess["server_ip"] = dst_ip
            sess["client_port"] = sport
            sess["server_port"] = dport

        # 2. Server SYN-ACK (SYN=1, ACK=1)
        elif flags.get("S") and flags.get("A") and sess["state"] == "SYN_SENT":
            sess["state"] = "SYN_RECEIVED"
            sess["synack_time"] = pkt_time

        # 3. Client ACK (SYN=0, ACK=1) completing handshake
        elif flags.get("A") and not flags.get("S") and sess["state"] == "SYN_RECEIVED":
            sess["state"] = "ESTABLISHED"
            sess["ack_time"] = pkt_time
            if sess["syn_time"] > 0:
                sess["rtt_handshake_ms"] = max(0.1, (pkt_time - sess["syn_time"]) * 1000.0)

        # 4. Teardown via FIN or RST
        elif flags.get("F"):
            sess["state"] = "FIN_WAIT"
            sess["fin_time"] = pkt_time
        elif flags.get("R"):
            sess["state"] = "RESET"


class ForensicsAnalyzer:
    """Wireshark-level packet inspection, protocol breakdown, and evidence reporting."""

    def __init__(self):
        self.handshake_tracker = TCPHandshakeTracker()

    def analyze_stream(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Performs comprehensive multi-layer forensic analysis across packet batch."""
        # Start from a clean tracker: the dashboard re-runs this on the same packets after every click,
        # and a persistent tracker would count every already-seen packet as a retransmission on each re-run.
        self.handshake_tracker = TCPHandshakeTracker()
        protocol_counts: Dict[str, int] = defaultdict(int)
        protocol_bytes: Dict[str, int] = defaultdict(int)
        ip_talkers: Dict[str, int] = defaultdict(int)
        port_activity: Dict[int, int] = defaultdict(int)

        rtts = []
        tcp_packets = 0
        udp_packets = 0
        icmp_packets = 0
        dns_queries = 0
        http_requests = 0
        retransmissions = 0
        syn_without_ack = 0

        for pkt in packets:
            proto = pkt.get("protocol", "OTHER")
            pkt_len = pkt.get("length", 0)
            src_ip = pkt.get("src_ip", "")
            dst_ip = pkt.get("dst_ip", "")
            
            protocol_counts[proto] += 1
            protocol_bytes[proto] += pkt_len
            ip_talkers[src_ip] += 1
            ip_talkers[dst_ip] += 1
            
            dport = pkt.get("dst_port", 0)
            if dport > 0:
                port_activity[dport] += 1

            if proto == "TCP":
                tcp_packets += 1
                self.handshake_tracker.process_packet(pkt)
                flags = pkt.get("tcp_flags", {})
                if flags.get("S") and not flags.get("A"):
                    syn_without_ack += 1
            elif proto == "UDP":
                udp_packets += 1
            elif proto == "ICMP":
                icmp_packets += 1
            elif proto == "DNS":
                dns_queries += 1
            elif proto == "HTTP":
                http_requests += 1

        # Collect session states from handshake tracker
        sessions_summary = []
        for key, s in self.handshake_tracker.sessions.items():
            if s["syn_time"] > 0:
                if s["rtt_handshake_ms"] > 0:
                    rtts.append(s["rtt_handshake_ms"])
                retransmissions += s["retransmissions"]
                sessions_summary.append({
                    "session": key,
                    "state": s["state"],
                    "rtt_ms": round(s["rtt_handshake_ms"], 2),
                    "client": f"{s['client_ip']}:{s['client_port']}",
                    "server": f"{s['server_ip']}:{s['server_port']}",
                    "retransmissions": s["retransmissions"]
                })

        avg_rtt = float(sum(rtts) / len(rtts)) if rtts else 0.0

        # Protocol comparison: TCP vs UDP
        tcp_bytes = protocol_bytes.get("TCP", 0)
        udp_bytes = protocol_bytes.get("UDP", 0)
        tcp_vs_udp = {
            "tcp_packet_count": tcp_packets,
            "udp_packet_count": udp_packets,
            "tcp_total_bytes": tcp_bytes,
            "udp_total_bytes": udp_bytes,
            "tcp_avg_packet_size": round(tcp_bytes / tcp_packets, 1) if tcp_packets > 0 else 0,
            "udp_avg_packet_size": round(udp_bytes / udp_packets, 1) if udp_packets > 0 else 0,
            "tcp_handshakes_completed": sum(1 for s in sessions_summary if s["state"] == "ESTABLISHED"),
            "tcp_half_open_syn": sum(1 for s in sessions_summary if s["state"] == "SYN_SENT")
        }

        return {
            "total_packets": len(packets),
            "protocol_counts": dict(protocol_counts),
            "protocol_bytes": dict(protocol_bytes),
            "top_talkers": sorted(ip_talkers.items(), key=lambda x: x[1], reverse=True)[:5],
            "top_ports": sorted(port_activity.items(), key=lambda x: x[1], reverse=True)[:8],
            "avg_rtt_ms": round(avg_rtt, 2),
            "retransmission_count": retransmissions,
            "syn_without_ack_count": syn_without_ack,
            "sessions": sessions_summary,
            "tcp_vs_udp": tcp_vs_udp
        }

    @staticmethod
    def apply_filter(packets: List[Dict[str, Any]], filter_str: str) -> List[Dict[str, Any]]:
        """Emulates Wireshark display filter queries (e.g. 'tcp', 'udp', 'ip.addr==192.168.1.10', 'tcp.port==80', 'dns')."""
        if not filter_str or filter_str.strip() == "":
            return packets
        
        query = filter_str.strip().lower()
        filtered = []

        for p in packets:
            proto = p.get("protocol", "").lower()
            src_ip = p.get("src_ip", "").lower()
            dst_ip = p.get("dst_ip", "").lower()
            sport = str(p.get("src_port", ""))
            dport = str(p.get("dst_port", ""))
            info = p.get("info", "").lower()

            if query == "tcp" and proto == "tcp":
                filtered.append(p)
            elif query == "udp" and proto == "udp":
                filtered.append(p)
            elif query == "icmp" and proto == "icmp":
                filtered.append(p)
            elif query == "dns" and (proto == "dns" or p.get("dns_query") is not None):
                filtered.append(p)
            elif query == "http" and (proto == "http" or p.get("http_method") is not None):
                filtered.append(p)
            elif query == "arp" and proto == "arp":
                filtered.append(p)
            elif query.startswith("ip.addr=="):
                target_ip = query.split("==")[1].strip()
                if target_ip in (src_ip, dst_ip):
                    filtered.append(p)
            elif query.startswith("tcp.port==") or query.startswith("port=="):
                target_port = query.split("==")[1].strip()
                if target_port in (sport, dport):
                    filtered.append(p)
            elif query in ("syn", "tcp.flags.syn==1"):
                if p.get("tcp_flags", {}).get("S", False):
                    filtered.append(p)
            elif query in ("rst", "tcp.flags.rst==1"):
                if p.get("tcp_flags", {}).get("R", False):
                    filtered.append(p)
            elif query in src_ip or query in dst_ip or query in info:
                filtered.append(p)

        return filtered

    @staticmethod
    def generate_mitigation_rules(threat_flow: Dict[str, Any]) -> Dict[str, str]:
        """Generates automated defensive firewall rules (iptables & Windows netsh) for an identified threat."""
        src_ip = threat_flow.get("src_ip", "0.0.0.0")
        dst_port = threat_flow.get("dst_port", 80)
        raw_proto = threat_flow.get("protocol", "TCP").upper()
        if raw_proto in ("DNS", "DHCP"):
            proto = "udp"
        elif raw_proto in ("HTTP", "HTTPS", "TCP"):
            proto = "tcp"
        elif raw_proto in ("ICMP", "UDP"):
            proto = raw_proto.lower()
        else:
            proto = "tcp"
        threat_type = threat_flow.get("prediction", "ATTACK")
        if threat_type == "NORMAL":
            threat_type = "ZERO_DAY_ANOMALY"

        iptables_cmd = f"sudo iptables -A INPUT -s {src_ip} -p {proto} --dport {dst_port} -j DROP # Block {threat_type}"
        windows_netsh = f'netsh advfirewall firewall add rule name="Block_{threat_type}_{src_ip}" dir=in action=block remoteip={src_ip} protocol={proto.upper()} localport={dst_port}'
        cisco_acl = f"access-list 101 deny {proto} host {src_ip} any eq {dst_port}\naccess-list 101 permit ip any any"

        return {
            "iptables": iptables_cmd,
            "windows_netsh": windows_netsh,
            "cisco_acl": cisco_acl
        }


    # ------------------------------------------------------------------ incident-level rules
    @staticmethod
    def _safe_ip(value: str) -> Optional[str]:
        try:
            return str(ipaddress.ip_address(str(value)))
        except ValueError:
            return None

    @staticmethod
    def _safe_mac(value: str) -> Optional[str]:
        v = str(value or "").lower()
        return v if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", v) else None

    @staticmethod
    def generate_incident_mitigation(incident: Dict[str, Any]) -> Dict[str, str]:
        """Firewall / switch rules for an incident (as opposed to a single flow).

        Addresses come from captured packets, i.e. untrusted input that a human will paste into a root shell,
        so every address is validated before being interpolated; anything malformed yields a comment instead.
        """
        kind = incident.get("type")
        ex = incident.get("example_flow", {})
        safe_ip, safe_mac = ForensicsAnalyzer._safe_ip, ForensicsAnalyzer._safe_mac

        if kind == "ARP_SPOOFING":
            mac = safe_mac(incident.get("src_mac", ""))
            ipt, win, cisco = [], [], ["ip dhcp snooping", "ip dhcp snooping vlan 1", "ip arp inspection vlan 1",
                                       "! mark the uplink / router port trusted:  ip arp inspection trust"]
            for c in incident.get("conflicts", []):
                ip, legit = safe_ip(c.get("ip")), safe_mac(c.get("legit_mac"))
                if ip and legit:
                    ipt.append(f"sudo ip neigh replace {ip} lladdr {legit} dev eth0 nud permanent   # pin the genuine binding")
                    win.append(f'netsh interface ipv4 add neighbor "Ethernet" {ip} {legit.replace(":", "-")}')
            if mac:
                ipt.append(f"sudo ebtables -A INPUT -p ARP --arp-mac-src {mac} -j DROP   # drop the impersonator's ARP")
                cisco.append(f"! locate and shut the switch port that learned {mac}:  show mac address-table address {mac.replace(':', '')[:4]}.{mac.replace(':', '')[4:8]}.{mac.replace(':', '')[8:]}")
            return {"iptables": "\n".join(ipt) or "# no validated addresses to build a rule from",
                    "windows_netsh": "\n".join(win) or "# no validated addresses to build a rule from",
                    "cisco_acl": "\n".join(cisco)}

        if kind == "SLOWLORIS":
            src, dst, port = safe_ip(incident.get("src_ip", "")), safe_ip(incident.get("dst_ip", incident.get("dst", ""))), int(incident.get("dst_port") or 80)
            ipt = [f"sudo iptables -A INPUT -p tcp --dport {port} -m connlimit --connlimit-above 20 --connlimit-mask 32 -j REJECT --reject-with tcp-reset   # cap connections per client"]
            if src:
                ipt.append(f"sudo iptables -A INPUT -s {src} -p tcp --dport {port} -j DROP   # block this client")
            win = f'netsh advfirewall firewall add rule name="Block_SLOWLORIS_{src}" dir=in action=block remoteip={src} protocol=TCP localport={port}' if src else "# no validated source address"
            cisco = f"access-list 101 deny tcp host {src} any eq {port}\naccess-list 101 permit ip any any" if src else "! no validated source address"
            return {"iptables": "\n".join(ipt) + "\n# also: raise web-server header timeout / use a reverse proxy that buffers requests (nginx, HAProxy)",
                    "windows_netsh": win, "cisco_acl": cisco}

        if kind in ("PORT_SCAN", "DNS_TUNNELING"):
            src = safe_ip(incident.get("src_ip") or ex.get("src_ip", ""))
            if not src:
                return {"iptables": "# no validated source address", "windows_netsh": "# n/a", "cisco_acl": "! n/a"}
            if kind == "PORT_SCAN":      # a scanner probes many ports: block the host, not one port
                return {"iptables": f"sudo iptables -A INPUT -s {src} -j DROP   # block the scanner entirely",
                        "windows_netsh": f'netsh advfirewall firewall add rule name="Block_PORT_SCAN_{src}" dir=in action=block remoteip={src}',
                        "cisco_acl": f"access-list 101 deny ip host {src} any\naccess-list 101 permit ip any any"}
            # DNS tunnelling: the *inside* host is the one leaking data, so stop its outbound DNS and force it through the internal resolver
            return {"iptables": f"sudo iptables -A FORWARD -s {src} -p udp --dport 53 -j DROP   # quarantine this host's outbound DNS (allow only your internal resolver)\n"
                                f"sudo iptables -A FORWARD -s {src} -p tcp --dport 53 -j DROP",
                    "windows_netsh": f'# run on {src}, or enforce on the gateway:\nnetsh advfirewall firewall add rule name="Block_DNS_TUNNEL_{src}" dir=out action=block protocol=UDP remoteport=53',
                    "cisco_acl": f"access-list 102 deny udp host {src} any eq 53\naccess-list 102 deny tcp host {src} any eq 53\naccess-list 102 permit ip any any"}

        many_sources = str(incident.get("src", "")).endswith("sources")
        if kind in ("SYN_FLOOD", "UDP_DDOS") and many_sources:
            dst, port = safe_ip(incident.get("dst", "")), int(incident.get("dst_port") or 0)
            if not dst:
                return {"iptables": "# no validated destination", "windows_netsh": "# n/a", "cisco_acl": "! n/a"}
            if kind == "SYN_FLOOD":
                ipt = (f"sudo sysctl -w net.ipv4.tcp_syncookies=1\n"
                       f"sudo iptables -A INPUT -p tcp -d {dst} --dport {port} --syn -m limit --limit 100/s --limit-burst 200 -j ACCEPT\n"
                       f"sudo iptables -A INPUT -p tcp -d {dst} --dport {port} --syn -j DROP")
                acl = f"access-list 110 permit tcp any host {dst} eq {port}"
            else:
                ipt = (f"sudo iptables -A INPUT -p udp -d {dst} -m limit --limit 500/s --limit-burst 1000 -j ACCEPT\n"
                       f"sudo iptables -A INPUT -p udp -d {dst} -j DROP")
                acl = f"access-list 110 permit udp any host {dst}"
            cisco = (acl + "\nclass-map match-all ATTACK_TRAFFIC\n match access-group 110\npolicy-map RATE_LIMIT_ATTACK\n class ATTACK_TRAFFIC\n"
                     "  police 1000000 conform-action transmit exceed-action drop\n! then: interface <uplink> / service-policy input RATE_LIMIT_ATTACK")
            return {"iptables": ipt + "\n# sources are spoofed or numerous: blocking them one by one is futile, rate-limit the victim service",
                    "windows_netsh": "# Windows Firewall cannot rate-limit. Apply the rate limit upstream (edge router / ISP / scrubbing service).",
                    "cisco_acl": cisco}

        return ForensicsAnalyzer.generate_mitigation_rules({**ex, "prediction": kind})
