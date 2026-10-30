"""
Network Traffic Generator & Attack Simulation Engine.
Generates realistic multi-protocol baseline network traffic (including the multicast / broadcast
chatter every LAN has: mDNS, SSDP, LLMNR, NetBIOS, DHCP, IGMP) as well as attack vectors
(SYN Flood, Port Scan, DNS Tunneling, UDP DDoS, Slowloris, ARP Spoofing)
for validation, testing, and live demonstration.

Every packet is wrapped in an Ethernet frame with deterministic MAC addresses, so captures
written by this module carry real layer-2 information (multicast MACs, ARP sender/target MACs).
"""

import time
import random
import os
import ipaddress
from typing import List, Dict, Any, Optional, Tuple
from scapy.all import (
    IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, ARP, Ether, wrpcap, Packet
)


def mac_for_ip(ip: str) -> str:
    """Deterministic MAC for an IP, following the real multicast-to-MAC mappings."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "02:00:00:00:00:00"
    if addr.version == 4:
        if ip == "255.255.255.255" or ip.endswith(".255"):
            return "ff:ff:ff:ff:ff:ff"
        b = addr.packed
        if addr.is_multicast:
            return "01:00:5e:%02x:%02x:%02x" % (b[1] & 0x7F, b[2], b[3])
        return "02:00:%02x:%02x:%02x:%02x" % tuple(b)
    b = addr.packed
    if addr.is_multicast:
        return "33:33:%02x:%02x:%02x:%02x" % tuple(b[-4:])
    return "02:00:%02x:%02x:%02x:%02x" % tuple(b[-4:])

class TrafficGenerator:
    """Generates synthetic network packets for normal traffic and attack vectors."""

    @staticmethod
    def generate_normal_traffic(count: int = 50, base_time: float = None, include_multicast: bool = True) -> List[Packet]:
        """Baseline LAN traffic: web, DNS, ping, TLS, and (by default) multicast / broadcast chatter."""
        if base_time is None:
            base_time = time.time()
        packets: List[Packet] = []
        cur_time = base_time

        hosts = ["192.168.1.10", "192.168.1.15", "192.168.1.20"]
        servers = ["142.250.190.46", "104.244.42.1", "13.232.180.20"]  # Google, Twitter, AWS
        domains = ["vit.ac.in", "google.com", "github.com", "cloudflare.com"]

        for i in range(count):
            cur_time += random.uniform(0.01, 0.15)
            client = random.choice(hosts)
            server = random.choice(servers)
            kinds = ["HTTP", "DNS", "ICMP", "TCP_NORMAL"] + (["MULTICAST"] if include_multicast else [])
            traffic_type = random.choice(kinds)

            if traffic_type == "MULTICAST":
                evs, cur_time = TrafficGenerator._multicast_events(1, cur_time, hosts)
                packets.extend(evs)
                continue

            if traffic_type == "DNS":
                client_port = random.randint(49152, 65535)
                domain = random.choice(domains)
                # DNS Query
                pkt_q = IP(src=client, dst="8.8.8.8") / UDP(sport=client_port, dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
                pkt_q.time = cur_time
                packets.append(pkt_q)
                
                # DNS Response
                cur_time += random.uniform(0.005, 0.02)
                pkt_r = IP(src="8.8.8.8", dst=client) / UDP(sport=53, dport=client_port) / DNS(qr=1, ancount=1)
                pkt_r.time = cur_time
                packets.append(pkt_r)

            elif traffic_type == "HTTP":
                client_port = random.randint(49152, 65535)
                seq_c = random.randint(1000, 50000)
                seq_s = random.randint(1000, 50000)

                # 1. SYN
                syn = IP(src=client, dst=server) / TCP(sport=client_port, dport=80, flags="S", seq=seq_c, window=64240)
                syn.time = cur_time
                packets.append(syn)

                # 2. SYN-ACK
                cur_time += random.uniform(0.005, 0.025)
                synack = IP(src=server, dst=client) / TCP(sport=80, dport=client_port, flags="SA", seq=seq_s, ack=seq_c + 1, window=65535)
                synack.time = cur_time
                packets.append(synack)

                # 3. ACK
                cur_time += random.uniform(0.001, 0.01)
                ack = IP(src=client, dst=server) / TCP(sport=client_port, dport=80, flags="A", seq=seq_c + 1, ack=seq_s + 1, window=64240)
                ack.time = cur_time
                packets.append(ack)

                # 4. HTTP GET Request
                cur_time += random.uniform(0.002, 0.01)
                http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                http_req = IP(src=client, dst=server) / TCP(sport=client_port, dport=80, flags="PA", seq=seq_c + 1, ack=seq_s + 1, window=64240) / Raw(load=http_payload)
                http_req.time = cur_time
                packets.append(http_req)

                # 5. HTTP Response
                cur_time += random.uniform(0.01, 0.03)
                http_resp_payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 45\r\n\r\n<html><body><h1>VIT Lab Portal</h1></body></html>"
                http_resp = IP(src=server, dst=client) / TCP(sport=80, dport=client_port, flags="PA", seq=seq_s + 1, ack=seq_c + 1 + len(http_payload), window=65535) / Raw(load=http_resp_payload)
                http_resp.time = cur_time
                packets.append(http_resp)

            elif traffic_type == "ICMP":
                # Ping Request & Reply
                icmp_req = IP(src=client, dst=server) / ICMP(type=8, code=0) / Raw(load=b"VIT_NETWORK_LAB_TEST_PACKET")
                icmp_req.time = cur_time
                packets.append(icmp_req)

                cur_time += random.uniform(0.008, 0.035)
                icmp_rep = IP(src=server, dst=client) / ICMP(type=0, code=0) / Raw(load=b"VIT_NETWORK_LAB_TEST_PACKET")
                icmp_rep.time = cur_time
                packets.append(icmp_rep)

            else:  # TCP stream
                c_port = random.randint(49152, 65535)
                pkt = IP(src=client, dst=server) / TCP(sport=c_port, dport=443, flags="PA", seq=random.randint(100, 5000), ack=random.randint(100, 5000), window=32768) / Raw(load=os.urandom(128))
                pkt.time = cur_time
                packets.append(pkt)

        return TrafficGenerator._wrap_ether(packets)

    @staticmethod
    def generate_syn_flood(count: int = 100, target_ip: str = "192.168.1.100", target_port: int = 80, base_time: float = None) -> List[Packet]:
        """Generates high-velocity TCP SYN flood attack with spoofed sources and zero handshakes completed."""
        if base_time is None:
            base_time = time.time()
        packets: List[Packet] = []
        cur_time = base_time

        for _ in range(count):
            cur_time += random.uniform(0.0001, 0.002)
            spoofed_src = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            sport = random.randint(1024, 65535)
            pkt = IP(src=spoofed_src, dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S", seq=random.randint(100000, 999999), window=1024)
            pkt.time = cur_time
            packets.append(pkt)
        return TrafficGenerator._wrap_ether(packets)

    @staticmethod
    def generate_port_scan(target_ip: str = "192.168.1.50", scanner_ip: str = "192.168.1.99", base_time: float = None) -> List[Packet]:
        """Generates stealth SYN port sweep across target services."""
        if base_time is None:
            base_time = time.time()
        packets: List[Packet] = []
        cur_time = base_time

        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 9000, 27017]
        for p in ports:
            cur_time += random.uniform(0.005, 0.03)
            sport = random.randint(40000, 60000)
            pkt = IP(src=scanner_ip, dst=target_ip) / TCP(sport=sport, dport=p, flags="S", seq=random.randint(1000, 90000), window=1024)
            pkt.time = cur_time
            packets.append(pkt)

            # Target responds RST on closed ports, SYN-ACK on open ports (80, 443)
            cur_time += random.uniform(0.001, 0.005)
            if p in (80, 443):
                resp = IP(src=target_ip, dst=scanner_ip) / TCP(sport=p, dport=sport, flags="SA", seq=100, ack=pkt[TCP].seq + 1, window=65535)
            else:
                resp = IP(src=target_ip, dst=scanner_ip) / TCP(sport=p, dport=sport, flags="R", seq=0, ack=pkt[TCP].seq + 1, window=0)
            resp.time = cur_time
            packets.append(resp)
        return TrafficGenerator._wrap_ether(packets)

    @staticmethod
    def generate_dns_tunneling(count: int = 40, attacker_ip: str = "192.168.1.88", base_time: float = None) -> List[Packet]:
        """Generates DNS exfiltration / covert tunneling with high-entropy base32 encoded subdomains."""
        if base_time is None:
            base_time = time.time()
        packets: List[Packet] = []
        cur_time = base_time

        hex_chars = "0123456789abcdef"
        for _ in range(count):
            cur_time += random.uniform(0.01, 0.05)
            sport = random.randint(49152, 65535)
            chunk1 = "".join(random.choice(hex_chars) for _ in range(24))
            chunk2 = "".join(random.choice(hex_chars) for _ in range(24))
            subdomain = f"{chunk1}.{chunk2}.exfil.threat-actor-c2.net"
            pkt = IP(src=attacker_ip, dst="8.8.8.8") / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=subdomain))
            pkt.time = cur_time
            packets.append(pkt)
        return TrafficGenerator._wrap_ether(packets)

    @staticmethod
    def generate_udp_ddos(count: int = 80, target_ip: str = "192.168.1.200", base_time: float = None) -> List[Packet]:
        """Generates volumetric UDP DDoS flood."""
        if base_time is None:
            base_time = time.time()
        packets: List[Packet] = []
        cur_time = base_time

        for _ in range(count):
            cur_time += random.uniform(0.0001, 0.0015)
            spoofed_src = f"172.16.{random.randint(0,255)}.{random.randint(1,254)}"
            sport = random.randint(1024, 65535)
            dport = random.randint(10000, 60000)
            pkt = IP(src=spoofed_src, dst=target_ip) / UDP(sport=sport, dport=dport) / Raw(load=os.urandom( random.randint(512, 1400) ))
            pkt.time = cur_time
            packets.append(pkt)
        return TrafficGenerator._wrap_ether(packets)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _wrap_ether(packets: List[Packet]) -> List[Packet]:
        """Wraps IP-level packets in Ethernet frames (keeps timestamps). Frames that already have Ether are untouched."""
        out: List[Packet] = []
        for p in packets:
            if p.haslayer(Ether):
                out.append(p)
                continue
            if p.haslayer(IP):
                src, dst = p[IP].src, p[IP].dst
            elif p.haslayer(IPv6):
                src, dst = p[IPv6].src, p[IPv6].dst
            else:
                src, dst = "0.0.0.0", "0.0.0.0"
            frame = Ether(src=mac_for_ip(src), dst=mac_for_ip(dst)) / p
            frame.time = p.time
            out.append(frame)
        return out

    _MDNS_SERVICES = ["_googlecast._tcp.local", "_airplay._tcp.local", "_ipp._tcp.local",
                      "_spotify-connect._tcp.local", "_http._tcp.local", "_workstation._tcp.local",
                      "_homekit._tcp.local", "_printer._tcp.local", "_companion-link._tcp.local"]

    @staticmethod
    def _uuid() -> str:
        h = "0123456789abcdef"
        return "".join(random.choice(h) for _ in range(8)) + "-" + "-".join(
            "".join(random.choice(h) for _ in range(n)) for n in (4, 4, 4, 12))

    @staticmethod
    def _multicast_events(n_events: int, start_time: float, hosts: Optional[List[str]] = None,
                          storm_probability: float = 0.05) -> Tuple[List[Packet], float]:
        """Builds `n_events` multicast / broadcast conversations (IP-level, un-framed).

        Returns (packets, end_time). Covers the discovery protocols that dominate a home / campus LAN:
        mDNS (IPv4+IPv6), SSDP M-SEARCH/NOTIFY, LLMNR, NetBIOS name service, DHCP broadcast, IGMP.
        Occasionally a chatty device "storms" (a few hundred NOTIFYs in a second or two) because that
        is exactly what trips naive flood detectors.
        """
        hosts = hosts or ["192.168.1.10", "192.168.1.15", "192.168.1.20", "192.168.1.31", "192.168.1.44"]
        pkts: List[Packet] = []
        t = start_time
        kinds = ["mdns_q", "mdns_r", "ssdp_search", "ssdp_notify", "llmnr", "nbns", "dhcp", "igmp", "mdns6", "storm"]
        weights = [0.27, 0.14, 0.12, 0.14, 0.06, 0.06, 0.04, 0.04, 0.08, storm_probability]

        def add(pkt, when):
            pkt.time = when
            pkts.append(pkt)

        for _ in range(n_events):
            t += random.uniform(0.01, 0.4)
            kind = random.choices(kinds, weights)[0]
            h = random.choice(hosts)
            svc = random.choice(TrafficGenerator._MDNS_SERVICES)

            if kind == "mdns_q":
                for retry in range(random.choice([1, 1, 2, 3])):
                    add(IP(src=h, dst="224.0.0.251", ttl=255) / UDP(sport=5353, dport=5353) /
                        DNS(rd=0, qd=DNSQR(qname=svc, qtype="PTR")), t)
                    t += [1.0, 2.0, 4.0][retry] * random.uniform(0.9, 1.1) if retry < 2 else 0.5
            elif kind == "mdns_r":
                name = "dev-%d.%s" % (random.randint(1, 99), svc)
                add(IP(src=h, dst="224.0.0.251", ttl=255) / UDP(sport=5353, dport=5353) /
                    DNS(qr=1, aa=1, qd=None, an=DNSRR(rrname=svc, type="PTR", ttl=4500, rdata=name)), t)
            elif kind == "ssdp_search":
                sport = random.randint(40000, 60000)
                body = (b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
                        b'MX: 2\r\nST: ssdp:all\r\nUSER-AGENT: Linux/5.15 UPnP/1.1 client/1.0\r\n\r\n')
                for _r in range(random.choice([2, 3])):
                    add(IP(src=h, dst="239.255.255.250", ttl=4) / UDP(sport=sport, dport=1900) / Raw(load=body), t)
                    t += random.uniform(0.1, 0.3)
                for dev in random.sample([x for x in hosts if x != h], k=min(len(hosts) - 1, random.randint(1, 3))):
                    t += random.uniform(0.01, 0.4)
                    resp = (b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\nLOCATION: http://" +
                            dev.encode() + b":49152/description.xml\r\nSERVER: Linux/5.4 UPnP/1.0\r\nST: ssdp:all\r\nUSN: uuid:" +
                            TrafficGenerator._uuid().encode() + b"\r\n\r\n")
                    add(IP(src=dev, dst=h) / UDP(sport=1900, dport=sport) / Raw(load=resp), t)
            elif kind in ("ssdp_notify", "storm"):
                sport = 1900 if (kind == "storm" or random.random() < 0.4) else random.randint(40000, 60000)
                n = random.randint(80, 250) if kind == "storm" else random.randint(3, 8)
                gap = (0.003, 0.015) if kind == "storm" else (0.002, 0.03)
                for _n in range(n):
                    nt = random.choice(["upnp:rootdevice", "urn:schemas-upnp-org:device:MediaServer:1",
                                        "urn:schemas-upnp-org:service:ContentDirectory:1", "uuid:" + TrafficGenerator._uuid()])
                    body = (b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://" +
                            h.encode() + b":49152/desc.xml\r\nNT: " + nt.encode() + b"\r\nNTS: ssdp:alive\r\nSERVER: Linux UPnP/1.0\r\nUSN: uuid:" +
                            TrafficGenerator._uuid().encode() + b"\r\n\r\n")
                    add(IP(src=h, dst="239.255.255.250", ttl=4) / UDP(sport=sport, dport=1900) / Raw(load=body), t)
                    t += random.uniform(*gap)
            elif kind == "llmnr":
                qname = b"\x08wpad-%02d\x00" % random.randint(0, 99)
                body = os.urandom(2) + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"
                for _r in range(2):
                    add(IP(src=h, dst="224.0.0.252", ttl=1) / UDP(sport=random.randint(49152, 65535), dport=5355) / Raw(load=body), t)
                    t += random.uniform(0.1, 0.5)
            elif kind == "nbns":
                sport = 137
                for _r in range(3):
                    add(IP(src=h, dst="192.168.1.255") / UDP(sport=sport, dport=137) / Raw(load=os.urandom(50)), t)
                    t += 0.75
            elif kind == "dhcp":
                for _r in range(random.randint(1, 3)):
                    add(IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / Raw(load=os.urandom(240) + b"\x63\x82\x53\x63"), t)
                    t += random.uniform(2.0, 4.0)
            elif kind == "igmp":
                add(IP(src=h, dst="224.0.0.22", proto=2, ttl=1) /
                    Raw(load=b"\x22\x00\xf9\x02\x00\x00\x00\x01\x04\x00\x00\x00\xef\xff\xff\xfa"), t)
            elif kind == "mdns6":
                ll = "fe80::%x:%x:%x:%x" % (random.randint(1, 0xffff), random.randint(1, 0xffff), random.randint(1, 0xffff), random.randint(1, 0xffff))
                add(IPv6(src=ll, dst="ff02::fb", hlim=255) / UDP(sport=5353, dport=5353) /
                    DNS(rd=0, qd=DNSQR(qname=svc, qtype="PTR")), t)
        pkts.sort(key=lambda p: float(p.time))
        return pkts, (float(pkts[-1].time) if pkts else t)

    @staticmethod
    def generate_multicast_chatter(count: int = 40, base_time: float = None, hosts: Optional[List[str]] = None,
                                   storm_probability: float = 0.05) -> List[Packet]:
        """Multicast / broadcast LAN chatter: mDNS, SSDP, LLMNR, NetBIOS, DHCP, IGMP, IPv6 mDNS.

        `count` is the number of conversations (each is one or more packets). All of this is benign.
        """
        if base_time is None:
            base_time = time.time()
        pkts, _ = TrafficGenerator._multicast_events(count, base_time, hosts, storm_probability)
        return TrafficGenerator._wrap_ether(pkts)

    @staticmethod
    def generate_video_call(duration: float = 20.0, local_ip: str = "192.168.1.20", remote_ip: str = "52.114.132.10",
                            base_time: float = None, audio_pps: int = 50, video_pps: int = 45) -> List[Packet]:
        """Benign two-way encrypted media (WebRTC/RTP style): sustained ~100 pkts/s each way, random-looking payloads.

        Included because it looks like a UDP flood to a naive model: high packet rate, high payload entropy.
        """
        if base_time is None:
            base_time = time.time()
        pkts: List[Packet] = []
        l_port, r_port = random.randint(50000, 60000), 3478
        # STUN binding exchange
        t = base_time
        for i in range(3):
            pkts.append(IP(src=local_ip, dst=remote_ip) / UDP(sport=l_port, dport=r_port) / Raw(load=os.urandom(20)))
            pkts[-1].time = t; t += 0.02
            pkts.append(IP(src=remote_ip, dst=local_ip) / UDP(sport=r_port, dport=l_port) / Raw(load=os.urandom(32)))
            pkts[-1].time = t; t += 0.03
        # Audio: 50 pps each way, ~100-200 B. Video: 30-60 pps each way, 600-1200 B.
        for kind, pps, lo, hi, lport_off in (("audio", audio_pps, 90, 200, 0), ("video", video_pps, 500, 1200, 2)):
            for direction in ("up", "down"):
                n = int(duration * pps)
                tt = base_time + 0.2 + random.uniform(0, 0.02)
                for _ in range(n):
                    tt += random.gauss(1.0 / pps, 0.15 / pps) if pps else 0.02
                    size = random.randint(lo, hi)
                    if direction == "up":
                        pkt = IP(src=local_ip, dst=remote_ip) / UDP(sport=l_port + lport_off, dport=r_port + lport_off + 1) / Raw(load=os.urandom(size))
                    else:
                        pkt = IP(src=remote_ip, dst=local_ip) / UDP(sport=r_port + lport_off + 1, dport=l_port + lport_off) / Raw(load=os.urandom(size))
                    pkt.time = tt
                    pkts.append(pkt)
        pkts.sort(key=lambda p: float(p.time))
        return TrafficGenerator._wrap_ether(pkts)

    @staticmethod
    def generate_streaming_download(duration: float = 10.0, pps: int = 800, client_ip: str = "192.168.1.20",
                                    server_ip: str = "142.250.80.46", base_time: float = None) -> List[Packet]:
        """Benign QUIC-style bulk download: ~1200-byte encrypted UDP datagrams server->client at `pps`, small ACKs back.

        Deliberately NOT used for training. It is the hardest benign case for a flood detector: very high one-way packet
        rate, near-maximal payload entropy, large packets.
        """
        if base_time is None:
            base_time = time.time()
        pkts: List[Packet] = []
        c_port = random.randint(49152, 65535)
        t = base_time
        n = int(duration * pps)
        for k in range(n):
            t += random.gauss(1.0 / pps, 0.2 / pps)
            d = IP(src=server_ip, dst=client_ip) / UDP(sport=443, dport=c_port) / Raw(load=os.urandom(random.randint(1150, 1250)))
            d.time = t
            pkts.append(d)
            if k % 2 == 1:
                a = IP(src=client_ip, dst=server_ip) / UDP(sport=c_port, dport=443) / Raw(load=os.urandom(random.randint(30, 60)))
                a.time = t + 0.0005
                pkts.append(a)
        return TrafficGenerator._wrap_ether(pkts)

    @staticmethod
    def generate_arp_spoofing(victim_ip: str = "192.168.1.20", gateway_ip: str = "192.168.1.1",
                              attacker_ip: str = "192.168.1.66", count: int = 20, base_time: float = None,
                              attacker_mac: str = "02:00:de:ad:be:ef") -> List[Packet]:
        """ARP cache poisoning / man-in-the-middle.

        Starts with a normal exchange (victim resolves the gateway), then the attacker repeatedly sends
        *unsolicited* ARP replies claiming the gateway's IP at the attacker's MAC (to the victim) and the
        victim's IP at the attacker's MAC (to the gateway).
        """
        if base_time is None:
            base_time = time.time()
        v_mac, g_mac = mac_for_ip(victim_ip), mac_for_ip(gateway_ip)
        pkts: List[Packet] = []
        t = base_time
        # legitimate prelude
        pkts.append(Ether(src=v_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=v_mac, psrc=victim_ip, hwdst="00:00:00:00:00:00", pdst=gateway_ip))
        pkts[-1].time = t; t += 0.002
        pkts.append(Ether(src=g_mac, dst=v_mac) / ARP(op=2, hwsrc=g_mac, psrc=gateway_ip, hwdst=v_mac, pdst=victim_ip))
        pkts[-1].time = t; t += random.uniform(1.0, 2.0)
        # the attack
        for _ in range(count):
            pkts.append(Ether(src=attacker_mac, dst=v_mac) / ARP(op=2, hwsrc=attacker_mac, psrc=gateway_ip, hwdst=v_mac, pdst=victim_ip))
            pkts[-1].time = t; t += random.uniform(0.01, 0.05)
            pkts.append(Ether(src=attacker_mac, dst=g_mac) / ARP(op=2, hwsrc=attacker_mac, psrc=victim_ip, hwdst=g_mac, pdst=gateway_ip))
            pkts[-1].time = t; t += random.uniform(1.0, 2.5)
        return pkts

    @staticmethod
    def generate_benign_arp(hosts: Optional[List[str]] = None, gateway_ip: str = "192.168.1.1", count: int = 12,
                            base_time: float = None) -> List[Packet]:
        """Ordinary ARP: who-has requests (broadcast) answered by the owner, plus an occasional gratuitous ARP."""
        if base_time is None:
            base_time = time.time()
        hosts = hosts or ["192.168.1.10", "192.168.1.15", "192.168.1.20", "192.168.1.31"]
        pkts: List[Packet] = []
        t = base_time
        for _ in range(count):
            t += random.uniform(0.2, 3.0)
            asker = random.choice(hosts)
            target = random.choice([gateway_ip] + [h for h in hosts if h != asker])
            a_mac, t_mac = mac_for_ip(asker), mac_for_ip(target)
            pkts.append(Ether(src=a_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=a_mac, psrc=asker, hwdst="00:00:00:00:00:00", pdst=target))
            pkts[-1].time = t
            pkts.append(Ether(src=t_mac, dst=a_mac) / ARP(op=2, hwsrc=t_mac, psrc=target, hwdst=a_mac, pdst=asker))
            pkts[-1].time = t + random.uniform(0.0005, 0.003)
        # gratuitous ARP (a host announcing itself, same MAC as always)
        g = random.choice(hosts)
        pkts.append(Ether(src=mac_for_ip(g), dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=mac_for_ip(g), psrc=g, hwdst="00:00:00:00:00:00", pdst=g))
        pkts[-1].time = t + 1.0
        return pkts

    @staticmethod
    def generate_slowloris(attacker_ip: str = "192.168.1.77", target_ip: str = "192.168.1.50", target_port: int = 80,
                           connections: int = 60, duration: float = 60.0, base_time: float = None) -> List[Packet]:
        """Slowloris: many connections to one web server, each holding an *unfinished* HTTP request open.

        Every connection completes the TCP handshake, sends a partial request (headers with no terminating blank
        line), then trickles one bogus header line every ~10-15 s so the server never times it out.
        """
        if base_time is None:
            base_time = time.time()
        pkts: List[Packet] = []

        def add(pkt, when):
            pkt.time = when
            pkts.append(pkt)

        for c in range(connections):
            sport = random.randint(30000, 65000)
            t = base_time + random.uniform(0, min(5.0, duration / 4))
            sc, ss = random.randint(1000, 90000), random.randint(1000, 90000)
            add(IP(src=attacker_ip, dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S", seq=sc, window=29200), t)
            t += random.uniform(0.001, 0.01)
            add(IP(src=target_ip, dst=attacker_ip) / TCP(sport=target_port, dport=sport, flags="SA", seq=ss, ack=sc + 1, window=65535), t)
            t += random.uniform(0.0005, 0.005)
            add(IP(src=attacker_ip, dst=target_ip) / TCP(sport=sport, dport=target_port, flags="A", seq=sc + 1, ack=ss + 1, window=29200), t)
            t += random.uniform(0.001, 0.01)
            req = (b"GET /?" + str(random.randint(0, 2000)).encode() + b" HTTP/1.1\r\nHost: " + target_ip.encode() +
                   b"\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko\r\n"
                   b"Content-Length: 42\r\n")
            add(IP(src=attacker_ip, dst=target_ip) / TCP(sport=sport, dport=target_port, flags="PA", seq=sc + 1, ack=ss + 1, window=29200) / Raw(load=req), t)
            seq = sc + 1 + len(req)
            t += random.uniform(0.001, 0.01)
            add(IP(src=target_ip, dst=attacker_ip) / TCP(sport=target_port, dport=sport, flags="A", seq=ss + 1, ack=seq, window=65535), t)
            t += random.uniform(8.0, 15.0)
            while t < base_time + duration:
                hdr = b"X-a: " + str(random.randint(1, 5000)).encode() + b"\r\n"
                add(IP(src=attacker_ip, dst=target_ip) / TCP(sport=sport, dport=target_port, flags="PA", seq=seq, ack=ss + 1, window=29200) / Raw(load=hdr), t)
                seq += len(hdr)
                add(IP(src=target_ip, dst=attacker_ip) / TCP(sport=target_port, dport=sport, flags="A", seq=ss + 1, ack=seq, window=65535), t + 0.001)
                t += random.uniform(8.0, 15.0)
        pkts.sort(key=lambda p: float(p.time))
        return TrafficGenerator._wrap_ether(pkts)

    @staticmethod
    def generate_benign_web_sessions(connections: int = 20, client_ip: str = "192.168.1.20", server_ip: str = "192.168.1.50",
                                     duration: float = 60.0, base_time: float = None) -> List[Packet]:
        """Benign counterpart to Slowloris: many ordinary HTTP sessions (complete requests, full responses, some idle keep-alives)."""
        if base_time is None:
            base_time = time.time()
        pkts: List[Packet] = []

        def add(pkt, when):
            pkt.time = when
            pkts.append(pkt)

        for _ in range(connections):
            sport = random.randint(30000, 65000)
            t = base_time + random.uniform(0, duration * 0.8)
            sc, ss = random.randint(1000, 90000), random.randint(1000, 90000)
            add(IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=80, flags="S", seq=sc), t); t += 0.004
            add(IP(src=server_ip, dst=client_ip) / TCP(sport=80, dport=sport, flags="SA", seq=ss, ack=sc + 1), t); t += 0.002
            add(IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=80, flags="A", seq=sc + 1, ack=ss + 1), t); t += 0.003
            req = b"GET /index.html HTTP/1.1\r\nHost: portal.local\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"
            add(IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=80, flags="PA", seq=sc + 1, ack=ss + 1) / Raw(load=req), t); t += 0.02
            resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1200\r\n\r\n" + os.urandom(600)
            add(IP(src=server_ip, dst=client_ip) / TCP(sport=80, dport=sport, flags="PA", seq=ss + 1, ack=sc + 1 + len(req)) / Raw(load=resp), t); t += random.uniform(0.01, 0.05)
            add(IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=80, flags="FA", seq=sc + 1 + len(req), ack=ss + 1 + len(resp)), t)
        pkts.sort(key=lambda p: float(p.time))
        return TrafficGenerator._wrap_ether(pkts)

    @classmethod
    def create_sample_pcaps(cls, output_dir: str, seed: Optional[int] = 2026):
        """Pre-populates pcap_samples directory with individual scenario captures.

        `seed` makes the sample files reproducible (None = different every run). The global RNG state
        is restored afterwards so callers are not affected.
        """
        os.makedirs(output_dir, exist_ok=True)
        rng_state = random.getstate()
        if seed is not None:
            random.seed(seed)
        try:
            cls._write_sample_pcaps(output_dir)
        finally:
            random.setstate(rng_state)

    @classmethod
    def _write_sample_pcaps(cls, output_dir: str):
        now = time.time()

        normal_pkts = cls.generate_normal_traffic(count=60, base_time=now)
        wrpcap(os.path.join(output_dir, "normal_traffic.pcap"), normal_pkts)

        wrpcap(os.path.join(output_dir, "multicast_chatter.pcap"), cls.generate_multicast_chatter(count=80, base_time=now))

        syn_pkts = cls.generate_syn_flood(count=120, base_time=now)
        wrpcap(os.path.join(output_dir, "syn_flood_attack.pcap"), syn_pkts)

        scan_pkts = cls.generate_port_scan(base_time=now)
        wrpcap(os.path.join(output_dir, "port_scan_recon.pcap"), scan_pkts)

        dns_pkts = cls.generate_dns_tunneling(count=50, base_time=now)
        wrpcap(os.path.join(output_dir, "dns_tunneling_exfiltration.pcap"), dns_pkts)

        arp_pkts = cls.generate_benign_arp(base_time=now) + cls.generate_arp_spoofing(base_time=now + 30.0)
        arp_pkts.sort(key=lambda p: float(p.time))
        wrpcap(os.path.join(output_dir, "arp_spoofing.pcap"), arp_pkts)

        wrpcap(os.path.join(output_dir, "slowloris_attack.pcap"), cls.generate_slowloris(base_time=now))

        # Combined realistic pcap
        combined = []
        combined.extend(cls.generate_normal_traffic(count=40, base_time=now))
        combined.extend(cls.generate_syn_flood(count=60, base_time=now + 5.0))
        combined.extend(cls.generate_port_scan(base_time=now + 10.0))
        combined.extend(cls.generate_dns_tunneling(count=30, base_time=now + 15.0))
        combined.extend(cls.generate_udp_ddos(count=50, base_time=now + 20.0))
        combined.extend(cls.generate_benign_arp(base_time=now + 21.0, count=6))
        combined.extend(cls.generate_arp_spoofing(base_time=now + 22.0, count=10))
        combined.extend(cls.generate_slowloris(connections=30, duration=45.0, base_time=now + 25.0))
        combined.sort(key=lambda p: float(p.time))
        wrpcap(os.path.join(output_dir, "comprehensive_enterprise_trace.pcap"), combined)
