"""
Rule-based attack detectors that work on packet records (not flow statistics):

  * ARPSpoofDetector - ARP cache poisoning / man-in-the-middle (layer 2)
  * SlowlorisDetector - slow HTTP header attack (application layer)

Both are incremental: feed them one dissected packet record at a time with `process(record)`
(the same stream the flow aggregator sees), then ask for `findings()`. That means they work on
captures that are streamed rather than loaded into memory.

Each finding is a dict with: type, confidence (0-100), severity, summary, evidence (list of strings),
src (offender), dst (victim / target), packets, first_seen, last_seen.

Both are heuristics with documented false-positive sources (see each class's docstring).
"""

from collections import defaultdict
from typing import Dict, Any, List, Optional, Tuple
import statistics

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ")


class ARPSpoofDetector:
    """Detects ARP spoofing from conflicting IP-to-MAC bindings.

    Evidence used:
      1. Binding conflict - one IP address announced by two or more MAC addresses.
      2. Unsolicited replies - ARP replies nobody asked for (no matching who-has in the previous 10 s).
      3. Repetition - the same offending MAC re-announcing the same IP repeatedly.
      4. Frame/ARP mismatch - Ethernet source MAC differs from the ARP sender MAC (classic forgery sign).
      5. Flip-flopping - the IP's owner alternating between MACs.

    Legitimate causes of a lone conflict: DHCP lease reassignment, NIC replacement, VRRP/HSRP failover,
    NIC teaming. A lone conflict therefore scores ~50% ("needs review"); repeated unsolicited replies
    for the same IP push it past 90%.
    """

    REQUEST_WINDOW = 10.0   # seconds a who-has stays "outstanding"

    def __init__(self):
        self.reset()

    def reset(self):
        # ip -> mac -> {first, last, count, unsolicited, mismatch}
        self.bindings: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
        self.first_mac: Dict[str, str] = {}
        self.last_mac: Dict[str, str] = {}
        self.flips: Dict[str, int] = defaultdict(int)
        self.outstanding: Dict[Tuple[str, str], float] = {}
        self.mac_ips: Dict[str, str] = {}     # mac -> an IP it used in ordinary IP traffic (to name the attacker)
        self.arp_packets = 0

    def process(self, rec: Dict[str, Any]):
        proto = rec.get("protocol")
        if proto != "ARP":
            src_mac, src_ip = rec.get("src_mac"), rec.get("src_ip")
            if src_mac and src_ip and src_ip != "0.0.0.0" and src_mac not in self.mac_ips:
                self.mac_ips[src_mac] = src_ip
            return

        self.arp_packets += 1
        op = rec.get("arp_op")
        t = rec.get("timestamp", 0.0)
        psrc, pdst = rec.get("arp_psrc"), rec.get("arp_pdst")
        hwsrc = rec.get("arp_hwsrc")
        if not psrc or not hwsrc:
            return

        if op == 1:
            self.outstanding[(psrc, pdst)] = t
            if len(self.outstanding) > 50000:
                cutoff = t - self.REQUEST_WINDOW
                self.outstanding = {k: v for k, v in self.outstanding.items() if v >= cutoff}

        if psrc == "0.0.0.0":     # ARP probe (address conflict detection): not a claim of ownership
            return

        unsolicited = False
        if op == 2:
            asked = self.outstanding.get((pdst, psrc))
            unsolicited = not (asked is not None and 0 <= t - asked <= self.REQUEST_WINDOW)

        mismatch = bool(rec.get("src_mac")) and rec["src_mac"] != hwsrc

        b = self.bindings[psrc].get(hwsrc)
        if b is None:
            b = {"first": t, "last": t, "count": 0, "unsolicited": 0, "mismatch": 0}
            self.bindings[psrc][hwsrc] = b
        b["last"] = t
        b["count"] += 1
        b["unsolicited"] += int(unsolicited)
        b["mismatch"] += int(mismatch)

        if psrc not in self.first_mac:
            self.first_mac[psrc] = hwsrc
        elif self.last_mac.get(psrc) not in (None, hwsrc):
            self.flips[psrc] += 1
        self.last_mac[psrc] = hwsrc

    def binding_table(self) -> List[Dict[str, Any]]:
        """Every IP seen in ARP with the MAC(s) that claimed it (for display)."""
        rows = []
        for ip, macs in sorted(self.bindings.items()):
            rows.append({"ip": ip, "mac_count": len(macs), "macs": ", ".join(macs.keys()),
                         "announcements": sum(b["count"] for b in macs.values()),
                         "unsolicited_replies": sum(b["unsolicited"] for b in macs.values()),
                         "conflict": len(macs) > 1})
        return rows

    def findings(self) -> List[Dict[str, Any]]:
        # offender MAC -> list of per-IP conflict records
        by_offender: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for ip, macs in self.bindings.items():
            if len(macs) < 2:
                continue
            legit = self.first_mac[ip]
            for mac, b in macs.items():
                if mac == legit:
                    continue
                by_offender[mac].append({"ip": ip, "legit_mac": legit, **b, "flips": self.flips.get(ip, 0)})

        out = []
        for mac, conflicts in by_offender.items():
            best = 0
            ev = []
            for c in conflicts:
                score = 50
                reasons = [f"{c['ip']} was first announced by {c['legit_mac']}, then claimed by {mac} ({c['count']} announcement(s))"]
                if c["unsolicited"] >= 1:
                    score += 20
                    reasons.append(f"{c['unsolicited']} unsolicited ARP reply(ies) for {c['ip']}")
                if c["unsolicited"] >= 5:
                    score += 10
                if c["count"] >= 5:
                    score += 10
                    reasons.append("repeated re-announcement (cache keep-alive pattern)")
                if c["mismatch"]:
                    score += 15
                    reasons.append(f"Ethernet source MAC differs from ARP sender MAC in {c['mismatch']} frame(s)")
                if c["flips"] >= 3:
                    score += 10
                    reasons.append(f"binding flipped between MACs {c['flips']} times")
                best = max(best, min(score, 99))
                ev.extend(reasons)
            n_claimed = len(conflicts)
            if n_claimed >= 2:     # one MAC claiming several IPs that already belong to others: classic MITM pair
                best = min(99, best + 5)
                ev.append(f"{mac} claims {n_claimed} IP addresses that other hosts own")
            first = min(c["first"] for c in conflicts)
            last = max(c["last"] for c in conflicts)
            claimed = sorted(c["ip"] for c in conflicts)
            out.append({
                "type": "ARP_SPOOFING",
                "confidence": float(best),
                "severity": "HIGH",
                "src": mac,
                "src_mac": mac,
                "src_ip": self.mac_ips.get(mac, ""),
                "dst": ", ".join(claimed),
                "dst_port": 0,
                "protocol": "ARP",
                "packets": sum(c["count"] for c in conflicts),
                "flows": 0,
                "first_seen": first,
                "last_seen": last,
                "conflicts": [{"ip": c["ip"], "legit_mac": c["legit_mac"]} for c in conflicts],
                "summary": f"MAC {mac} is impersonating {', '.join(claimed)}",
                "evidence": ev,
            })
        return out


class SlowlorisDetector:
    """Detects Slowloris (slow HTTP headers) from connection-level behaviour.

    Slowloris opens many TCP connections to one web server and sends each request *incompletely*:
    request line and a few headers, never the terminating blank line, then trickles another header
    every ~10-15 s so the server keeps the connection (and its worker) reserved.

    Signature used: >= `min_conns` connections from one client to one server:port whose HTTP request
    never completed (no CRLFCRLF), ideally with trickle segments after the first one.

    Cleartext HTTP only. TLS-wrapped slow attacks, and variants that finish the headers but send the body slowly
    (R.U.D.Y.), are not detected. A capture window shorter than the attacker's trickle interval
    (~10 s) still shows the unfinished requests but loses the trickle evidence, lowering the score.
    False-positive sources: a capture that simply ends while many requests are mid-flight, or a flaky mobile client
    holding many half-sent requests.
    """

    MAX_TRACKED = 200_000

    def __init__(self, min_conns: int = 10):
        self.min_conns = min_conns
        self.reset()

    def reset(self):
        # (client_ip, client_port, server_ip, server_port) -> state
        self.conns: Dict[Tuple[str, int, str, int], Dict[str, Any]] = {}
        self.initiator: Dict[Tuple, Tuple[str, int]] = {}   # canonical pair -> (client_ip, client_port)

    @staticmethod
    def _canon(a_ip, a_port, b_ip, b_port):
        return (a_ip, a_port, b_ip, b_port) if (a_ip, a_port) <= (b_ip, b_port) else (b_ip, b_port, a_ip, a_port)

    def process(self, rec: Dict[str, Any]):
        if rec.get("protocol") not in ("TCP", "HTTP"):
            return
        src, sport = rec.get("src_ip"), rec.get("src_port", 0)
        dst, dport = rec.get("dst_ip"), rec.get("dst_port", 0)
        flags = rec.get("tcp_flags") or {}
        t = rec.get("timestamp", 0.0)
        canon = self._canon(src, sport, dst, dport)

        # The client is whoever sent the first SYN; otherwise the first sender of an HTTP request line.
        if flags.get("S") and not flags.get("A"):
            self.initiator[canon] = (src, sport)
        payload = rec.get("payload_bytes") or b""
        client = self.initiator.get(canon)
        if client is None:
            if payload.startswith(HTTP_METHODS):
                self.initiator[canon] = client = (src, sport)
            else:
                return

        if (src, sport) != client:
            c = self.conns.get((client[0], client[1], dst, dport))
            if c is not None and (flags.get("F") or flags.get("R")):
                c["ended"] = True
            return

        key = (src, sport, dst, dport)
        c = self.conns.get(key)
        if c is None:
            if not payload.startswith(HTTP_METHODS) or len(self.conns) >= self.MAX_TRACKED:
                return
            c = {"first": t, "last": t, "started": True, "complete": False, "tail": b"",
                 "segments": 0, "bytes": 0, "ended": False}
            self.conns[key] = c
        if flags.get("F") or flags.get("R"):
            c["ended"] = True
        if payload:
            if not c["complete"]:
                window = c["tail"] + payload
                if b"\r\n\r\n" in window:
                    c["complete"] = True
                c["tail"] = window[-3:]
            c["segments"] += 1
            c["bytes"] += len(payload)
            c["last"] = t

    def server_summary(self) -> List[Dict[str, Any]]:
        """Per client -> server:port summary of HTTP request completion (for display)."""
        groups: Dict[Tuple[str, str, int], List[Dict[str, Any]]] = defaultdict(list)
        for (cip, cport, sip, sport), c in self.conns.items():
            groups[(cip, sip, sport)].append(c)
        rows = []
        for (cip, sip, sport), conns in sorted(groups.items()):
            inc = [c for c in conns if not c["complete"]]
            rows.append({"client": cip, "server": f"{sip}:{sport}", "http_connections": len(conns),
                         "unfinished_requests": len(inc),
                         "unfinished_pct": round(100.0 * len(inc) / len(conns), 1),
                         "avg_bytes_unfinished": round(sum(c["bytes"] for c in inc) / len(inc), 1) if inc else 0.0})
        return rows

    def findings(self) -> List[Dict[str, Any]]:
        groups: Dict[Tuple[str, str, int], List[Dict[str, Any]]] = defaultdict(list)
        for (cip, cport, sip, sport), c in self.conns.items():
            c = dict(c, client_port=cport)
            groups[(cip, sip, sport)].append(c)

        out = []
        for (cip, sip, sport), conns in groups.items():
            incomplete = [c for c in conns if not c["complete"]]
            n_inc = len(incomplete)
            if n_inc < self.min_conns:
                continue
            frac = n_inc / len(conns)
            if frac < 0.8:
                continue
            trickled = [c for c in incomplete if c["segments"] >= 2]
            frac_trickle = len(trickled) / n_inc
            open_secs = statistics.median(c["last"] - c["first"] for c in incomplete)
            avg_bytes = statistics.mean(c["bytes"] for c in incomplete)

            score = 40
            ev = [f"{n_inc} of {len(conns)} HTTP connections from {cip} to {sip}:{sport} never completed their request headers "
                  f"({frac:.0%})"]
            score += min(30, int(30 * n_inc / (self.min_conns * 3)))
            if frac >= 0.9:
                score += 10
            if frac_trickle >= 0.5:
                score += 15
                ev.append(f"{len(trickled)} of them kept dribbling extra header lines ({avg_bytes:.0f} bytes per connection on average)")
            else:
                ev.append(f"average only {avg_bytes:.0f} bytes sent per connection; no trickle seen (capture may be too short)")
            if open_secs >= 10:
                score += 5
                ev.append(f"median time held open: {open_secs:.0f} s")
            score = min(score, 99)
            out.append({
                "type": "SLOWLORIS",
                "confidence": float(score),
                "severity": "HIGH",
                "src": cip,
                "src_ip": cip,
                "dst": sip,
                "dst_ip": sip,
                "dst_port": sport,
                "protocol": "HTTP",
                "packets": sum(c["segments"] for c in conns),
                "flows": len(conns),
                "first_seen": min(c["first"] for c in conns),
                "last_seen": max(c["last"] for c in conns),
                "summary": f"{cip} is holding {n_inc} unfinished HTTP requests open against {sip}:{sport}",
                "evidence": ev,
            })
        return out


class DetectorSuite:
    """Runs every packet-level detector over one packet stream."""

    def __init__(self):
        self.arp = ARPSpoofDetector()
        self.slowloris = SlowlorisDetector()

    def process(self, rec: Dict[str, Any]):
        self.arp.process(rec)
        self.slowloris.process(rec)

    def findings(self) -> List[Dict[str, Any]]:
        return self.arp.findings() + self.slowloris.findings()

    def reset(self):
        self.arp.reset()
        self.slowloris.reset()
