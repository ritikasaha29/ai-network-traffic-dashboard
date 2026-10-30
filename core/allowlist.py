"""
Trusted-address allowlist.

Lets an operator mark addresses (a router, a printer, multicast groups, a whole subnet, a MAC)
as trusted so traffic involving them never raises an incident.

Entries can be:
  * a single IP address         192.168.1.1, fe80::1
  * a CIDR range                224.0.0.0/4, ff00::/8, 192.168.1.0/24
  * a MAC address               02:00:de:ad:be:ef   (matched against the offending MAC of layer-2 findings)

Matching mode for IP entries (flow-based incidents and Slowloris):
  * "source"      trust traffic *from* the entry
  * "destination" trust traffic *to* the entry
  * "either"      (default) trust traffic in either direction

Caveat worth knowing: trusting a host also trusts attacks that target it (with "either" / "destination").
ARP spoofing findings are deliberately NOT suppressed by an IP entry, because the thing being spoofed is
usually the router's IP; only the attacker's MAC can suppress them.
"""

import ipaddress
import json
import os
import re
from typing import Dict, Any, List, Optional, Tuple

_MAC_RE = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.IGNORECASE)

PRESETS: Dict[str, List[str]] = {
    "Multicast & broadcast (IPv4/IPv6)": ["224.0.0.0/4", "ff00::/8", "255.255.255.255"],
}

MATCH_MODES = ("either", "source", "destination")


def normalize_entry(text: str) -> Optional[str]:
    """Canonical string for a valid entry, or None if it is not an IP / CIDR / MAC."""
    text = (text or "").strip()
    if not text:
        return None
    if _MAC_RE.match(text):
        return text.lower().replace("-", ":")
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    if net.num_addresses == 1:
        return str(net.network_address)
    return str(net)


class Allowlist:
    def __init__(self, entries: Optional[List[str]] = None, path: Optional[str] = None):
        self.path = path
        self._entries: List[str] = []
        self._nets: List[Tuple[Any, str]] = []
        self._macs: set = set()
        if entries:
            for e in entries:
                self.add(e)

    # ---------------------------------------------------------------- editing
    @property
    def entries(self) -> List[str]:
        return list(self._entries)

    def add(self, text: str) -> bool:
        norm = normalize_entry(text)
        if norm is None:
            return False
        if norm in self._entries:
            return True
        self._entries.append(norm)
        self._rebuild()
        return True

    def add_many(self, text: str) -> Tuple[List[str], List[str]]:
        """Adds entries separated by commas / spaces / newlines. Returns (added, rejected)."""
        added, rejected = [], []
        for tok in re.split(r"[,\s;]+", text or ""):
            if not tok:
                continue
            if self.add(tok):
                added.append(normalize_entry(tok))
            else:
                rejected.append(tok)
        return added, rejected

    def remove(self, entry: str):
        if entry in self._entries:
            self._entries.remove(entry)
            self._rebuild()

    def clear(self):
        self._entries.clear()
        self._rebuild()

    def _rebuild(self):
        self._nets, self._macs = [], set()
        for e in self._entries:
            if _MAC_RE.match(e):
                self._macs.add(e)
            else:
                self._nets.append((ipaddress.ip_network(e, strict=False), e))

    @property
    def signature(self) -> str:
        """Changes whenever the list changes (used to invalidate cached analysis)."""
        return "|".join(sorted(self._entries))

    # ---------------------------------------------------------------- matching
    def match_ip(self, ip: str) -> Optional[str]:
        """The entry that contains `ip`, or None."""
        if not self._nets:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, label in self._nets:
            if addr.version == net.version and addr in net:
                return label
        return None

    def match_mac(self, mac: str) -> Optional[str]:
        mac = (mac or "").lower()
        return mac if mac in self._macs else None

    def flow_trusted(self, flow: Dict[str, Any], mode: str = "either") -> Optional[str]:
        """The matching entry if this flow's endpoints are trusted under `mode`, else None."""
        hit = None
        if mode in ("either", "source"):
            hit = self.match_ip(flow.get("src_ip", ""))
        if hit is None and mode in ("either", "destination"):
            hit = self.match_ip(flow.get("dst_ip", ""))
        return hit

    # ---------------------------------------------------------------- persistence
    def save(self, path: Optional[str] = None):
        path = path or self.path
        if not path:
            return
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"entries": self._entries}, f, indent=2)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str) -> "Allowlist":
        al = cls(path=path)
        try:
            with open(path, "r", encoding="utf-8") as f:
                for e in json.load(f).get("entries", []):
                    al.add(e)
        except (OSError, ValueError):
            pass
        return al
