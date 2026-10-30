"""
Incident grouping.

A per-flow model verdict is not an incident. A SYN flood is thousands of one-packet flows from spoofed
sources; a port scan is one flow per probed port. This module groups flagged flows (and the findings of
the packet-level detectors) into incidents, scores each one, and decides whether to RAISE it
(status CONFIRMED) or leave it for a human (status NEEDS_REVIEW).

An incident is CONFIRMED only if
  * its confidence >= `threshold` (default 70%), AND
  * it has enough evidence for its type (see MIN_EVIDENCE: a lone SYN-looking flow is not a "flood").
Everything else is NEEDS_REVIEW: listed, but excluded from alert counts and firewall rules.

Confidence is the mean of the member flows' classifier confidence (Random Forest class probability, %).
Anomaly-only incidents (Isolation Forest said "unusual" but the classifier said NORMAL) have no class
probability to speak of, so they are always NEEDS_REVIEW. Findings from the rule-based detectors carry
their own evidence-based score.
"""

from collections import defaultdict
from typing import Dict, Any, List, Optional, Tuple

from core.allowlist import Allowlist

DEFAULT_CONFIDENCE_THRESHOLD = 70.0

# type -> (min flows, min packets). An incident needs either many flows OR a lot of packets.
MIN_EVIDENCE: Dict[str, Tuple[int, int]] = {
    "SYN_FLOOD": (10, 50),
    "UDP_DDOS": (10, 50),
    "PORT_SCAN": (5, 40),
    "DNS_TUNNELING": (5, 20),
    "ANOMALY": (1, 1),
}

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

CONFIRMED = "CONFIRMED"
NEEDS_REVIEW = "NEEDS_REVIEW"


def _group_key(f: Dict[str, Any]) -> Tuple[str, Tuple]:
    pred = f["prediction"]
    if pred == "NORMAL":
        return "ANOMALY", (f.get("src_ip"),)
    if pred == "SYN_FLOOD":
        return pred, (f.get("dst_ip"), f.get("dst_port"))      # many (often spoofed) sources -> one victim service
    if pred == "UDP_DDOS":
        return pred, (f.get("dst_ip"),)
    if pred == "PORT_SCAN":
        return pred, (f.get("src_ip"), f.get("dst_ip"))        # one scanner -> one target, many ports
    if pred == "DNS_TUNNELING":
        return pred, (f.get("src_ip"), f.get("dst_ip"))        # one client -> one resolver
    return pred, (f.get("src_ip"), f.get("dst_ip"))


def _describe(kind: str, flows: List[Dict[str, Any]]) -> Tuple[str, str, str, int, str]:
    """Returns (src label, dst label, dst_port-ish, port int, summary)."""
    srcs = sorted({f["src_ip"] for f in flows})
    dsts = sorted({f["dst_ip"] for f in flows})
    ports = sorted({f["dst_port"] for f in flows if f.get("dst_port")})
    src_label = srcs[0] if len(srcs) == 1 else f"{len(srcs)} sources"
    dst_label = dsts[0] if len(dsts) == 1 else f"{len(dsts)} destinations"
    port = ports[0] if len(ports) == 1 else 0
    pk = sum(f["total_packets"] for f in flows)
    if kind == "SYN_FLOOD":
        s = f"{len(flows)} SYN-only flows from {src_label} to {dst_label}:{port or 'multiple ports'} ({pk} packets)"
    elif kind == "UDP_DDOS":
        s = f"{len(flows)} high-volume UDP flows from {src_label} to {dst_label} ({pk} packets)"
    elif kind == "PORT_SCAN":
        s = f"{src_label} probed {len(ports)} distinct ports on {dst_label}"
    elif kind == "DNS_TUNNELING":
        s = f"{src_label} sent {pk} long, high-entropy DNS queries to {dst_label}"
    else:
        s = f"{len(flows)} unusual flow(s) from {src_label} (anomaly detector only, classifier says normal)"
    return src_label, dst_label, port, s


def _aggregate_evidence(kind: str, flows: List[Dict[str, Any]]) -> str:
    """One line of numbers that actually mean something for this incident type."""
    n = len(flows)
    pk = sum(f["total_packets"] for f in flows)
    by = sum(f["total_bytes"] for f in flows)
    span = max(0.001, max(f.get("end_time", 0.0) for f in flows) - min(f.get("start_time", 0.0) for f in flows))
    line = f"{pk} packets / {by / 1024:.1f} KB over {span:.1f} s (aggregate {pk / span:.0f} pkt/s)"
    if kind in ("SYN_FLOOD", "PORT_SCAN"):
        line += f"; mean SYN ratio {sum(f['syn_ratio'] for f in flows) / n:.2f}, mean RST ratio {sum(f['rst_ratio'] for f in flows) / n:.2f}"
    elif kind == "UDP_DDOS":
        line += f"; mean packet size {by / max(pk, 1):.0f} B, mean payload entropy {sum(f['payload_entropy_mean'] for f in flows) / n:.2f} bits/byte"
    elif kind == "DNS_TUNNELING":
        line += (f"; mean query length {sum(f['dns_query_len_mean'] for f in flows) / n:.0f} chars, "
                 f"mean query entropy {sum(f['dns_entropy_mean'] for f in flows) / n:.2f} bits/char")
    return line


def build_incidents(flow_predictions: List[Dict[str, Any]],
                    detector_findings: Optional[List[Dict[str, Any]]] = None,
                    threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
                    allowlist: Optional[Allowlist] = None,
                    allowlist_mode: str = "either") -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Groups flagged flows + detector findings into incidents.

    Returns (incidents sorted most serious first, stats). `stats` counts what was left out and why, so
    the dashboard can show that nothing disappeared silently.
    """
    stats = {"flows_total": len(flow_predictions), "flows_flagged": 0, "flows_allowlisted": 0,
             "flows_guardrailed": 0, "findings_allowlisted": 0, "anomaly_incidents_merged": 0}
    groups: Dict[Tuple, List[Dict[str, Any]]] = defaultdict(list)

    for f in flow_predictions:
        if f.get("guardrail"):
            stats["flows_guardrailed"] += 1
        if not f.get("mitigation_required"):
            continue
        stats["flows_flagged"] += 1
        if allowlist is not None:
            hit = allowlist.flow_trusted(f, allowlist_mode)
            if hit:
                stats["flows_allowlisted"] += 1
                continue
        kind, key = _group_key(f)
        groups[(kind,) + key].append(f)

    incidents: List[Dict[str, Any]] = []
    for gkey, flows in groups.items():
        kind = gkey[0]
        n_flows = len(flows)
        n_pkts = sum(f["total_packets"] for f in flows)
        src, dst, port, summary = _describe(kind, flows)
        if kind == "ANOMALY":
            conf: Optional[float] = None
            sev = "MEDIUM"
        else:
            conf = round(sum(f["confidence"] for f in flows) / n_flows, 1)
            sev = max((f["severity"] for f in flows), key=lambda s: SEVERITY_RANK.get(s, 0))
        min_flows, min_pkts = MIN_EVIDENCE.get(kind, (1, 1))
        enough = n_flows >= min_flows or n_pkts >= min_pkts
        reasons = []
        if conf is None:
            reasons.append("anomaly-only: no classifier confidence")
        elif conf < threshold:
            reasons.append(f"confidence {conf}% is below the {threshold:g}% threshold")
        if not enough:
            reasons.append(f"only {n_flows} flow(s) / {n_pkts} packet(s); needs {min_flows} flows or {min_pkts} packets")
        incidents.append({
            "type": kind,
            "status": CONFIRMED if not reasons else NEEDS_REVIEW,
            "review_reason": "; ".join(reasons),
            "severity": sev,
            "confidence": conf,
            "src": src,
            "dst": dst,
            "dst_port": port,
            "src_ip": flows[0]["src_ip"] if src == flows[0]["src_ip"] else "",
            "protocol": flows[0].get("protocol", ""),
            "flows": n_flows,
            "packets": n_pkts,
            "first_seen": min(f.get("start_time", 0.0) for f in flows),
            "last_seen": max(f.get("end_time", 0.0) for f in flows),
            "summary": summary,
            "evidence": [_aggregate_evidence(kind, flows)],
            "example_flow": flows[0],
            "source": "flow-model",
        })

    for d in (detector_findings or []):
        trusted = None
        if allowlist is not None:
            if d["type"] == "ARP_SPOOFING":
                trusted = allowlist.match_mac(d.get("src_mac", ""))      # IP entries never silence ARP spoofing
            else:
                trusted = allowlist.flow_trusted(d, allowlist_mode)
        if trusted:
            stats["findings_allowlisted"] += 1
            continue
        reasons = []
        if d["confidence"] < threshold:
            reasons.append(f"confidence {d['confidence']:g}% is below the {threshold:g}% threshold")
        incidents.append({
            **d,
            "status": CONFIRMED if not reasons else NEEDS_REVIEW,
            "review_reason": "; ".join(reasons),
            "example_flow": {"src_ip": d.get("src_ip") or d["src"], "dst_ip": d.get("dst_ip", d["dst"]), "dst_port": d.get("dst_port", 0),
                             "protocol": d.get("protocol", "TCP"), "prediction": d["type"]},
            "source": "packet-detector",
        })

    # An anomaly-only incident from a host that a dedicated detector already explains is the same story twice.
    explained = {d.get("src_ip") for d in incidents if d.get("source") == "packet-detector" and d.get("src_ip")}
    kept = [i for i in incidents if not (i["type"] == "ANOMALY" and i.get("src_ip") in explained)]
    stats["anomaly_incidents_merged"] = len(incidents) - len(kept)
    incidents = kept

    incidents.sort(key=lambda i: (i["status"] != CONFIRMED, -SEVERITY_RANK.get(i["severity"], 0), -(i["confidence"] or 0), -i["packets"]))
    for n, inc in enumerate(incidents, 1):
        inc["incident_id"] = f"INC-{n:03d}"
    return incidents, stats
