#!/usr/bin/env python3
"""
Measure false alarms (and detections) of the whole pipeline on capture files.

Usage
-----
  # benign captures you recorded (home Wi-Fi, a quiet network, a video call ...): every alert is a false alarm
  python tools/evaluate_captures.py captures/home_wifi.pcapng captures/video_call.pcapng

  # a directory of captures
  python tools/evaluate_captures.py captures/

  # captures that DO contain attacks; list which incident types you expect
  python tools/evaluate_captures.py --attack lab/synflood.pcap:SYN_FLOOD --attack lab/mitm.pcap:ARP_SPOOFING

  # write the simulated demo set, then evaluate it (clearly labelled as simulated)
  python tools/evaluate_captures.py --simulate captures_sim/ captures_sim/

Options: --threshold 70   confidence threshold for raising an incident
         --max-packets N  stop reading each file after N packets
         --allow ENTRY    allowlist entry (repeatable)
         --markdown FILE / --csv FILE / --json FILE   save results

For every capture it reports, with and without the multicast/broadcast guardrail:
  * flow alerts      flows the models flagged (before grouping)           -> flow false-positive rate
  * confirmed        incidents raised at/above the threshold              -> false alarms on benign captures
  * needs review     incidents listed but not raised
"""

import argparse
import csv
import json
import os
import sys
import time
import warnings

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.ai_engine import AIEngine                      # noqa: E402
from core.allowlist import Allowlist                      # noqa: E402
from core.session import CaptureSession                   # noqa: E402
from core.sniffer import DEFAULT_MAX_PACKETS              # noqa: E402

CAPTURE_EXTS = (".pcap", ".pcapng", ".cap")


def collect_paths(items):
    out = []
    for it in items:
        if os.path.isdir(it):
            out += sorted(os.path.join(it, f) for f in os.listdir(it) if f.lower().endswith(CAPTURE_EXTS))
        else:
            out.append(it)
    return out


def evaluate(path, ai, threshold, allowlist, max_packets, expected=None):
    """Runs one capture with the guardrail on and off. `expected` = set of incident types for attack captures."""
    row = {"capture": os.path.basename(path), "kind": "attack" if expected is not None else "benign"}
    for mode, flag in (("guardrail_on", True), ("guardrail_off", False)):
        ai.guardrails_enabled = flag
        s = CaptureSession()
        info = s.load_pcap(path, max_packets=max_packets)
        a = s.analyze(ai, allowlist, threshold)
        flows = a["flow_predictions"]
        flagged = sum(1 for f in flows if f["mitigation_required"])
        r = {
            "packets": info["packets_read"], "flows": len(flows),
            "flow_alerts": flagged,
            "flow_alert_rate_pct": round(100.0 * flagged / len(flows), 1) if flows else 0.0,
            "confirmed": len(a["confirmed"]), "needs_review": len(a["needs_review"]),
            "confirmed_types": sorted({i["type"] for i in a["confirmed"]}),
            "guardrailed_flows": a["suppression"]["flows_guardrailed"],
            "span_s": round(max((x["timestamp"] for x in a["window_records"]), default=0) - min((x["timestamp"] for x in a["window_records"]), default=0), 1),
        }
        if expected is not None:
            got = set(r["confirmed_types"])
            r["detected"] = sorted(expected & got)
            r["missed"] = sorted(expected - got)
            r["unexpected"] = sorted(got - expected)
        row[mode] = r
    ai.guardrails_enabled = True
    return row


def render_markdown(rows, threshold, simulated_note):
    L = ["# Capture evaluation", "", f"Generated {time.strftime('%Y-%m-%d %H:%M:%S')}  |  confidence threshold {threshold:g}%", ""]
    if simulated_note:
        L += [f"> **{simulated_note}**", ""]
    L += ["## Benign captures (every alert is a false alarm)", "",
          "| Capture | Packets | Flows | Flow alerts (guardrail on) | Flow FP rate | Confirmed incidents | Needs review | Flow alerts (guardrail off) | Flow FP rate (off) | Confirmed (off) |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for r in (x for x in rows if x["kind"] == "benign"):
        on, off = r["guardrail_on"], r["guardrail_off"]
        L.append(f"| {r['capture']} | {on['packets']:,} | {on['flows']:,} | {on['flow_alerts']} | {on['flow_alert_rate_pct']}% | "
                 f"**{on['confirmed']}** {on['confirmed_types'] or ''} | {on['needs_review']} | {off['flow_alerts']} | {off['flow_alert_rate_pct']}% | {off['confirmed']} |")
    atk = [x for x in rows if x["kind"] == "attack"]
    if atk:
        L += ["", "## Attack captures (detections)", "", "| Capture | Expected | Detected | Missed | Unexpected confirmed | Needs review |", "|---|---|---|---|---|---|"]
        for r in atk:
            on = r["guardrail_on"]
            L.append(f"| {r['capture']} | {', '.join(on['detected'] + on['missed'])} | {', '.join(on['detected']) or '-'} | "
                     f"{', '.join(on['missed']) or '-'} | {', '.join(on['unexpected']) or '-'} | {on['needs_review']} |")
    ben = [x["guardrail_on"] for x in rows if x["kind"] == "benign"]
    if ben:
        tf, ta = sum(b["flows"] for b in ben), sum(b["flow_alerts"] for b in ben)
        L += ["", f"**Overall (benign):** {ta} of {tf} flows flagged ({100.0 * ta / tf if tf else 0:.1f}%); "
                  f"{sum(b['confirmed'] for b in ben)} confirmed incident(s) across {len(ben)} capture(s)."]
    return "\n".join(L) + "\n"


def write_simulated_set(out_dir):
    """Writes benign simulated captures with seeds/parameters that differ from the training data."""
    import random
    from scapy.all import wrpcap
    from core.traffic_generator import TrafficGenerator as G
    os.makedirs(out_dir, exist_ok=True)
    state = random.getstate()
    now = 1_760_000_000.0
    try:
        random.seed(7001)
        home = (G.generate_normal_traffic(count=500, base_time=now) + G.generate_multicast_chatter(count=250, base_time=now)
                + G.generate_benign_web_sessions(connections=25, duration=120, base_time=now + 5)
                + G.generate_benign_arp(count=25, base_time=now) + G.generate_video_call(duration=15, base_time=now + 30))
        home.sort(key=lambda p: float(p.time)); wrpcap(os.path.join(out_dir, "sim_home_wifi.pcap"), home)

        random.seed(7002)
        quiet = (G.generate_multicast_chatter(count=200, base_time=now, storm_probability=0.02)
                 + G.generate_normal_traffic(count=15, base_time=now, include_multicast=False) + G.generate_benign_arp(count=10, base_time=now))
        quiet.sort(key=lambda p: float(p.time)); wrpcap(os.path.join(out_dir, "sim_quiet_network.pcap"), quiet)

        random.seed(7003)
        call = G.generate_video_call(duration=40, base_time=now, audio_pps=50, video_pps=45) + G.generate_multicast_chatter(count=30, base_time=now)
        call.sort(key=lambda p: float(p.time)); wrpcap(os.path.join(out_dir, "sim_video_call.pcap"), call)

        random.seed(7004)   # outside the training range (training used video 15-60 pps, audio 25-100 pps)
        hd = G.generate_video_call(duration=30, base_time=now, audio_pps=100, video_pps=150) + G.generate_multicast_chatter(count=30, base_time=now)
        hd.sort(key=lambda p: float(p.time)); wrpcap(os.path.join(out_dir, "sim_video_call_hd_unseen.pcap"), hd)

        random.seed(7005)   # never part of training
        dl = G.generate_streaming_download(duration=12, pps=800, base_time=now) + G.generate_multicast_chatter(count=20, base_time=now)
        dl.sort(key=lambda p: float(p.time)); wrpcap(os.path.join(out_dir, "sim_streaming_download_unseen.pcap"), dl)

        random.seed(7006)
        atk = (G.generate_syn_flood(count=200, base_time=now) + G.generate_port_scan(base_time=now + 5) + G.generate_arp_spoofing(base_time=now + 8)
               + G.generate_slowloris(connections=40, duration=45, base_time=now + 10) + G.generate_normal_traffic(count=100, base_time=now))
        atk.sort(key=lambda p: float(p.time)); wrpcap(os.path.join(out_dir, "sim_attacks.pcap"), atk)
    finally:
        random.setstate(state)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", help="benign capture files or directories")
    ap.add_argument("--attack", action="append", default=[], metavar="FILE:TYPE[,TYPE]", help="capture that contains attacks, with expected incident types")
    ap.add_argument("--threshold", type=float, default=70.0)
    ap.add_argument("--max-packets", type=int, default=DEFAULT_MAX_PACKETS)
    ap.add_argument("--allow", action="append", default=[], help="allowlist entry (IP, CIDR or MAC); repeatable")
    ap.add_argument("--model-dir", default=None)
    ap.add_argument("--simulate", metavar="DIR", help="write the simulated demo captures into DIR first")
    ap.add_argument("--markdown"); ap.add_argument("--csv"); ap.add_argument("--json")
    args = ap.parse_args()

    if args.simulate:
        write_simulated_set(args.simulate)
        print(f"wrote simulated captures to {args.simulate}")

    ai = AIEngine(model_dir=args.model_dir)
    allow = Allowlist(args.allow)
    rows = []
    sim_names = set()
    for p in collect_paths(args.paths):
        rows.append(evaluate(p, ai, args.threshold, allow, args.max_packets))
        sim_names.add(os.path.basename(p).startswith("sim_"))
    for spec in args.attack:
        path, _, types = spec.partition(":")
        rows.append(evaluate(path, ai, args.threshold, allow, args.max_packets, set(filter(None, types.split(",")))))
    # the simulated attack capture is a convenience: expected types are known
    for r in rows:
        if r["capture"] == "sim_attacks.pcap" and r["kind"] == "benign":
            exp = {"SYN_FLOOD", "PORT_SCAN", "ARP_SPOOFING", "SLOWLORIS"}
            got = set(r["guardrail_on"]["confirmed_types"])
            r["kind"] = "attack"
            for m in ("guardrail_on", "guardrail_off"):
                g = set(r[m]["confirmed_types"])
                r[m].update(detected=sorted(exp & g), missed=sorted(exp - g), unexpected=sorted(g - exp))

    note = ("These captures are SIMULATED by this project's traffic generator, not recorded from a real network. "
            "They show the tool works; re-run it on real recordings for real false-positive rates.") if any(sim_names) else ""
    md = render_markdown(rows, args.threshold, note)
    print(md)
    if args.markdown:
        open(args.markdown, "w", encoding="utf-8").write(md)
    if args.json:
        json.dump(rows, open(args.json, "w"), indent=2)
    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["capture", "kind", "mode", "packets", "flows", "flow_alerts", "flow_alert_rate_pct", "confirmed", "needs_review", "guardrailed_flows"])
            for r in rows:
                for m in ("guardrail_on", "guardrail_off"):
                    x = r[m]
                    w.writerow([r["capture"], r["kind"], m, x["packets"], x["flows"], x["flow_alerts"], x["flow_alert_rate_pct"], x["confirmed"], x["needs_review"], x["guardrailed_flows"]])


if __name__ == "__main__":
    main()
