"""
AI-Driven Network Traffic Intelligence Dashboard
BCSE308P - Computer Networks Lab Project
School of Computer Science and Engineering, VIT Vellore
Supervisor: Dr. S. Ebenezer Juliet
"""

import os
import sys
import time
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Setup import path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)

from core.traffic_generator import TrafficGenerator
from core.sniffer import PacketDissector, DEFAULT_MAX_PACKETS, DEFAULT_DISPLAY_WINDOW
from core.ai_engine import AIEngine, LABELS
from core.forensics import ForensicsAnalyzer
from core.session import CaptureSession
from core.allowlist import Allowlist, PRESETS, MATCH_MODES, normalize_entry
from core.incidents import DEFAULT_CONFIDENCE_THRESHOLD
from core.report import build_report, render_markdown, render_pdf

# Streamlit Page Config
st.set_page_config(
    page_title="AI Network Traffic Intelligence Dashboard | BCSE308P",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .metric-card {
        background-color: #0e1117;
        border: 1px solid #262730;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 10px;
    }
    .stAlert {
        border-radius: 8px;
    }
    .badge-critical {
        background-color: #ff4b4b;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
    .badge-high {
        background-color: #ffa500;
        color: black;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
    .badge-low {
        background-color: #00cc66;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Initialize Session State
ALLOWLIST_PATH = os.path.join(BASE_DIR, "allowlist.json")


@st.cache_resource(show_spinner="Loading AI models (trains on first run, about a minute)...")
def get_ai_engine() -> AIEngine:
    return AIEngine()


if "capture" not in st.session_state:
    st.session_state.capture = CaptureSession()
if "allowlist" not in st.session_state:
    st.session_state.allowlist = Allowlist.load(ALLOWLIST_PATH)
if "current_pcap" not in st.session_state:
    st.session_state.current_pcap = "comprehensive_enterprise_trace.pcap"
if "last_upload_sig" not in st.session_state:
    st.session_state.last_upload_sig = None

ai_engine = get_ai_engine()
capture: CaptureSession = st.session_state.capture
allowlist: Allowlist = st.session_state.allowlist

pcap_dir = os.path.join(BASE_DIR, "pcap_samples")
if not os.path.exists(os.path.join(pcap_dir, "comprehensive_enterprise_trace.pcap")):
    TrafficGenerator.create_sample_pcaps(pcap_dir)


def load_selected_pcap(filename: str):
    """Streams a capture from pcap_samples/ using the limits currently set in the sidebar."""
    path = os.path.join(pcap_dir, filename)
    if os.path.exists(path):
        with st.spinner(f"Reading {filename} ..."):
            capture.load_pcap(path,
                              max_packets=int(st.session_state.get("max_packets", DEFAULT_MAX_PACKETS)),
                              display_window=int(st.session_state.get("display_window", DEFAULT_DISPLAY_WINDOW)))
        st.session_state.current_pcap = filename


def save_allowlist():
    try:
        allowlist.save(ALLOWLIST_PATH)
    except OSError as exc:
        st.sidebar.warning(f"Could not save allowlist to disk: {exc}")


# Pre-load the default capture once per session (not again after the user clears the buffer)
if not st.session_state.get("initial_loaded"):
    load_selected_pcap("comprehensive_enterprise_trace.pcap")
    st.session_state.initial_loaded = True

# ================= SIDEBAR =================
_, center, _ = st.sidebar.columns([1, 3, 1])
center.image("https://img.magnific.com/premium-vector/digital-security-network-shield_954948-21758.jpg?semt=ais_hybrid&w=740&q=80", width="stretch")
st.sidebar.title("Network AI Intelligence")
st.sidebar.caption("BCSE308P: Computer Networks Lab | VIT Vellore")
st.sidebar.markdown("**Supervisor:** Dr. S. Ebenezer Juliet")
st.sidebar.markdown("---")

nav_choice = st.sidebar.radio(
    "Navigation Modules:",
    [
        "Traffic Overview & Telemetry",
        "AI Threat Intelligence (Multi-Class & Anomaly)",
        "ARP Spoofing & Slowloris Detection",
        "Deep Packet Forensics & Protocols (Wireshark)",
        "AI Evaluation & Benchmarks (Rubrics: 10M)",
        "Traffic & Attack Simulation Lab",
        "Forensic Evidence & Firewall Rules"
    ]
)

st.sidebar.markdown("---")
st.sidebar.subheader("PCAP Data Source")
sample_files = sorted(f for f in os.listdir(pcap_dir) if f.lower().endswith((".pcap", ".pcapng")))
default_first = "comprehensive_enterprise_trace.pcap"
if default_first in sample_files:
    sample_files.remove(default_first)
    sample_files.insert(0, default_first)
if st.session_state.get("sample_choice") not in sample_files:
    st.session_state.sample_choice = st.session_state.current_pcap if st.session_state.current_pcap in sample_files else sample_files[0]
selected_pcap = st.sidebar.selectbox("Load Sample Capture:", sample_files, key="sample_choice")

with st.sidebar.expander("Capture limits (large files)"):
    st.number_input("Max packets to analyse", min_value=1_000, max_value=10_000_000, step=50_000,
                    value=DEFAULT_MAX_PACKETS, key="max_packets",
                    help="Files are streamed one packet at a time, so this is a time limit, not a memory limit. "
                         "Flows and attack detectors see every packet up to this number. Parsing runs at roughly 3,000 packets/s.")
    st.number_input("Packet table window", min_value=1_000, max_value=500_000, step=5_000,
                    value=DEFAULT_DISPLAY_WINDOW, key="display_window",
                    help="How many of the most recent packets stay in memory for the Packet Inspector and protocol charts.")
    st.caption("Applied the next time a capture is loaded.")

if st.sidebar.button("Load Selected PCAP", use_container_width=True):
    load_selected_pcap(selected_pcap)
    st.sidebar.success(f"Loaded: {selected_pcap}")

uploaded_file = st.sidebar.file_uploader("Upload External PCAP (.pcap/.pcapng):", type=["pcap", "pcapng"])
if uploaded_file is not None:
    sig = (uploaded_file.name, uploaded_file.size)
    if sig != st.session_state.last_upload_sig:      # Streamlit re-runs the script on every click; load each upload once
        safe_name = os.path.basename(uploaded_file.name)
        os.makedirs(os.path.join(pcap_dir, "uploads"), exist_ok=True)
        temp_rel = os.path.join("uploads", safe_name)
        with open(os.path.join(pcap_dir, temp_rel), "wb") as f:
            f.write(uploaded_file.getbuffer())
        load_selected_pcap(temp_rel)
        st.session_state.last_upload_sig = sig
        st.sidebar.success(f"Uploaded & loaded: {safe_name}")

st.sidebar.markdown("---")
st.sidebar.subheader("Detection Settings")
threshold = st.sidebar.slider("Incident confidence threshold (%)", 0, 100, int(DEFAULT_CONFIDENCE_THRESHOLD), 5,
                              help="An incident is raised only at or above this confidence (and with enough supporting flows). "
                                   "Anything below is listed as 'needs review' and does not count as an alert or generate firewall rules.")
ai_engine.guardrails_enabled = st.sidebar.checkbox(
    "Multicast / broadcast guardrail", value=True,
    help="Flows addressed to multicast or broadcast groups (mDNS, SSDP, DHCP, NetBIOS...) can never be reported as floods or scans.")

st.sidebar.subheader("Trusted Addresses (Allowlist)")
allow_mode = st.sidebar.selectbox("Match trusted addresses on", list(MATCH_MODES), index=0,
                                  help="'either' trusts traffic to or from an entry. Note that trusting a host also trusts attacks "
                                       "aimed at it. ARP spoofing is only silenced by a trusted MAC, never by an IP entry.")
new_entries = st.sidebar.text_input("Add IP, CIDR or MAC", placeholder="192.168.1.1  or  224.0.0.0/4",
                                    key="allow_input")
c_add, c_pre = st.sidebar.columns(2)
if c_add.button("Add", use_container_width=True) and new_entries.strip():
    added, rejected = allowlist.add_many(new_entries)
    if added:
        save_allowlist()
        st.sidebar.success("Trusted: " + ", ".join(added))
    if rejected:
        st.sidebar.error("Not a valid IP, CIDR or MAC: " + ", ".join(rejected))
if c_pre.button("+ Multicast", use_container_width=True, help="Trust " + ", ".join(PRESETS["Multicast & broadcast (IPv4/IPv6)"])):
    for e in PRESETS["Multicast & broadcast (IPv4/IPv6)"]:
        allowlist.add(e)
    save_allowlist()
if allowlist.entries:
    to_remove = st.sidebar.multiselect("Trusted now (select to remove):", allowlist.entries)
    if to_remove and st.sidebar.button("Remove selected", use_container_width=True):
        for e in to_remove:
            allowlist.remove(e)
        save_allowlist()
        st.rerun()
else:
    st.sidebar.caption("No trusted addresses.")

# ---- Run (or reuse) the analysis --------------------------------------------------------------
analysis_key = (capture.version, threshold, allowlist.signature, allow_mode, ai_engine.guardrails_enabled)
if st.session_state.get("_analysis_key") != analysis_key:
    with st.spinner("Analysing flows..."):
        st.session_state["_analysis"] = capture.analyze(ai_engine, allowlist, float(threshold), allow_mode)
    st.session_state["_analysis_key"] = analysis_key
analysis = st.session_state["_analysis"]

records = analysis["window_records"]
forensic_stats = analysis["forensic_stats"]
flow_predictions = analysis["flow_predictions"]
incidents = analysis["incidents"]
confirmed = analysis["confirmed"]
needs_review = analysis["needs_review"]
suppression = analysis["suppression"]
flows = flow_predictions

total_packets = capture.total_packets
total_bytes = capture.total_bytes
avg_rtt = forensic_stats.get("avg_rtt_ms", 0.0)
retransmissions = forensic_stats.get("retransmission_count", 0)

# Global Top KPI Banner
col1, col2, col3, col4, col5, col6 = st.columns(6)
with col1:
    st.metric("Total Packets", f"{total_packets:,}")
with col2:
    st.metric("Active Sessions", f"{len(flows):,}")
with col3:
    st.metric("Volume", f"{(total_bytes / 1024):.1f} KB")
with col4:
    st.metric("Avg RTT", f"{avg_rtt:.1f} ms")
with col5:
    st.metric("Retransmissions", f"{retransmissions}")
with col6:
    if confirmed:
        st.metric("Threat Status", f"ALERT ({len(confirmed)})", delta="-Incidents confirmed", delta_color="inverse")
    elif needs_review:
        st.metric("Threat Status", f"REVIEW ({len(needs_review)})", delta="Low-confidence findings", delta_color="off")
    else:
        st.metric("Threat Status", "SECURE", delta="Normal")

load_info = capture.sniffer.last_load
bits = [f"Source: **{capture.source_name or 'simulated traffic'}**"]
if load_info.get("truncated"):
    bits.append(f"⚠️ stopped at the {load_info['max_packets']:,}-packet limit (the file has more; raise it under *Capture limits*)")
if total_packets > len(records):
    bits.append(f"packet table and protocol charts cover the most recent {len(records):,} of {total_packets:,} packets; flows and detectors cover all of them")
if suppression["flows_guardrailed"] or suppression["flows_allowlisted"]:
    bits.append(f"{suppression['flows_guardrailed']} flow(s) judged benign by the multicast/L2 guardrail, {suppression['flows_allowlisted']} excluded by the allowlist")
st.caption("  |  ".join(bits))

flash = st.session_state.pop("flash", None)
if flash:
    getattr(st, flash[0])(flash[1])

st.markdown("---")

# ================= MODULE 1: TRAFFIC OVERVIEW & TELEMETRY =================
if nav_choice == "Traffic Overview & Telemetry":
    st.header("Real-Time Network Traffic Intelligence & Telemetry")
    st.markdown("""
    Visualizes macroscopic network conversation volume, protocol layer distribution, 
    and bandwidth inter-arrival patterns across active flows.
    """)

    col_a, col_b = st.columns([1, 1])

    with col_a:
        st.subheader("Protocol Distribution")
        proto_data = forensic_stats.get("protocol_counts", {})
        if proto_data:
            df_proto = pd.DataFrame(list(proto_data.items()), columns=["Protocol", "Packets"])
            fig_pie = px.pie(df_proto, values="Packets", names="Protocol", hole=0.45,
                             color_discrete_sequence=px.colors.qualitative.Plotly)
            fig_pie.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=320)
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("No packets loaded.")

    with col_b:
        st.subheader("Top Talkers (IP Volume)")
        top_talkers = forensic_stats.get("top_talkers", [])
        if top_talkers:
            df_talk = pd.DataFrame(top_talkers, columns=["IP Address", "Packet Count"])
            fig_bar = px.bar(df_talk, x="IP Address", y="Packet Count", color="Packet Count",
                             color_continuous_scale="Viridis")
            fig_bar.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=320)
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("No IP data.")

    st.subheader("Packet Arrival Timeline & Data Rate")
    if records:
        df_timeline = pd.DataFrame({"timestamp": [r["timestamp"] for r in records], "length": [r["length"] for r in records]})
        df_timeline["rel_time"] = df_timeline["timestamp"] - df_timeline["timestamp"].min()
        df_timeline["sec_bucket"] = df_timeline["rel_time"].round(0)
        grouped = df_timeline.groupby("sec_bucket").agg(
            packets=("length", "count"),
            bytes_sum=("length", "sum")
        ).reset_index()

        fig_time = go.Figure()
        fig_time.add_trace(go.Scatter(x=grouped["sec_bucket"], y=grouped["packets"], name="Packets / Sec",
                                      line=dict(color="#00ffff", width=2.5)))
        fig_time.add_trace(go.Bar(x=grouped["sec_bucket"], y=grouped["bytes_sum"] / 1024, name="Throughput (KB/s)",
                                  opacity=0.35, yaxis="y2", marker_color="#ff9900"))

        fig_time.update_layout(
            height=350,
            margin=dict(t=20, b=20, l=20, r=20),
            xaxis=dict(title="Relative Time (seconds)"),
            yaxis=dict(title="Packets / Second"),
            yaxis2=dict(title="Throughput (KB/s)", overlaying="y", side="right"),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        st.plotly_chart(fig_time, use_container_width=True)

# ================= MODULE 2: AI THREAT INTELLIGENCE =================
elif nav_choice == "AI Threat Intelligence (Multi-Class & Anomaly)":
    st.header("AI-Driven Threat Classification & Anomaly Detection")
    st.markdown("""
    Combines **Supervised Random Forest (Multi-Class Attack Classifier)** and 
    **Unsupervised Isolation Forest (Zero-Day Anomaly Detector)** to detect both known weaponized signatures
    and unknown deviations in statistical flow behavior. Flagged flows are grouped into **incidents**; an incident is
    only *raised* above the confidence threshold with enough supporting flows, otherwise it is listed as *needs review*.
    """)

    if not flow_predictions:
        st.warning("No flows currently captured. Please load a sample PCAP or generate traffic.")
    else:
        df_flows = pd.DataFrame(flow_predictions)

        st.subheader("Incidents")
        i1, i2, i3, i4 = st.columns(4)
        i1.metric("Confirmed", len(confirmed), help=f"Confidence at or above {threshold}% with enough evidence")
        i2.metric("Needs review", len(needs_review), help="Below the threshold or too little evidence; not counted as alerts")
        i3.metric("Benign by guardrail", suppression["flows_guardrailed"], help="Multicast / broadcast / ARP flows the models cannot judge")
        i4.metric("Excluded by allowlist", suppression["flows_allowlisted"])

        def incident_frame(items):
            return pd.DataFrame([{
                "ID": i["incident_id"], "Type": i["type"], "Status": i["status"].replace("_", " "), "Severity": i["severity"],
                "Confidence %": i["confidence"], "Source": i["src"], "Target": i["dst"], "Port": i["dst_port"] or None,
                "Flows": i["flows"], "Packets": i["packets"],
                "First seen": time.strftime("%H:%M:%S", time.localtime(i["first_seen"])) if i["first_seen"] else "",
                "Summary": i["summary"], "Why not raised": i["review_reason"],
            } for i in items])

        if confirmed:
            st.dataframe(incident_frame(confirmed).drop(columns=["Why not raised"]), use_container_width=True, hide_index=True)
        else:
            st.success(f"No incident reached {threshold}% confidence with enough supporting evidence.")
        if needs_review:
            with st.expander(f"Needs review ({len(needs_review)}): below the threshold, too little evidence, or anomaly-only"):
                st.dataframe(incident_frame(needs_review), use_container_width=True, hide_index=True)

        candidates = []
        for inc in incidents:
            for addr in (inc.get("src_ip"), inc["src"], inc["dst"]):
                if addr and normalize_entry(addr) and normalize_entry(addr) not in candidates:
                    candidates.append(normalize_entry(addr))
        if candidates:
            t1, t2 = st.columns([3, 1])
            trust_pick = t1.selectbox("Trust an address from these incidents (excludes it from future incidents):", candidates, key="trust_pick")
            t2.write("")
            t2.write("")
            if t2.button("Trust it", use_container_width=True):
                allowlist.add(trust_pick)
                save_allowlist()
                st.rerun()

        st.markdown("---")
        # Threat distribution metrics (flow level)
        pred_counts = df_flows["prediction"].value_counts()
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Normal Sessions", pred_counts.get("NORMAL", 0))
        c2.metric("SYN Flood Flows", pred_counts.get("SYN_FLOOD", 0))
        c3.metric("Port Scan Flows", pred_counts.get("PORT_SCAN", 0))
        c4.metric("DNS Tunneling / DDoS Flows", pred_counts.get("DNS_TUNNELING", 0) + pred_counts.get("UDP_DDOS", 0))

        st.subheader("Active Session Flows Intelligence Table")
        
        display_cols = [
            "flow_id", "protocol", "duration", "total_packets", "packet_rate",
            "syn_ratio", "payload_entropy_mean", "is_multicast_dst", "prediction", "confidence", "severity", "is_anomaly", "guardrail"
        ]
        
        # Format table (cap rows so very large captures stay responsive)
        MAX_FLOW_ROWS = 5000
        flow_view = df_flows[display_cols].head(MAX_FLOW_ROWS)
        if len(df_flows) > MAX_FLOW_ROWS:
            st.caption(f"Showing the first {MAX_FLOW_ROWS:,} of {len(df_flows):,} flows.")
        st.dataframe(
            flow_view.style.map(
                lambda val: "background-color: #ff4b4b; color: white;" if val in ("CRITICAL", "SYN_FLOOD", "UDP_DDOS")
                else ("background-color: #ffa500; color: black;" if val in ("HIGH", "PORT_SCAN", "DNS_TUNNELING")
                else ("background-color: #00cc66; color: white;" if val == "NORMAL" else "")),
                subset=["prediction", "severity"]
            ),
            use_container_width=True,
            height=350
        )

        col_x, col_y = st.columns(2)
        with col_x:
            st.subheader("Threat Classification Breakdown")
            fig_threat = px.bar(
                df_flows["prediction"].value_counts().reset_index(),
                x="prediction", y="count", color="prediction",
                color_discrete_map={
                    "NORMAL": "#00cc66",
                    "SYN_FLOOD": "#ff4b4b",
                    "PORT_SCAN": "#ffa500",
                    "DNS_TUNNELING": "#9933ff",
                    "UDP_DDOS": "#ff0066"
                }
            )
            fig_threat.update_layout(height=300, showlegend=False)
            st.plotly_chart(fig_threat, use_container_width=True)

        with col_y:
            st.subheader("Isolation Forest Anomaly Score Distribution")
            fig_iso = px.histogram(
                df_flows, x="anomaly_score", color="is_anomaly",
                nbins=30,
                color_discrete_map={True: "#ff4b4b", False: "#00cc66"},
                labels={"anomaly_score": "Isolation Forest Decision Value (<0 is Anomaly)"}
            )
            fig_iso.add_vline(x=0.0, line_dash="dash", line_color="red", annotation_text="Anomaly Boundary")
            fig_iso.update_layout(height=300)
            st.plotly_chart(fig_iso, use_container_width=True)

# ================= MODULE 2b: ARP SPOOFING & SLOWLORIS =================
elif nav_choice == "ARP Spoofing & Slowloris Detection":
    st.header("ARP Spoofing & Slowloris Detection")
    st.markdown("""
    Two rule-based detectors that read **packets**, not flow statistics, so they catch attacks the flow classifier cannot see.
    **ARP spoofing** looks for one IP claimed by several MAC addresses, unsolicited replies and forged sender MACs.
    **Slowloris** looks for many HTTP connections that never finish their request headers. Both are heuristics:
    each finding lists the evidence behind its score.
    """)
    det = capture.detectors
    special = [i for i in incidents if i["type"] in ("ARP_SPOOFING", "SLOWLORIS")]
    if special:
        for inc in special:
            badge = "🔴 CONFIRMED" if inc["status"] == "CONFIRMED" else "🟡 NEEDS REVIEW"
            with st.expander(f"{badge}  {inc['type'].replace('_', ' ')}  |  {inc['summary']}  |  confidence {inc['confidence']:g}%", expanded=(inc["status"] == "CONFIRMED")):
                for e in inc["evidence"]:
                    st.markdown(f"- {e}")
                if inc["review_reason"]:
                    st.caption(f"Not raised: {inc['review_reason']}")
    else:
        st.success("No ARP spoofing or Slowloris behaviour found in the loaded traffic.")

    ca, cb = st.columns(2)
    with ca:
        st.subheader("ARP IP → MAC bindings")
        arp_rows = det.arp.binding_table()
        if arp_rows:
            st.dataframe(pd.DataFrame(arp_rows), use_container_width=True, hide_index=True,
                         height=min(400, 38 + 35 * len(arp_rows)))
            st.caption("An IP with more than one MAC is a conflict. A single conflict can be legitimate (DHCP reassignment, failover); "
                       "repeated unsolicited replies are what raise the score.")
        else:
            st.info("No ARP traffic in this capture.")
    with cb:
        st.subheader("HTTP request completion per client")
        sl_rows = det.slowloris.server_summary()
        if sl_rows:
            st.dataframe(pd.DataFrame(sl_rows), use_container_width=True, hide_index=True,
                         height=min(400, 38 + 35 * len(sl_rows)))
            st.caption("Normal clients finish their request headers (0% unfinished). Slowloris clients hold many unfinished requests open.")
        else:
            st.info("No cleartext HTTP requests in this capture.")

# ================= MODULE 3: DEEP PACKET FORENSICS & PROTOCOLS =================
elif nav_choice == "Deep Packet Forensics & Protocols (Wireshark)":
    st.header("Real-Time Network Packet Forensics & Protocol Dissection")
    st.markdown("""
    **Adheres to Problem Statement IV:** In-depth forensic packet inspection matching Wireshark capabilities.
    Inspects TCP 3-way handshakes, sequence/ACK progression, window scaling, DNS queries, and comparative TCP vs UDP telemetry.
    """)

    # Filter Bar
    filter_query = st.text_input("Wireshark Display Filter (e.g., 'tcp', 'udp', 'dns', 'http', 'icmp', 'syn', 'rst', 'ip.addr==192.168.1.10', 'port==80'):", "")
    filtered_packets = ForensicsAnalyzer.apply_filter(records, filter_query)

    st.caption(f"Showing **{len(filtered_packets)}** of **{len(records)}** total packets")

    # Packet Table
    MAX_PKT_ROWS = 5000
    if len(filtered_packets) > MAX_PKT_ROWS:
        st.caption(f"Table and inspector show the first {MAX_PKT_ROWS:,} matching packets; narrow the filter to see others.")
        filtered_packets = filtered_packets[:MAX_PKT_ROWS]
    df_pkts = pd.DataFrame(filtered_packets)
    if not df_pkts.empty:
        df_display = df_pkts[["timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "length", "info"]].copy()
        df_display["timestamp"] = df_display["timestamp"].apply(lambda t: time.strftime("%H:%M:%S", time.localtime(t)) + f".{int((t%1)*1000):03d}")
        
        st.dataframe(df_display, use_container_width=True, height=280)

        # Single Packet Inspection
        st.subheader("Deep Packet Inspector (Frame / Hex / Payload View)")
        pkt_idx = st.number_input("Select Packet Row Index to Dissect:", min_value=0, max_value=len(filtered_packets)-1, value=0, step=1)
        if pkt_idx < len(filtered_packets):
            sel_pkt = filtered_packets[pkt_idx]
            c1, c2 = st.columns([1, 1])
            with c1:
                st.markdown(f"**Protocol:** `{sel_pkt.get('protocol')}`")
                st.markdown(f"**Source:** `{sel_pkt.get('src_ip')}:{sel_pkt.get('src_port')}`")
                st.markdown(f"**Destination:** `{sel_pkt.get('dst_ip')}:{sel_pkt.get('dst_port')}`")
                st.markdown(f"**Length:** `{sel_pkt.get('length')} bytes` | **TTL:** `{sel_pkt.get('ttl', 'N/A')}`")
                st.markdown(f"**TCP Flags:** `{sel_pkt.get('tcp_flags_str', 'N/A')}`")
                st.markdown(f"**Seq:** `{sel_pkt.get('seq_num')}` | **Ack:** `{sel_pkt.get('ack_num')}` | **Window:** `{sel_pkt.get('window_size')}`")
            with c2:
                payload = sel_pkt.get("payload_bytes", b"")
                st.markdown("**Payload Preview (ASCII & Hex):**")
                if payload:
                    text_prev = payload[:256].decode("utf-8", errors="replace")
                    hex_prev = payload[:64].hex(" ")
                    st.code(f"ASCII:\n{text_prev}\n\nHEX (First 64 Bytes):\n{hex_prev}", language="text")
                else:
                    st.info("No application payload attached (pure header).")

    # TCP vs UDP Comparative Analysis
    st.subheader("Comparative Protocol Analysis: TCP vs UDP")
    t_v_u = forensic_stats.get("tcp_vs_udp", {})
    col_u1, col_u2, col_u3, col_u4 = st.columns(4)
    col_u1.metric("TCP Packets", f"{t_v_u.get('tcp_packet_count', 0):,}")
    col_u2.metric("UDP Packets", f"{t_v_u.get('udp_packet_count', 0):,}")
    col_u3.metric("TCP Avg Size", f"{t_v_u.get('tcp_avg_packet_size', 0)} B")
    col_u4.metric("UDP Avg Size", f"{t_v_u.get('udp_avg_packet_size', 0)} B")

    st.subheader("TCP 3-Way Handshake & Connection State Tracker")
    sessions = forensic_stats.get("sessions", [])
    if sessions:
        st.dataframe(pd.DataFrame(sessions), use_container_width=True, height=200)
    else:
        st.info("No active TCP handshake sessions recorded.")

# ================= MODULE 4: AI EVALUATION & BENCHMARKS =================
elif nav_choice == "AI Evaluation & Benchmarks (Rubrics: 10M)":
    st.header("Multi-Model AI Evaluation Lab (Bloom's Taxonomy: Evaluate [10 Marks])")
    st.markdown("""
    **Rigorous Evaluation & Comparative Analysis of Machine Learning Architectures:**
    Compares **Random Forest (Ensemble)**, **Decision Tree (Symbolic Rule-Based)**, 
    **Logistic Regression (Linear Discriminant)**, and **Isolation Forest (Unsupervised Tree Anomaly Detector)**.
    Evaluates Precision, Recall, F1-Score, ROC-AUC, Training Time, and Inference Latency.
    """)

    benchmarks = ai_engine.benchmark_results
    if benchmarks:
        df_bench = pd.DataFrame.from_dict(benchmarks, orient="index").reset_index().rename(columns={"index": "Model Architecture"})
        
        st.subheader("Model Benchmark Performance Matrix")
        st.dataframe(
            df_bench[["Model Architecture", "accuracy", "precision", "recall", "f1_score", "inference_latency_ms", "training_time_sec"]].rename(
                columns={
                    "accuracy": "Accuracy (%)",
                    "precision": "Precision (%)",
                    "recall": "Recall (%)",
                    "f1_score": "F1-Score (%)",
                    "inference_latency_ms": "Latency (ms/pkt)",
                    "training_time_sec": "Train Time (s)"
                }
            ).style.highlight_max(subset=["Accuracy (%)", "Precision (%)", "Recall (%)", "F1-Score (%)"], color="#1f77b4")
            .highlight_min(subset=["Latency (ms/pkt)"], color="#2ca02c"),
            use_container_width=True
        )

        col_b1, col_b2 = st.columns(2)
        with col_b1:
            st.subheader("F1-Score vs Inference Latency Tradeoff")
            fig_tradeoff = px.scatter(
                df_bench, x="inference_latency_ms", y="f1_score", text="Model Architecture",
                color="Model Architecture", size=[25, 20, 20, 22],
                labels={"inference_latency_ms": "Inference Latency (ms / packet)", "f1_score": "F1-Score (%)"}
            )
            fig_tradeoff.update_traces(textposition='top center')
            fig_tradeoff.update_layout(height=340, showlegend=False)
            st.plotly_chart(fig_tradeoff, use_container_width=True)

        with col_b2:
            st.subheader("Top Discriminant Feature Importance (Random Forest)")
            feat_imp = ai_engine.get_feature_importances()
            top_feats = list(feat_imp.items())[:8]
            df_feats = pd.DataFrame(top_feats, columns=["Network Feature", "Importance (%)"])
            fig_feats = px.bar(df_feats, x="Importance (%)", y="Network Feature", orientation="h", color="Importance (%)", color_continuous_scale="Teal")
            fig_feats.update_layout(height=340, yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig_feats, use_container_width=True)

        st.subheader("Confusion Matrix (Random Forest Multi-Class)")
        rf_cm = benchmarks.get("Random Forest", {}).get("confusion_matrix", [])
        if rf_cm:
            fig_cm = px.imshow(
                rf_cm,
                x=LABELS,
                y=LABELS,
                color_continuous_scale="Blues",
                text_auto=True,
                labels=dict(x="Predicted Class", y="Actual Ground Truth", color="Sample Count")
            )
            fig_cm.update_layout(height=380)
            st.plotly_chart(fig_cm, use_container_width=True)

        hold = ai_engine.holdout_check
        if hold:
            st.subheader("Hold-out check on unseen simulated captures (flow level)")
            st.caption("Generator output from seeds never used in training, per scenario. Benign scenarios should raise no alerts; "
                       "attack scenarios should be detected. The multicast guardrail column shows what the rule adds on top of the model.")
            rows = []
            for scn, e in hold.items():
                if not isinstance(e, dict):
                    continue
                benign = e["expected"] == "NORMAL"
                rows.append({
                    "Scenario": scn, "Flows": e["flows"], "Expected": "benign" if benign else e["expected"],
                    "Alerts, model only": e.get("false_alarms_model_only") if benign else f"{e.get('detected_model_only')} detected",
                    "Alerts, with guardrail": e.get("false_alarms_with_guardrail") if benign else f"{e.get('detected_with_guardrail')} detected",
                })
            st.dataframe(pd.DataFrame(rows).astype(str), use_container_width=True, hide_index=True)
            st.warning(hold.get("note", "") + " Near-perfect numbers here show the pipeline is consistent with its own generator, "
                       "not that it will be this accurate on a real network. Use tools/evaluate_captures.py on real recordings.")

# ================= MODULE 5: TRAFFIC & ATTACK SIMULATION LAB =================
elif nav_choice == "Traffic & Attack Simulation Lab":
    st.header("Live Traffic & Cyber Threat Simulation Console")
    st.markdown("""
    Inject real network packet bursts directly into the live ingestion buffer to test
    how the forensics and AI engines detect traffic anomalies in real time.
    Everything injected is added to what is already loaded; use *Clear Buffer* for a clean slate.
    """)

    def inject(pkts, label, kind, msg):
        capture.inject(pkts, label=label)
        st.session_state.flash = (kind, msg)
        st.rerun()      # re-run so the KPI banner and analysis include the new packets

    col_s1, col_s2, col_s3 = st.columns(3)

    with col_s1:
        st.markdown("### 🟢 Normal Traffic")
        st.write("Baseline web requests, DNS lookups, pings and LAN chatter (mDNS, SSDP, DHCP, NetBIOS).")
        if st.button("Generate Normal Traffic (50 events)", use_container_width=True):
            inject(TrafficGenerator.generate_normal_traffic(count=50), "simulated traffic", "success", "Injected normal traffic.")

        st.markdown("### 📡 Multicast / Broadcast Chatter")
        st.write("mDNS, SSDP, LLMNR, NetBIOS, DHCP, IGMP. Benign, but looks like a flood to a naive detector.")
        if st.button("Generate Multicast Chatter (60 events)", use_container_width=True):
            inject(TrafficGenerator.generate_multicast_chatter(count=60, storm_probability=0.1), "simulated traffic", "success", "Injected multicast chatter. It should raise no incident.")

        st.markdown("### 🔴 TCP SYN Flood")
        st.write("Simulates high-velocity SYN flood with spoofed sources to exhaust target TCP backlogs.")
        if st.button("Launch SYN Flood (80 pkts)", use_container_width=True):
            inject(TrafficGenerator.generate_syn_flood(count=80), "simulated traffic", "error", "Injected 80 SYN Flood Packets!")

    with col_s2:
        st.markdown("### 🟠 Stealth Port Scan")
        st.write("Simulates reconnaissance port sweep targeting standard enterprise services.")
        if st.button("Launch Port Sweep (40 pkts)", use_container_width=True):
            inject(TrafficGenerator.generate_port_scan(), "simulated traffic", "warning", "Injected Reconnaissance Port Scan!")

        st.markdown("### 🟣 DNS Data Exfiltration")
        st.write("Simulates covert tunneling using high-entropy base32 encoded subdomains.")
        if st.button("Launch DNS Tunnel (40 pkts)", use_container_width=True):
            inject(TrafficGenerator.generate_dns_tunneling(count=40), "simulated traffic", "info", "Injected 40 DNS Tunneling Packets!")

        st.markdown("### 🕷️ ARP Spoofing (MITM)")
        st.write("Attacker sends forged ARP replies claiming the gateway and a victim's IP.")
        if st.button("Launch ARP Spoofing (40 frames)", use_container_width=True):
            inject(TrafficGenerator.generate_benign_arp(count=6) + TrafficGenerator.generate_arp_spoofing(count=20), "simulated traffic", "error", "Injected ARP spoofing. See the ARP / Slowloris page.")

    with col_s3:
        st.markdown("### 💥 Volumetric UDP DDoS")
        st.write("Floods network with high-byte-rate UDP packets to overwhelm link bandwidth.")
        if st.button("Launch UDP DDoS (60 pkts)", use_container_width=True):
            inject(TrafficGenerator.generate_udp_ddos(count=60), "simulated traffic", "error", "Injected 60 UDP DDoS Packets!")

        st.markdown("### 🐌 Slowloris")
        st.write("Many HTTP connections held open with unfinished request headers.")
        if st.button("Launch Slowloris (40 connections)", use_container_width=True):
            inject(TrafficGenerator.generate_slowloris(connections=40, duration=45.0), "simulated traffic", "error", "Injected Slowloris. See the ARP / Slowloris page.")

        st.markdown("### 🧹 Buffer Controls")
        if st.button("Clear Buffer & Reset Flows", use_container_width=True):
            capture.clear()
            st.session_state.flash = ("success", "Packet and flow buffers reset.")
            st.rerun()

# ================= MODULE 6: FORENSIC EVIDENCE & MITIGATION =================
elif nav_choice == "Forensic Evidence & Firewall Rules":
    st.header("Automated Forensic Evidence & Defensive Mitigation Synthesis")
    st.markdown("""
    Translates **confirmed incidents** into actionable network defense rules (Linux `iptables`/`ebtables`, Windows `netsh`,
    Cisco IOS) and exports the evidence as a PDF, Markdown or CSV report. Incidents below the confidence threshold are listed
    for review but get no rules.
    """)

    if not confirmed:
        st.success("✅ No incident met the confidence threshold. Nothing to mitigate.")
        if needs_review:
            st.info(f"{len(needs_review)} lower-confidence finding(s) are waiting under *needs review* on the Threat Intelligence page.")
    else:
        st.warning(f"⚠️ **{len(confirmed)} confirmed incident(s).** Review the suggested rules before applying them.")

        for i, inc in enumerate(confirmed):
            tgt = f"{inc['dst']}:{inc['dst_port']}" if inc["dst_port"] else inc["dst"]
            with st.expander(f"{inc['incident_id']}: {inc['type']} | {inc['src']} -> {tgt} | {inc['confidence']:g}%", expanded=(i == 0)):
                c1, c2 = st.columns([1, 1])
                with c1:
                    st.markdown(f"**Classification:** `{inc['type']}`")
                    st.markdown(f"**Confidence:** `{inc['confidence']:g}%`")
                    st.markdown(f"**Severity:** `{inc['severity']}`")
                    st.markdown(f"**Flows / packets:** `{inc['flows']}` / `{inc['packets']}`")
                    st.markdown(f"**Summary:** {inc['summary']}")
                    for e in inc["evidence"]:
                        st.markdown(f"- {e}")
                with c2:
                    rules = ForensicsAnalyzer.generate_incident_mitigation(inc)
                    st.markdown("**Linux (`iptables` / `ebtables` / `sysctl`):**")
                    st.code(rules["iptables"], language="bash")
                    st.markdown("**Windows Firewall (`netsh`):**")
                    st.code(rules["windows_netsh"], language="powershell")
                    st.markdown("**Cisco IOS:**")
                    st.code(rules["cisco_acl"], language="text")

    if needs_review:
        with st.expander(f"Needs review ({len(needs_review)}): listed in the report, no rules generated"):
            for inc in needs_review:
                conf = f"{inc['confidence']:g}%" if inc["confidence"] is not None else "no confidence"
                st.markdown(f"- **{inc['incident_id']} {inc['type']}** ({conf}): {inc['summary']}. _{inc['review_reason']}_")

    st.subheader("Export Forensic Evidence")
    report = build_report(capture, analysis, {
        "threshold": float(threshold), "allowlist": allowlist.entries, "allowlist_mode": allow_mode,
        "max_packets": int(st.session_state.get("max_packets", DEFAULT_MAX_PACKETS)),
    })
    stamp = int(time.time())
    d1, d2, d3, d4 = st.columns(4)
    try:
        d1.download_button("📄 Evidence report (PDF)", data=render_pdf(report), file_name=f"network_evidence_{stamp}.pdf", mime="application/pdf")
    except Exception as exc:     # reportlab missing or a rendering problem should not break the page
        d1.error(f"PDF export unavailable: {exc}")
    d2.download_button("📝 Evidence report (Markdown)", data=render_markdown(report).encode("utf-8"),
                       file_name=f"network_evidence_{stamp}.md", mime="text/markdown")
    inc_rows = pd.DataFrame([{k: v for k, v in i.items() if k not in ("example_flow", "evidence")} | {"evidence": " | ".join(i["evidence"])} for i in incidents])
    d3.download_button("📥 Incidents (CSV)", data=inc_rows.to_csv(index=False).encode("utf-8"),
                       file_name=f"network_incidents_{stamp}.csv", mime="text/csv", disabled=inc_rows.empty)
    flagged_flows = pd.DataFrame([f for f in flow_predictions if f.get("mitigation_required")])
    d4.download_button("📥 Flagged flows (CSV)", data=flagged_flows.to_csv(index=False).encode("utf-8"),
                       file_name=f"network_flagged_flows_{stamp}.csv", mime="text/csv", disabled=flagged_flows.empty)

st.markdown("---")
st.caption("AI-Driven Network Traffic Intelligence Dashboard | BCSE308P Computer Networks Lab | VIT Vellore (2026-2027)")
