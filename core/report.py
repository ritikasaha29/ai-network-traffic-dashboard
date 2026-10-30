"""
Forensic evidence report: PDF and Markdown renderers.

Both formats are generated from the same report dictionary (`build_report`) so they always agree.
Anything that came out of a capture (IP addresses, DNS names, MACs) is untrusted text: it is escaped
before it reaches the PDF engine's mini-markup.
"""

import io
import time
from typing import Dict, Any, List, Optional
from xml.sax.saxutils import escape

from core.forensics import ForensicsAnalyzer

LIMITATIONS = [
    "Training data is simulated. The classifiers learn from flows produced by this project's own traffic generator, "
    "so near-perfect scores on simulated captures show the pipeline works end-to-end, not that it will be accurate on a "
    "real network. Measure false positives on your own captures (tools/evaluate_captures.py) before trusting alerts.",
    "Per-flow verdicts are noisy by nature: a flood of spoofed sources is thousands of one-packet flows. Findings are "
    "therefore grouped into incidents and only raised above a confidence threshold with enough supporting flows; the rest "
    "are listed as 'needs review'.",
    "The multicast/broadcast guardrail treats any x.x.x.255 address as broadcast without knowing the subnet mask, and "
    "never reports floods addressed to a multicast or broadcast group. A real attack aimed at such an address is missed by design.",
    "The Isolation Forest zero-day detector has weak recall on the generator's attacks (see the benchmark page); do not rely on it alone.",
    "ARP spoofing and Slowloris detection are heuristics. A single IP/MAC conflict is also caused by DHCP reassignment or "
    "failover; Slowloris detection covers cleartext HTTP only and needs a capture long enough to show unfinished requests.",
    "Large captures are analysed up to the configured packet limit; the packet table shows only the most recent packets "
    "(display window). Parsing speed is bounded by scapy (roughly 3,000 packets per second).",
    "Encrypted traffic is classified from timing and size statistics only; payload-based indicators (entropy, HTTP method) "
    "do not apply to it.",
]


def _ts(t: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(t)) if t else "-"


def build_report(session, analysis: Dict[str, Any], params: Dict[str, Any], model_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Collects everything the report needs. `params` = threshold, allowlist entries/mode, packet limits."""
    window = analysis["window_records"]
    ts = [r["timestamp"] for r in window] or [0.0]
    incidents = []
    for inc in analysis["incidents"]:
        item = {k: inc.get(k) for k in ("incident_id", "type", "status", "review_reason", "severity", "confidence", "src", "dst",
                                        "dst_port", "flows", "packets", "first_seen", "last_seen", "summary", "evidence", "source")}
        try:
            item["rules"] = ForensicsAnalyzer.generate_incident_mitigation(inc) if inc["status"] == "CONFIRMED" else None
        except Exception:      # a report must still render if a rule template fails on odd input
            item["rules"] = None
        incidents.append(item)
    return {
        "generated": time.time(),
        "capture": {
            "name": session.source_name or "(simulated traffic)",
            "packets_analysed": session.total_packets,
            "bytes": session.total_bytes,
            "flows": len(analysis["flow_predictions"]),
            "start": min(ts), "end": max(ts),
            "load": dict(session.sniffer.last_load),
        },
        "parameters": params,
        "model": model_info or {},
        "incidents": incidents,
        "suppression": analysis["suppression"],
        "limitations": LIMITATIONS,
    }


# ------------------------------------------------------------------ Markdown
def _md_cell(text: Any) -> str:
    return str(text if text is not None else "-").replace("|", "\\|").replace("\n", " ")


def render_markdown(report: Dict[str, Any]) -> str:
    cap, par, sup = report["capture"], report["parameters"], report["suppression"]
    confirmed = [i for i in report["incidents"] if i["status"] == "CONFIRMED"]
    review = [i for i in report["incidents"] if i["status"] != "CONFIRMED"]
    L = ["# Network Forensic Evidence Report", "",
         f"Generated: {_ts(report['generated'])}", "",
         "## Capture", "",
         f"- Source: `{cap['name']}`",
         f"- Packets analysed: {cap['packets_analysed']:,} ({cap['bytes'] / 1024:.1f} KB), {cap['flows']:,} flows",
         f"- Capture window: {_ts(cap['start'])} to {_ts(cap['end'])}"]
    if cap["load"].get("truncated"):
        L.append(f"- **Truncated:** stopped at the {cap['load']['max_packets']:,}-packet limit; the file has more packets.")
    L += ["", "## Settings", "",
          f"- Confidence threshold: {par['threshold']:g}% (below this an incident is 'needs review')",
          f"- Allowlist ({par.get('allowlist_mode', 'either')}): " + (", ".join(f"`{e}`" for e in par.get("allowlist", [])) or "none"),
          "", "## Summary", "",
          f"- **{len(confirmed)}** confirmed incident(s), **{len(review)}** needing review",
          f"- Flows judged benign by the multicast/broadcast/L2 guardrail: {sup.get('flows_guardrailed', 0)}",
          f"- Flows excluded by the allowlist: {sup.get('flows_allowlisted', 0)}"
          + (f", detector findings excluded: {sup.get('findings_allowlisted', 0)}" if sup.get("findings_allowlisted") else ""), ""]

    L += ["## Confirmed incidents", ""]
    if confirmed:
        L += ["| ID | Type | Severity | Confidence | Source | Target | Flows | Packets | First seen |", "|---|---|---|---|---|---|---|---|---|"]
        for i in confirmed:
            L.append("| " + " | ".join(_md_cell(x) for x in (
                i["incident_id"], i["type"], i["severity"], f"{i['confidence']:g}%" if i["confidence"] is not None else "-",
                i["src"], f"{i['dst']}:{i['dst_port']}" if i["dst_port"] else i["dst"], i["flows"], i["packets"], _ts(i["first_seen"]))) + " |")
        for i in confirmed:
            L += ["", f"### {i['incident_id']} - {i['type']}", "", i["summary"], "", "Evidence:"]
            L += [f"- {e}" for e in i["evidence"]]
            if i.get("rules"):
                L += ["", "Suggested mitigation (review before applying):", "", "Linux:", "", "```bash", i["rules"]["iptables"], "```"]
                L += ["", "Windows:", "", "```text", i["rules"]["windows_netsh"], "```", "", "Cisco IOS:", "", "```text", i["rules"]["cisco_acl"], "```"]
    else:
        L.append("None. No incident met the confidence threshold with enough supporting evidence.")

    L += ["", "## Needs review", ""]
    if review:
        L += ["| ID | Type | Confidence | Source | Target | Flows | Why not raised |", "|---|---|---|---|---|---|---|"]
        for i in review:
            L.append("| " + " | ".join(_md_cell(x) for x in (
                i["incident_id"], i["type"], f"{i['confidence']:g}%" if i["confidence"] is not None else "-", i["src"],
                f"{i['dst']}:{i['dst_port']}" if i["dst_port"] else i["dst"], i["flows"], i["review_reason"])) + " |")
    else:
        L.append("None.")

    L += ["", "## Limitations", ""] + [f"{n}. {t}" for n, t in enumerate(report["limitations"], 1)] + [""]
    return "\n".join(L)


# ------------------------------------------------------------------ PDF
def render_pdf(report: Dict[str, Any]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted, KeepTogether, PageBreak)

    cap, par, sup = report["capture"], report["parameters"], report["suppression"]
    confirmed = [i for i in report["incidents"] if i["status"] == "CONFIRMED"]
    review = [i for i in report["incidents"] if i["status"] != "CONFIRMED"]

    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["BodyText"], fontName="Helvetica", fontSize=9, leading=12.5, alignment=TA_LEFT)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10.5)
    cell = ParagraphStyle("cell", parent=body, fontSize=7.8, leading=9.8)
    cell_b = ParagraphStyle("cellb", parent=cell, fontName="Helvetica-Bold", textColor=colors.white)
    h1 = ParagraphStyle("h1", parent=ss["Title"], fontName="Helvetica-Bold", fontSize=20, leading=24, alignment=TA_LEFT, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold", fontSize=12.5, leading=16, spaceBefore=14, spaceAfter=6,
                        textColor=colors.HexColor("#14325c"))
    h3 = ParagraphStyle("h3", parent=ss["Heading3"], fontName="Helvetica-Bold", fontSize=10, leading=13, spaceBefore=10, spaceAfter=3)
    mono = ParagraphStyle("mono", fontName="Courier", fontSize=7.2, leading=9, backColor=colors.HexColor("#f2f4f7"),
                          borderPadding=(4, 4, 4, 4), spaceBefore=2, spaceAfter=4)

    def P(text, style=body):
        return Paragraph(escape(str(text)), style)

    sev_color = {"CRITICAL": "#b3261e", "HIGH": "#c25b00", "MEDIUM": "#8a6d00", "LOW": "#2e7d32"}

    def table(rows, widths, header=True, zebra=True):
        t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
        st = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
              ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
              ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#d0d5dd"))]
        if header:
            st.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14325c")))
        if zebra:
            for r in range(1 if header else 0, len(rows)):
                if r % 2 == 0:
                    st.append(("BACKGROUND", (0, r), (-1, r), colors.HexColor("#f6f8fb")))
        t.setStyle(TableStyle(st))
        return t

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#667085"))
        canvas.drawString(18 * mm, 10 * mm, f"Network Forensic Evidence Report  |  {cap['name']}")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=18 * mm,
                            title="Network Forensic Evidence Report", author="AI Network Traffic Intelligence Dashboard")
    W = A4[0] - 36 * mm
    S: List[Any] = [P("Network Forensic Evidence Report", h1), P(f"Generated {_ts(report['generated'])}", small), Spacer(1, 6)]

    # headline numbers
    headline = [[P(f"{len(confirmed)}", ParagraphStyle("n1", parent=h1, fontSize=22, textColor=colors.HexColor("#b3261e" if confirmed else "#2e7d32"))),
                 P(f"{len(review)}", ParagraphStyle("n2", parent=h1, fontSize=22, textColor=colors.HexColor("#8a6d00"))),
                 P(f"{cap['packets_analysed']:,}", ParagraphStyle("n3", parent=h1, fontSize=22)),
                 P(f"{cap['flows']:,}", ParagraphStyle("n4", parent=h1, fontSize=22))],
                [P("confirmed incidents", small), P("need review", small), P("packets analysed", small), P("flows", small)]]
    ht = Table(headline, colWidths=[W / 4] * 4)
    ht.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d5dd")), ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e4e7ec")),
                            ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    S += [ht]

    S.append(P("Capture and settings", h2))
    rows = [[P("Capture", cell), P(cap["name"], cell)],
            [P("Window", cell), P(f"{_ts(cap['start'])}  to  {_ts(cap['end'])}", cell)],
            [P("Volume", cell), P(f"{cap['packets_analysed']:,} packets, {cap['bytes'] / 1024:.1f} KB", cell)],
            [P("Confidence threshold", cell), P(f"{par['threshold']:g}%  (below this, an incident is listed as 'needs review')", cell)],
            [P("Allowlist", cell), P(f"{', '.join(par.get('allowlist', [])) or 'none'}  (match: {par.get('allowlist_mode', 'either')})", cell)],
            [P("Not reported", cell), P(f"{sup.get('flows_guardrailed', 0)} flow(s) judged benign by the multicast/broadcast/L2 guardrail; "
                                        f"{sup.get('flows_allowlisted', 0)} flow(s) excluded by the allowlist", cell)]]
    if cap["load"].get("truncated"):
        rows.insert(3, [P("Truncated", cell), P(f"Stopped at the {cap['load']['max_packets']:,}-packet limit; the file contains more packets.", cell)])
    S.append(table(rows, [38 * mm, W - 38 * mm], header=False))

    S.append(P("Confirmed incidents", h2))
    if confirmed:
        hdr = [P(x, cell_b) for x in ("ID", "Type", "Severity", "Conf.", "Source", "Target", "Flows / pkts")]
        rows = [hdr]
        for i in confirmed:
            tgt = f"{i['dst']}:{i['dst_port']}" if i["dst_port"] else i["dst"]
            sev = Paragraph(f'<font color="{sev_color.get(i["severity"], "#000000")}"><b>{escape(str(i["severity"]))}</b></font>', cell)
            rows.append([P(i["incident_id"], cell), P(i["type"], cell), sev,
                         P(f"{i['confidence']:g}%" if i["confidence"] is not None else "-", cell), P(i["src"], cell), P(tgt, cell),
                         P(f"{i['flows']} / {i['packets']}", cell)])
        S.append(table(rows, [16 * mm, 30 * mm, 18 * mm, 13 * mm, 34 * mm, 38 * mm, W - 149 * mm]))
        for i in confirmed:
            block = [P(f"{i['incident_id']}  -  {i['type'].replace('_', ' ')}", h3), P(i["summary"], body), Spacer(1, 2)]
            for e in i["evidence"][:8]:
                block.append(P("- " + e, small))
            block.append(P(f"First seen {_ts(i['first_seen'])}   |   last seen {_ts(i['last_seen'])}", small))
            if i.get("rules"):
                block.append(Spacer(1, 3))
                block.append(P("Suggested mitigation (review before applying)", small))
                for label, key in (("Linux (iptables / sysctl / ebtables)", "iptables"), ("Windows", "windows_netsh"), ("Cisco IOS", "cisco_acl")):
                    block.append(KeepTogether([P(label, ParagraphStyle("lbl", parent=small, fontName="Helvetica-Bold")),
                                               Preformatted(i["rules"][key], mono)]))
            S.append(KeepTogether(block[:4]))
            S.extend(block[4:])
    else:
        S.append(P("None. No incident met the confidence threshold with enough supporting evidence.", body))

    S.append(P("Needs review", h2))
    if review:
        rows = [[P(x, cell_b) for x in ("ID", "Type", "Conf.", "Source", "Target", "Flows", "Why it was not raised")]]
        for i in review:
            tgt = f"{i['dst']}:{i['dst_port']}" if i["dst_port"] else i["dst"]
            rows.append([P(i["incident_id"], cell), P(i["type"], cell), P(f"{i['confidence']:g}%" if i["confidence"] is not None else "-", cell),
                         P(i["src"], cell), P(tgt, cell), P(str(i["flows"]), cell), P(i["review_reason"], cell)])
        S.append(table(rows, [16 * mm, 28 * mm, 13 * mm, 30 * mm, 32 * mm, 11 * mm, W - 130 * mm]))
    else:
        S.append(P("None.", body))

    S.append(P("Limitations", h2))
    for n, t in enumerate(report["limitations"], 1):
        S.append(P(f"{n}.  {t}", small))
        S.append(Spacer(1, 2))

    doc.build(S, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
