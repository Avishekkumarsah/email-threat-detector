"""
report.py
---------
Builds an auto-adjusting, professional multi-page PDF forensic report for a completed scan
using ReportLab. Wrap all table text in Paragraph elements so content auto-wraps cleanly
without text clipping or page overflow.
"""

import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

import config
from modules import database

# Define styles
STYLES = getSampleStyleSheet()

STYLE_TITLE = ParagraphStyle(
    "DocTitle",
    parent=STYLES["Title"],
    fontName="Helvetica-Bold",
    fontSize=22,
    leading=26,
    textColor=colors.HexColor("#0f172a"),
    alignment=0,
)

STYLE_H1 = ParagraphStyle(
    "DocH1",
    parent=STYLES["Heading1"],
    fontName="Helvetica-Bold",
    fontSize=14,
    leading=18,
    textColor=colors.HexColor("#1e293b"),
    spaceBefore=12,
    spaceAfter=8,
)

STYLE_H2 = ParagraphStyle(
    "DocH2",
    parent=STYLES["Heading2"],
    fontName="Helvetica-Bold",
    fontSize=12,
    leading=16,
    textColor=colors.HexColor("#334155"),
    spaceBefore=8,
    spaceAfter=6,
)

STYLE_CELL = ParagraphStyle(
    "TableCell",
    fontName="Helvetica",
    fontSize=9,
    leading=12,
    textColor=colors.HexColor("#334155"),
)

STYLE_CELL_BOLD = ParagraphStyle(
    "TableCellBold",
    fontName="Helvetica-Bold",
    fontSize=9,
    leading=12,
    textColor=colors.HexColor("#0f172a"),
)

STYLE_CELL_HEADER = ParagraphStyle(
    "TableCellHeader",
    fontName="Helvetica-Bold",
    fontSize=9,
    leading=12,
    textColor=colors.white,
)

STYLE_CELL_MONO = ParagraphStyle(
    "TableCellMono",
    fontName="Courier",
    fontSize=8,
    leading=10,
    textColor=colors.HexColor("#0f172a"),
)

STYLE_SMALL_GREY = ParagraphStyle(
    "SmallGrey",
    fontName="Helvetica",
    fontSize=8,
    leading=11,
    textColor=colors.HexColor("#64748b"),
)

VERDICT_COLORS = {
    "Safe": colors.HexColor("#16a34a"),
    "Suspicious": colors.HexColor("#d97706"),
    "Dangerous": colors.HexColor("#dc2626"),
}


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(1.5 * cm, 1 * cm, "🛡️ Email Threat Detector — Official Forensic Analysis Report")
    canvas.drawRightString(19.5 * cm, 1 * cm, f"Page {doc.page}")
    canvas.setStrokeColor(colors.HexColor("#cbd5e1"))
    canvas.setLineWidth(0.5)
    canvas.line(1.5 * cm, 1.3 * cm, 19.5 * cm, 1.3 * cm)
    canvas.restoreState()


def _make_paragraph_table(data_matrix, col_widths, is_header=True):
    """
    Wraps every string entry in data_matrix inside a Paragraph to guarantee 
    automatic text wrapping and zero overflow across PDF margins.
    """
    formatted_table = []
    for row_idx, row in enumerate(data_matrix):
        formatted_row = []
        for col_idx, cell in enumerate(row):
            if isinstance(cell, Paragraph):
                formatted_row.append(cell)
            elif row_idx == 0 and is_header:
                formatted_row.append(Paragraph(str(cell), STYLE_CELL_HEADER))
            else:
                style = STYLE_CELL_BOLD if col_idx == 0 else STYLE_CELL
                formatted_row.append(Paragraph(str(cell), style))
        formatted_table.append(formatted_row)

    t = Table(formatted_table, colWidths=col_widths, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
    ]))
    return t


def generate_report(scan_id):
    scan = database.get_scan_by_id(scan_id)
    if not scan:
        raise ValueError("Scan not found")

    r = scan["full_result"]
    parsed = r.get("parsed", {})
    headers = parsed.get("headers", {})
    score = r.get("score", {})
    content = r.get("content", {})
    urlres = r.get("url", {})
    attres = r.get("attachment", {})
    geo = r.get("geo", {})

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(config.REPORT_DIR, f"report_{scan_id}_{timestamp}.pdf")

    # A4 printable area width = 21.0cm - 3.0cm = 18.0cm
    doc = SimpleDocTemplate(
        out_path,
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.8 * cm,
    )
    story = []

    # ── Section 1: Executive Summary ──
    story.append(Paragraph("Email Forensic Analysis Report", STYLE_TITLE))
    story.append(Spacer(1, 4))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#475569"), spaceAfter=12))

    summary_meta = [
        ["Report Generation Date:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Scan Reference ID:", f"#{scan_id}"],
        ["Analyzed File Name:", str(scan.get("filename") or "email.eml")],
        ["Sender Email Address:", str(headers.get("from") or scan.get("sender") or "Unknown")],
        ["SHA-256 Hash Digest:", str(parsed.get("file_hash") or "N/A")],
    ]
    meta_table = _make_paragraph_table(summary_meta, col_widths=[5.0 * cm, 13.0 * cm], is_header=False)
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # Verdict Banner
    verdict = score.get("verdict", "Unknown")
    color = VERDICT_COLORS.get(verdict, colors.grey)
    verdict_text = f"VERDICT: {verdict.upper()}   |   THREAT SCORE: {score.get('final_score', 0)} / 100"
    verdict_para = Paragraph(
        f"<font color='#ffffff'><b>{verdict_text}</b></font>",
        ParagraphStyle("VerdictBanner", fontName="Helvetica-Bold", fontSize=13, alignment=1, leading=16)
    )
    verdict_box = Table([[verdict_para]], colWidths=[18.0 * cm])
    verdict_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(verdict_box)
    story.append(Spacer(1, 14))

    # Reasons & Executive Summary
    story.append(Paragraph("Executive Summary", STYLE_H2))
    reasons = score.get("reasons", [])
    if reasons:
        story.append(Paragraph(
            f"This email was assessed as <b>{verdict}</b> due to {len(reasons)} forensic indicator(s) "
            f"detected across email body, headers, embedded links, and attachments:",
            STYLE_CELL
        ))
        story.append(Spacer(1, 6))
        for reason in reasons:
            story.append(Paragraph(f"• {reason}", STYLE_CELL_BOLD))
            story.append(Spacer(1, 3))
    else:
        story.append(Paragraph("This email passed all forensic security evaluations with no malicious indicators detected.", STYLE_CELL))

    story.append(Spacer(1, 16))

    # ── Section 2: Header & Authentication Analysis ──
    story.append(Paragraph("Email Header & Sender Authentication", STYLE_H1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=8))

    meta_fields = [
        ["Header Field", "Extracted Value"],
        ["From Header", str(headers.get("from") or "-")],
        ["From Domain", str(headers.get("from_domain") or "-")],
        ["Reply-To Header", str(headers.get("reply_to") or "-")],
        ["Return-Path", str(headers.get("return_path") or "-")],
        ["Subject Line", str(headers.get("subject") or "-")],
        ["Sent Date", str(headers.get("date") or "-")],
        ["Message-ID", str(headers.get("message_id") or "-")],
    ]
    story.append(_make_paragraph_table(meta_fields, col_widths=[4.5 * cm, 13.5 * cm]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Authentication Verification Checks (SPF / DKIM / DMARC)", STYLE_H2))
    auth_res = str(headers.get("authentication_results") or "No Authentication-Results header found in email.")
    story.append(Paragraph(auth_res, STYLE_CELL_MONO))
    story.append(Spacer(1, 16))

    # ── Section 3: Content & URL Inspection ──
    story.append(Paragraph("Content & URL Forensic Inspection", STYLE_H1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=8))

    prob = content.get("phishing_probability", 0)
    story.append(Paragraph(f"<b>AI Content Phishing Probability:</b> {prob}%", STYLE_CELL_BOLD))
    story.append(Spacer(1, 4))
    if content.get("keyword_flags"):
        susp_phrases = ", ".join(content["keyword_flags"])
        story.append(Paragraph(f"<b>Suspicious Urgency / Phishing Keywords:</b> {susp_phrases}", STYLE_CELL))
    story.append(Spacer(1, 12))

    url_results = urlres.get("url_results", [])
    if url_results:
        story.append(Paragraph(f"Embedded URLs Analyzed ({len(url_results)} total)", STYLE_H2))
        url_table_data = [["Target URL", "Anchor Mismatch?", "Security Check Flags"]]
        for u in url_results:
            flags_str = ", ".join(f["check"] for f in u["flags"]) or "Clean"
            has_mismatch = "YES (Suspicious)" if any(f["check"] == "anchor_mismatch" for f in u["flags"]) else "No"
            url_table_data.append([
                Paragraph(u["url"], STYLE_CELL_MONO),
                Paragraph(has_mismatch, STYLE_CELL_BOLD),
                Paragraph(flags_str, STYLE_CELL),
            ])
        story.append(_make_paragraph_table(url_table_data, col_widths=[9.0 * cm, 3.5 * cm, 5.5 * cm], is_header=False))
    else:
        story.append(Paragraph("No embedded HTTP/HTTPS URLs were found in this email body.", STYLE_CELL))

    story.append(Spacer(1, 16))

    # ── Section 4: Attachments ──
    att_results = attres.get("attachment_results", [])
    if att_results:
        story.append(Paragraph("Attachment Malware Analysis", STYLE_H1))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=8))
        att_data = [["Filename", "Content Type", "Size", "SHA-256 Digest", "Threat Flags"]]
        for a in att_results:
            flags_str = ", ".join(f["check"] for f in a["flags"]) or "Clean"
            att_data.append([
                Paragraph(a["filename"], STYLE_CELL_BOLD),
                Paragraph(a["content_type"], STYLE_CELL),
                Paragraph(f"{a['size_bytes']} bytes", STYLE_CELL),
                Paragraph(a.get("sha256") or "-", STYLE_CELL_MONO),
                Paragraph(flags_str, STYLE_CELL),
            ])
        story.append(_make_paragraph_table(att_data, col_widths=[3.5 * cm, 3.0 * cm, 2.0 * cm, 5.5 * cm, 4.0 * cm], is_header=False))
        story.append(Spacer(1, 16))

    # ── Section 5: Geolocation & Hop Tracing ──
    story.append(Paragraph("Network Hop Tracing & Geolocation", STYLE_H1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=8))

    hops = geo.get("hops", [])
    if hops:
        geo_data = [["Hop #", "IP Address", "Geographic Location", "ISP / Network Provider", "Node Role"]]
        for h in hops:
            loc_str = h.get("location_str") or ", ".join([p for p in [h.get("city"), h.get("region"), h.get("country")] if p]) or "Unknown"
            geo_data.append([
                Paragraph(f"#{h['hop_number']}", STYLE_CELL_BOLD),
                Paragraph(h["ip"], STYLE_CELL_MONO),
                Paragraph(loc_str, STYLE_CELL_BOLD),
                Paragraph(h.get("isp") or h.get("org") or "Unknown ISP", STYLE_CELL),
                Paragraph(h.get("label") or "Relay", STYLE_CELL),
            ])
        story.append(_make_paragraph_table(geo_data, col_widths=[1.5 * cm, 3.5 * cm, 5.0 * cm, 5.0 * cm, 3.0 * cm], is_header=False))
    else:
        story.append(Paragraph("No public sender IP address could be isolated from Received header hops.", STYLE_CELL))

    story.append(Spacer(1, 16))

    # ── Section 6: Score Breakdown & Custody ──
    story.append(Paragraph("Forensic Score Contribution Breakdown", STYLE_H1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=8))

    breakdown = score.get("breakdown", [])
    bd_data = [["Module Category", "Raw Score", "Category Weight", "Final Point Contribution"]]
    for b in breakdown:
        bd_data.append([
            Paragraph(b["category"], STYLE_CELL_BOLD),
            Paragraph(str(b["raw_score"]), STYLE_CELL),
            Paragraph(str(b["weight"]), STYLE_CELL),
            Paragraph(f"{b['contribution']} pts", STYLE_CELL_BOLD),
        ])
    story.append(_make_paragraph_table(bd_data, col_widths=[6.0 * cm, 3.5 * cm, 4.0 * cm, 4.5 * cm], is_header=False))

    story.append(Spacer(1, 16))
    story.append(Paragraph("Chain of Custody & Audit Certification", STYLE_H2))
    custody_text = (
        f"This forensic report was automatically generated from cryptographic SHA-256 hash "
        f"<font face='Courier'><b>{parsed.get('file_hash')}</b></font>. All extracted artifacts, header hop traces, "
        f"and score assessments remain immutable. Report generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."
    )
    story.append(Paragraph(custody_text, STYLE_SMALL_GREY))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return out_path
