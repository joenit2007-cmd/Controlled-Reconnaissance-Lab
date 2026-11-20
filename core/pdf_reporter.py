"""
PDF Report Generator module for Controlled Reconnaissance Lab.
Generates comprehensive, professional cybersecurity assessment reports
using ReportLab with custom styling, risk matrices, and remediation roadmaps.
"""
import os
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)

from core.config import REPORTS_DIR

# Cyber Theme Palette
COLOR_PRIMARY = colors.HexColor("#0f172a")    # Slate 900
COLOR_SECONDARY = colors.HexColor("#1e293b")  # Slate 800
COLOR_ACCENT = colors.HexColor("#0284c7")     # Sky Blue
COLOR_CRITICAL = colors.HexColor("#dc2626")   # Red 600
COLOR_HIGH = colors.HexColor("#ea580c")       # Orange 600
COLOR_MEDIUM = colors.HexColor("#d97706")     # Amber 600
COLOR_LOW = colors.HexColor("#16a34a")        # Green 600
COLOR_INFO = colors.HexColor("#2563eb")       # Blue 600
COLOR_TEXT = colors.HexColor("#0f172a")
COLOR_MUTED = colors.HexColor("#64748b")
COLOR_LIGHT_BG = colors.HexColor("#f8fafc")

def get_severity_color(severity: str) -> colors.HexColor:
    """Map finding severity to accent color."""
    sev = severity.capitalize()
    if sev == "Critical":
        return COLOR_CRITICAL
    elif sev == "High":
        return COLOR_HIGH
    elif sev == "Medium":
        return COLOR_MEDIUM
    elif sev == "Low":
        return COLOR_LOW
    else:
        return COLOR_INFO

def generate_security_report(
    target: str,
    findings: List[Dict[str, Any]],
    scans_summary: Dict[str, Any],
    pcap_summary: Dict[str, Any] = None,
    output_filename: str = None
) -> str:
    """
    Generate an executive and technical PDF security assessment report.
    Returns absolute file path of the generated PDF.
    """
    if not output_filename:
        safe_target = target.replace(":", "_").replace("/", "_").replace(".", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"Recon_Report_{safe_target}_{timestamp}.pdf"

    pdf_path = REPORTS_DIR / output_filename
    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=COLOR_PRIMARY,
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=11,
        leading=15,
        textColor=COLOR_MUTED,
        spaceAfter=14
    )

    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=COLOR_ACCENT,
        spaceBefore=14,
        spaceAfter=8
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13.5,
        textColor=COLOR_TEXT,
        spaceAfter=6
    )

    table_header_style = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=11,
        textColor=colors.white
    )

    table_cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=COLOR_TEXT
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("CONTROLLED RECONNAISSANCE LAB", title_style))
    story.append(Paragraph("Confidential Security Assessment & Reconnaissance Audit", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=COLOR_ACCENT, spaceAfter=14))

    # Metadata Box
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    meta_data = [
        [
            Paragraph("<b>Target Evaluated:</b>", table_cell_style),
            Paragraph(f"<code>{target}</code> (Authorized Lab Scope)", table_cell_style),
            Paragraph("<b>Assessment Date:</b>", table_cell_style),
            Paragraph(now_str, table_cell_style),
        ],
        [
            Paragraph("<b>Classification:</b>", table_cell_style),
            Paragraph("<font color='#0284c7'>LAB AUDIT / CONTROLLED SCOPE</font>", table_cell_style),
            Paragraph("<b>Total Findings:</b>", table_cell_style),
            Paragraph(f"<b>{len(findings)} Issue(s) Identified</b>", table_cell_style),
        ]
    ]
    meta_table = Table(meta_data, colWidths=[100, 160, 100, 172])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_LIGHT_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # 2. Executive Summary
    story.append(Paragraph("1. Executive Summary", section_heading))
    summary_text = (
        f"This document provides the formalized security assessment report generated by the "
        f"Controlled Reconnaissance Lab framework. A comprehensive multi-vector reconnaissance "
        f"audit was performed against authorized target <code>{target}</code>. The evaluation included "
        f"network port discovery, service version identification, DNS infrastructure mapping, "
        f"web security header verification, and packet capture anomaly analysis. "
        f"All testing was conducted strictly within authorized non-destructive boundaries."
    )
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 8))

    # Severity Matrix Breakdown
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        sev = f.get("severity", "Informational").capitalize()
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["Informational"] += 1

    matrix_data = [
        [
            Paragraph("<b>Critical</b>", table_header_style),
            Paragraph("<b>High</b>", table_header_style),
            Paragraph("<b>Medium</b>", table_header_style),
            Paragraph("<b>Low</b>", table_header_style),
            Paragraph("<b>Info</b>", table_header_style),
        ],
        [
            Paragraph(f"<font size=14><b>{sev_counts['Critical']}</b></font>", table_header_style),
            Paragraph(f"<font size=14><b>{sev_counts['High']}</b></font>", table_header_style),
            Paragraph(f"<font size=14><b>{sev_counts['Medium']}</b></font>", table_header_style),
            Paragraph(f"<font size=14><b>{sev_counts['Low']}</b></font>", table_header_style),
            Paragraph(f"<font size=14><b>{sev_counts['Informational']}</b></font>", table_header_style),
        ]
    ]
    matrix_table = Table(matrix_data, colWidths=[106, 106, 106, 106, 108])
    matrix_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), COLOR_CRITICAL),
        ("BACKGROUND", (1, 0), (1, -1), COLOR_HIGH),
        ("BACKGROUND", (2, 0), (2, -1), COLOR_MEDIUM),
        ("BACKGROUND", (3, 0), (3, -1), COLOR_LOW),
        ("BACKGROUND", (4, 0), (4, -1), COLOR_INFO),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(matrix_table)
    story.append(Spacer(1, 14))

    # 3. Reconnaissance Scope & Methodology
    story.append(Paragraph("2. Scope & Regulatory Compliance", section_heading))
    scope_text = (
        "In compliance with responsible disclosure and defensive security principles, "
        "scanning activity was strictly confined to localhost (127.0.0.1) and private RFC 1918 "
        "lab subnetworks. No unauthorized public resources or third-party cloud infrastructure "
        "were targeted during this operation."
    )
    story.append(Paragraph(scope_text, body_style))
    story.append(Spacer(1, 8))

    # 4. Port & Service Discovery Results
    story.append(Paragraph("3. Network Port & Service Reconnaissance", section_heading))
    ports_list = scans_summary.get("ports", [])
    if ports_list:
        port_rows = [
            [
                Paragraph("<b>Port/Proto</b>", table_header_style),
                Paragraph("<b>State</b>", table_header_style),
                Paragraph("<b>Service</b>", table_header_style),
                Paragraph("<b>Version / Banner Information</b>", table_header_style),
            ]
        ]
        for p in ports_list:
            port_rows.append([
                Paragraph(f"{p.get('port')}/{p.get('protocol', 'tcp')}", table_cell_style),
                Paragraph(f"<font color='green'><b>{p.get('state')}</b></font>", table_cell_style),
                Paragraph(p.get("service", "unknown"), table_cell_style),
                Paragraph(p.get("version", "-") or "-", table_cell_style),
            ])
        port_table = Table(port_rows, colWidths=[90, 70, 110, 262])
        port_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_SECONDARY),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(port_table)
    else:
        story.append(Paragraph("<i>No open ports or services exposed within scanned range.</i>", body_style))

    story.append(Spacer(1, 14))

    # 5. Packet Capture Analysis (if provided)
    if pcap_summary:
        story.append(Paragraph("4. Packet Capture (PCAP) Analysis Highlights", section_heading))
        pcap_text = (
            f"<b>Capture File:</b> {pcap_summary.get('file_name', 'capture.pcap')} | "
            f"<b>Total Packets:</b> {pcap_summary.get('total_packets', 0)} | "
            f"<b>Security Alerts:</b> {pcap_summary.get('alerts_count', 0)}"
        )
        story.append(Paragraph(pcap_text, body_style))

        alerts = pcap_summary.get("security_alerts", [])
        if alerts:
            for alt in alerts:
                alt_table = Table([
                    [
                        Paragraph(f"<b>ALERT: {alt['title']}</b>", table_header_style),
                        Paragraph(f"<b>{alt['severity']}</b>", table_header_style),
                    ],
                    [
                        Paragraph(f"{alt['details']}<br/><b>Recommendation:</b> {alt.get('recommendation', '')}", table_cell_style),
                        Paragraph("", table_cell_style)
                    ]
                ], colWidths=[432, 100])
                alt_table.setStyle(TableStyle([
                    ("SPAN", (0, 1), (1, 1)),
                    ("BACKGROUND", (0, 0), (-1, 0), get_severity_color(alt["severity"])),
                    ("BACKGROUND", (0, 1), (-1, 1), COLOR_LIGHT_BG),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                story.append(Spacer(1, 4))
                story.append(alt_table)

    story.append(Spacer(1, 14))

    # 6. Detailed Security Findings & Remediations
    story.append(Paragraph("5. Detailed Security Findings & Remediations", section_heading))
    if findings:
        for idx, finding in enumerate(findings, start=1):
            sev = finding.get("severity", "Info")
            sev_color = get_severity_color(sev)

            finding_flowables = []
            f_table_data = [
                [
                    Paragraph(f"<b>Finding #{idx}: {finding.get('title')}</b>", table_header_style),
                    Paragraph(f"<b>{sev.upper()}</b>", table_header_style)
                ],
                [
                    Paragraph(f"<b>Category:</b> {finding.get('category')} | <b>Target:</b> {finding.get('target', target)} | <b>Status:</b> {finding.get('status', 'Open')}", table_cell_style),
                    Paragraph("", table_cell_style)
                ],
                [
                    Paragraph(f"<b>Description:</b><br/>{finding.get('description', 'N/A')}", table_cell_style),
                    Paragraph("", table_cell_style)
                ],
                [
                    Paragraph(f"<b>Discovered Evidence:</b><br/><code>{finding.get('evidence', 'N/A')}</code>", table_cell_style),
                    Paragraph("", table_cell_style)
                ],
                [
                    Paragraph(f"<b>Actionable Remediation:</b><br/>{finding.get('remediation', 'N/A')}", table_cell_style),
                    Paragraph("", table_cell_style)
                ]
            ]
            f_table = Table(f_table_data, colWidths=[432, 100])
            f_table.setStyle(TableStyle([
                ("SPAN", (0, 1), (1, 1)),
                ("SPAN", (0, 2), (1, 2)),
                ("SPAN", (0, 3), (1, 3)),
                ("SPAN", (0, 4), (1, 4)),
                ("BACKGROUND", (0, 0), (-1, 0), sev_color),
                ("BACKGROUND", (0, 1), (-1, -1), COLOR_LIGHT_BG),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 1), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))

            finding_flowables.append(f_table)
            finding_flowables.append(Spacer(1, 10))
            story.append(KeepTogether(finding_flowables))
    else:
        story.append(Paragraph("<i>No security vulnerabilities or misconfigurations documented for this target.</i>", body_style))

    # 7. Hardening Roadmap
    story.append(Spacer(1, 10))
    story.append(Paragraph("6. Defensive Hardening Roadmap", section_heading))
    roadmap_text = (
        "1. <b>Service Exposure Reduction:</b> Disable legacy and unencrypted protocols (FTP, Telnet, unencrypted HTTP). Enforce TLS 1.3 across web endpoints.<br/>"
        "2. <b>Network Segmentation:</b> Isolate database, cache, and administration ports from untrusted network access using host firewalls (UFW/iptables).<br/>"
        "3. <b>DNS & Header Hardening:</b> Enforce SPF/DMARC records to prevent domain impersonation, and inject modern browser security headers (HSTS, CSP, X-Frame-Options)."
    )
    story.append(Paragraph(roadmap_text, body_style))

    # Build PDF
    doc.build(story)
    return str(pdf_path)
