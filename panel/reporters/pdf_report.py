"""
SentinelScan — reporters/pdf_report.py
Full PDF Security Report Generator
Phase 7 — Report Generator

Uses ReportLab to produce a professional, fully formatted PDF report
containing: cover page, executive summary with severity chart,
risk score, per-finding detail table with remediation, appendix,
and footer branding.
"""
from __future__ import annotations
import io
import math
import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.orchestrator import ScanSession

# ─── ReportLab imports ────────────────────────────────────────────────────────
try:
    from reportlab.lib.pagesizes  import A4, letter
    from reportlab.lib.units       import mm, inch, cm
    from reportlab.lib             import colors
    from reportlab.lib.styles      import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums       import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
    from reportlab.platypus        import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable, KeepTogether, Flowable,
    )
    from reportlab.graphics.shapes import Drawing, Rect, String, Circle, Wedge, Line
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics        import renderPDF
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


# ─── COLOUR PALETTE ───────────────────────────────────────────────────────────
C_DARK        = colors.HexColor("#0d1117")
C_NAVY        = colors.HexColor("#1A3A5C")
C_ACCENT      = colors.HexColor("#2E86AB")
C_ACCENT_LIGHT= colors.HexColor("#D4EBF8")
C_PANEL       = colors.HexColor("#161b22")
C_BORDER      = colors.HexColor("#30363d")
C_TEXT        = colors.HexColor("#1a1a2e")
C_MUTED       = colors.HexColor("#555577")
C_WHITE       = colors.white
C_LIGHT_BG    = colors.HexColor("#F0F4F8")
C_CRITICAL    = colors.HexColor("#e74c3c")
C_HIGH        = colors.HexColor("#e67e22")
C_MEDIUM      = colors.HexColor("#d4a017")
C_LOW         = colors.HexColor("#27ae60")
C_INFO        = colors.HexColor("#7f8c8d")
C_ROW_ALT     = colors.HexColor("#F7FAFB")

SEV_COLORS = {
    "CRITICAL": C_CRITICAL, "HIGH": C_HIGH,
    "MEDIUM":   C_MEDIUM,   "LOW":  C_LOW, "INFO": C_INFO,
}

PAGE_WIDTH, PAGE_HEIGHT = A4


# ─── CUSTOM FLOWABLES ─────────────────────────────────────────────────────────
class ColorBar(Flowable):
    """A horizontal colored bar — used as accent dividers."""
    def __init__(self, width, height=3, color=C_ACCENT):
        super().__init__()
        self.width  = width
        self.height = height
        self.color  = color

    def draw(self):
        self.canv.setFillColor(self.color)
        self.canv.rect(0, 0, self.width, self.height, fill=1, stroke=0)


class SeverityBadge(Flowable):
    """Inline colored severity badge pill."""
    def __init__(self, severity: str, width=72, height=16):
        super().__init__()
        self.severity = severity
        self.width    = width
        self.height   = height

    def draw(self):
        color = SEV_COLORS.get(self.severity, C_INFO)
        r     = self.height / 2
        c     = self.canv
        c.setFillColor(color)
        c.roundRect(0, 0, self.width, self.height, r, fill=1, stroke=0)
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 8)
        c.drawCentredString(self.width / 2, 4, self.severity)


def _severity_donut(counts: dict[str, int], size: float = 120) -> Drawing:
    """Build a donut/pie chart for severity breakdown."""
    total  = sum(counts.values())
    if total == 0:
        total = 1
    d  = Drawing(size, size)
    cx = size / 2
    cy = size / 2
    r  = size * 0.42
    ri = size * 0.24  # inner radius for donut effect

    angles = []
    start  = 90.0  # start from top
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = counts.get(sev, 0)
        if count == 0:
            continue
        sweep  = 360.0 * count / total
        color  = SEV_COLORS[sev]
        # Outer wedge
        w = Wedge(cx, cy, r, start, start - sweep, fillColor=color, strokeColor=colors.white, strokeWidth=1.5)
        d.add(w)
        # Cutout: white inner circle (donut hole)
        angles.append((sev, count, start - sweep / 2))
        start -= sweep

    # White centre circle for donut effect
    hole = Circle(cx, cy, ri, fillColor=colors.white, strokeColor=colors.white)
    d.add(hole)

    # Total count in centre
    d.add(String(cx, cy - 6, str(total),
                 fontSize=16, fontName="Helvetica-Bold",
                 fillColor=C_NAVY, textAnchor="middle"))
    d.add(String(cx, cy + 8, "findings",
                 fontSize=7, fontName="Helvetica",
                 fillColor=C_MUTED, textAnchor="middle"))
    return d


def _risk_gauge(score: float, size: float = 110) -> Drawing:
    """Semicircular risk gauge (0–100)."""
    d   = Drawing(size, size * 0.65)
    cx  = size / 2
    cy  = 0
    r   = size * 0.44
    # Background arc (grey)
    from reportlab.graphics.shapes import ArcPath
    # Draw arc segments
    colors_arc = [
        (0,  20, C_INFO),    (20, 40, C_LOW),
        (40, 60, C_MEDIUM),  (60, 80, C_HIGH),
        (80, 100, C_CRITICAL),
    ]
    for lo, hi, col in colors_arc:
        start_a = 180 - lo * 1.8
        end_a   = 180 - hi * 1.8
        w = Wedge(cx, cy, r, end_a, start_a, innerRadiusFraction=0.7,
                  fillColor=col, strokeColor=colors.white, strokeWidth=1)
        d.add(w)

    # Needle
    angle_deg = 180 - score * 1.8
    angle_rad = math.radians(angle_deg)
    nx = cx + r * 0.75 * math.cos(angle_rad)
    ny = cy + r * 0.75 * math.sin(angle_rad)
    d.add(Line(cx, cy, nx, ny, strokeColor=C_NAVY, strokeWidth=2.5))
    d.add(Circle(cx, cy, 5, fillColor=C_NAVY, strokeColor=colors.white, strokeWidth=1))

    # Score text
    d.add(String(cx, cy + 18, f"{score:.0f}",
                 fontSize=18, fontName="Helvetica-Bold",
                 fillColor=C_NAVY, textAnchor="middle"))
    d.add(String(cx, cy + 8, "/ 100",
                 fontSize=8, fontName="Helvetica",
                 fillColor=C_MUTED, textAnchor="middle"))
    return d


# ─── STYLES ───────────────────────────────────────────────────────────────────
def _build_styles():
    base = getSampleStyleSheet()
    def S(name, parent="Normal", **kwargs):
        return ParagraphStyle(name, parent=base[parent], **kwargs)

    return {
        "cover_title":   S("cover_title",   fontSize=32, textColor=C_WHITE,
                           fontName="Helvetica-Bold", leading=38, alignment=TA_LEFT),
        "cover_sub":     S("cover_sub",     fontSize=14, textColor=C_ACCENT_LIGHT,
                           fontName="Helvetica", leading=20, alignment=TA_LEFT),
        "cover_meta":    S("cover_meta",    fontSize=10, textColor=colors.HexColor("#aabbcc"),
                           fontName="Helvetica", leading=14, alignment=TA_LEFT),
        "h1":            S("h1",            fontSize=16, textColor=C_NAVY,
                           fontName="Helvetica-Bold", leading=20,
                           spaceBefore=18, spaceAfter=6),
        "h2":            S("h2",            fontSize=13, textColor=C_ACCENT,
                           fontName="Helvetica-Bold", leading=16,
                           spaceBefore=12, spaceAfter=4),
        "body":          S("body",          fontSize=9.5, textColor=C_TEXT,
                           fontName="Helvetica", leading=14,
                           spaceBefore=3, spaceAfter=3),
        "body_bold":     S("body_bold",     fontSize=9.5, textColor=C_TEXT,
                           fontName="Helvetica-Bold", leading=14),
        "code":          S("code",          fontSize=8, textColor=colors.HexColor("#1a3a5c"),
                           fontName="Courier", leading=11,
                           backColor=colors.HexColor("#EEF4FA"),
                           leftIndent=6, rightIndent=6, spaceBefore=2, spaceAfter=2),
        "table_header":  S("table_header",  fontSize=8, textColor=C_WHITE,
                           fontName="Helvetica-Bold", leading=11, alignment=TA_CENTER),
        "table_cell":    S("table_cell",    fontSize=8, textColor=C_TEXT,
                           fontName="Helvetica", leading=11),
        "table_cell_b":  S("table_cell_b",  fontSize=8, textColor=C_TEXT,
                           fontName="Helvetica-Bold", leading=11),
        "finding_title": S("finding_title", fontSize=9.5, textColor=C_NAVY,
                           fontName="Helvetica-Bold", leading=13),
        "finding_body":  S("finding_body",  fontSize=8.5, textColor=C_TEXT,
                           fontName="Helvetica", leading=12),
        "finding_rem":   S("finding_rem",   fontSize=8, textColor=colors.HexColor("#1a3a5c"),
                           fontName="Courier", leading=11,
                           backColor=colors.HexColor("#EEF4FA"),
                           leftIndent=4, rightIndent=4),
        "legend":        S("legend",        fontSize=8, textColor=C_MUTED,
                           fontName="Helvetica", leading=11),
        "footer":        S("footer",        fontSize=7.5, textColor=C_MUTED,
                           fontName="Helvetica", leading=10, alignment=TA_CENTER),
    }


# ─── PAGE TEMPLATES ───────────────────────────────────────────────────────────
def _header_footer(canvas, doc, session, styles):
    """Called on every page except cover."""
    canvas.saveState()
    page_num = doc.page

    if page_num == 1:
        canvas.restoreState()
        return

    w = PAGE_WIDTH
    # Top bar
    canvas.setFillColor(C_NAVY)
    canvas.rect(0, PAGE_HEIGHT - 22*mm, w, 22*mm, fill=1, stroke=0)
    canvas.setFillColor(C_ACCENT)
    canvas.rect(0, PAGE_HEIGHT - 23.5*mm, w, 1.5*mm, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.setFillColor(colors.white)
    canvas.drawString(18*mm, PAGE_HEIGHT - 14*mm, "🛡  SentinelScan — Security Audit Report")
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#aabbcc"))
    target_str = f"Target: {session.target}  |  Mode: {session.mode.upper()}  |  {session.scan_type.upper()} Scan"
    canvas.drawRightString(w - 18*mm, PAGE_HEIGHT - 14*mm, target_str)

    # Bottom bar
    canvas.setFillColor(C_ACCENT)
    canvas.rect(0, 14*mm, w, 1*mm, fill=1, stroke=0)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(C_MUTED)
    canvas.drawString(18*mm, 8*mm, "Confidential — Internal Use Only")
    canvas.drawCentredString(w / 2, 8*mm,
        f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
    canvas.drawRightString(w - 18*mm, 8*mm, f"Page {page_num}")

    canvas.restoreState()


# ─── COVER PAGE ───────────────────────────────────────────────────────────────
def _build_cover(session, styles) -> list:
    w = PAGE_WIDTH
    story = []

    class CoverCanvas(Flowable):
        def __init__(self, session):
            super().__init__()
            self.session = session
            self.width   = PAGE_WIDTH - 36*mm
            self.height  = PAGE_HEIGHT - 36*mm

        def draw(self):
            c = self.canv
            s = self.session
            W = PAGE_WIDTH - 36*mm

            # Dark background panel
            c.setFillColor(C_NAVY)
            c.rect(0, 0, W, self.height, fill=1, stroke=0)

            # Accent stripe top
            c.setFillColor(C_ACCENT)
            c.rect(0, self.height - 8, W, 8, fill=1, stroke=0)

            # Shield icon area
            c.setFillColor(colors.HexColor("#243B55"))
            c.roundRect(20, self.height - 120, 80, 80, 12, fill=1, stroke=0)
            c.setFont("Helvetica-Bold", 36)
            c.setFillColor(C_ACCENT_LIGHT)
            c.drawString(32, self.height - 88, "🛡")

            # Title
            c.setFont("Helvetica-Bold", 28)
            c.setFillColor(colors.white)
            c.drawString(20, self.height - 160, "Security Audit Report")
            c.setFont("Helvetica", 14)
            c.setFillColor(C_ACCENT_LIGHT)
            c.drawString(22, self.height - 180, "Powered by SentinelScan v1.0")

            # Divider
            c.setStrokeColor(C_ACCENT)
            c.setLineWidth(2)
            c.line(20, self.height - 196, W - 20, self.height - 196)

            # Metadata grid
            meta = [
                ("Scan ID",     s.scan_id),
                ("Target",      s.target),
                ("Scan Mode",   s.mode.upper()),
                ("Scan Type",   s.scan_type.upper()),
                ("Duration",    f"{s.elapsed_seconds:.1f}s"),
                ("Generated",   datetime.datetime.now().strftime("%Y-%m-%d %H:%M")),
            ]
            y = self.height - 220
            for label, value in meta:
                c.setFont("Helvetica", 8)
                c.setFillColor(colors.HexColor("#8899aa"))
                c.drawString(24, y, label.upper())
                c.setFont("Helvetica-Bold", 10)
                c.setFillColor(colors.white)
                c.drawString(110, y, value)
                y -= 18

            # Severity summary boxes
            counts = s.severity_counts
            box_w  = (W - 40) / 5
            bx     = 20
            by     = 80

            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                cnt   = counts.get(sev, 0)
                bcolor = SEV_COLORS[sev]
                c.setFillColor(bcolor)
                c.roundRect(bx, by, box_w - 4, 55, 6, fill=1, stroke=0)
                c.setFont("Helvetica-Bold", 22)
                c.setFillColor(colors.white)
                c.drawCentredString(bx + (box_w - 4) / 2, by + 30, str(cnt))
                c.setFont("Helvetica-Bold", 7)
                c.setFillColor(colors.HexColor("#ffffff88"))
                c.drawCentredString(bx + (box_w - 4) / 2, by + 14, sev)
                bx += box_w

            # Total findings
            c.setFont("Helvetica-Bold", 11)
            c.setFillColor(C_ACCENT_LIGHT)
            c.drawRightString(W - 20, by - 16,
                f"Total Findings: {s.total_findings}")

            # Confidential watermark area
            c.setFont("Helvetica-Bold", 8)
            c.setFillColor(colors.HexColor("#ffffff22"))
            c.drawString(20, 20, "CONFIDENTIAL — INTERNAL USE ONLY")

    story.append(CoverCanvas(session))
    story.append(PageBreak())
    return story


# ─── EXECUTIVE SUMMARY ────────────────────────────────────────────────────────
def _build_executive_summary(session, styles) -> list:
    story = []
    counts = session.severity_counts
    total  = session.total_findings

    # Risk score: weighted by severity
    weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
    raw = sum(counts.get(s, 0) * w for s, w in weights.items())
    max_raw = total * 10 if total > 0 else 1
    risk_score = min(100, int((raw / max_raw) * 100))

    story.append(Paragraph("Executive Summary", styles["h1"]))
    story.append(ColorBar(PAGE_WIDTH - 36*mm, color=C_ACCENT))
    story.append(Spacer(1, 8))

    # Two-column layout: donut + gauge
    donut   = _severity_donut(counts, size=140)
    gauge   = _risk_gauge(risk_score, size=140)

    chart_table = Table(
        [[renderPDF.Drawing(donut.width, donut.height, donut),
          renderPDF.Drawing(gauge.width, gauge.height, gauge)]],
        colWidths=[(PAGE_WIDTH - 36*mm) * 0.5] * 2,
    )
    chart_table.setStyle(TableStyle([
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",  (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0,0), (-1, -1), 6),
    ]))
    story.append(chart_table)
    story.append(Spacer(1, 4))

    # Legend row under donut
    legend_items = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        cnt = counts.get(sev, 0)
        legend_items.append(f"{sev}: {cnt}")
    story.append(Paragraph("  |  ".join(legend_items), styles["legend"]))
    story.append(Spacer(1, 10))

    # Summary paragraph
    critical_count = counts.get("CRITICAL", 0)
    high_count     = counts.get("HIGH", 0)
    if critical_count > 0:
        risk_label = "CRITICAL — Immediate action required"
    elif high_count > 3:
        risk_label = "HIGH — Significant remediation work needed"
    elif high_count > 0:
        risk_label = "ELEVATED — Address high-severity items promptly"
    else:
        risk_label = "MODERATE — Address medium-severity items"

    story.append(Paragraph(
        f"This scan of <b>{session.target}</b> ({session.mode.upper()} mode, "
        f"{session.scan_type.upper()} scan) completed in {session.elapsed_seconds:.1f}s and "
        f"identified <b>{total} finding(s)</b> across {len(session.modules)} scan modules. "
        f"Overall risk level: <b>{risk_label}</b>.",
        styles["body"]))
    story.append(Spacer(1, 8))

    # Top 5 findings table
    critical_findings = sorted(
        [f for f in session.findings if f.severity.value in ("CRITICAL", "HIGH")],
        key=lambda x: x.severity.sort_order
    )[:5]

    if critical_findings:
        story.append(Paragraph("Priority Findings (Top 5)", styles["h2"]))
        story.append(Spacer(1, 4))
        data = [["Severity", "Finding", "Component"]]
        for f in critical_findings:
            data.append([
                Paragraph(f.severity.value, styles["table_header"]),
                Paragraph(f.title[:80], styles["table_cell"]),
                Paragraph((f.affected_component or "—")[:55], styles["table_cell"]),
            ])
        col_w = [(PAGE_WIDTH - 36*mm) * r for r in (0.12, 0.55, 0.33)]
        tbl = Table(data, colWidths=col_w, repeatRows=1)
        tbl.setStyle(_finding_table_style(critical_findings))
        story.append(tbl)
        story.append(Spacer(1, 10))

    # Module summary
    story.append(Paragraph("Scan Module Summary", styles["h2"]))
    story.append(Spacer(1, 4))
    mod_data = [["Module", "Status", "Findings", "Duration"]]
    for m in session.modules:
        status_color = {
            "done":    C_LOW, "skipped": C_INFO,
            "error":   C_HIGH, "running": C_ACCENT,
        }.get(m.get("status", ""), C_INFO)
        mod_data.append([
            Paragraph(m.get("display_name", m.get("name", "?")), styles["table_cell"]),
            Paragraph(m.get("status", "?").upper(), ParagraphStyle(
                "st", fontName="Helvetica-Bold", fontSize=7.5,
                textColor=status_color, leading=10)),
            Paragraph(str(m.get("finding_count", 0)), styles["table_cell"]),
            Paragraph(f"{m.get('elapsed_s', 0):.1f}s", styles["table_cell"]),
        ])
    col_w2 = [(PAGE_WIDTH - 36*mm) * r for r in (0.45, 0.18, 0.18, 0.19)]
    tbl2 = Table(mod_data, colWidths=col_w2, repeatRows=1)
    tbl2.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 8),
        ("ALIGN",         (0, 0), (-1, 0), "CENTER"),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_ROW_ALT]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(tbl2)
    story.append(PageBreak())
    return story


def _finding_table_style(findings):
    style = [
        ("BACKGROUND",    (0, 0), (-1, 0), C_NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 8),
        ("ALIGN",         (0, 0), (0, -1), "CENTER"),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_ROW_ALT]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]
    for i, f in enumerate(findings, start=1):
        bg = SEV_COLORS.get(f.severity.value, C_INFO)
        style.append(("BACKGROUND", (0, i), (0, i), bg))
    return TableStyle(style)


# ─── FINDINGS DETAIL SECTION ──────────────────────────────────────────────────
def _build_findings_section(session, styles) -> list:
    story = []
    story.append(Paragraph("Detailed Findings & Remediation Plan", styles["h1"]))
    story.append(ColorBar(PAGE_WIDTH - 36*mm, color=C_ACCENT))
    story.append(Spacer(1, 8))

    # Sort by severity
    sorted_findings = sorted(session.findings, key=lambda f: f.severity.sort_order)
    current_category = None

    for finding in sorted_findings:
        # Category header
        if finding.category != current_category:
            current_category = finding.category
            story.append(Spacer(1, 10))
            story.append(Paragraph(f"Category: {current_category}", styles["h2"]))
            story.append(HRFlowable(
                width=PAGE_WIDTH - 36*mm,
                thickness=1, color=C_ACCENT_LIGHT, spaceAfter=4))

        # Finding card
        elements = _build_finding_card(finding, styles)
        story.append(KeepTogether(elements))

    story.append(PageBreak())
    return story


def _build_finding_card(finding, styles) -> list:
    elems = []
    bg    = SEV_COLORS.get(finding.severity.value, C_INFO)

    # Header row: severity badge + title
    badge_cell = Table(
        [[Paragraph(finding.severity.value,
                    ParagraphStyle("sb", fontName="Helvetica-Bold",
                                   fontSize=7.5, textColor=colors.white,
                                   alignment=TA_CENTER, leading=10))]],
        colWidths=[52], rowHeights=[16],
    )
    badge_cell.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), bg),
        ("ROUNDEDCORNERS", (0, 0), (-1, -1), [4, 4, 4, 4]),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",   (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 2),
    ]))

    title_para = Paragraph(finding.title, styles["finding_title"])
    header_tbl = Table(
        [[badge_cell, title_para]],
        colWidths=[58, PAGE_WIDTH - 36*mm - 58],
    )
    header_tbl.setStyle(TableStyle([
        ("ALIGN",        (0, 0), (0, 0), "CENTER"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING",   (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 0),
    ]))
    elems.append(header_tbl)
    elems.append(Spacer(1, 3))

    # Description
    elems.append(Paragraph(finding.description, styles["finding_body"]))

    # Affected component
    if finding.affected_component:
        elems.append(Spacer(1, 2))
        elems.append(Paragraph(
            f"<b>Affected:</b> {finding.affected_component}", styles["finding_body"]))

    # CVSS + CVEs
    meta_parts = []
    if finding.cvss_score:
        meta_parts.append(f"CVSS: {finding.cvss_score:.1f}")
    if finding.cve_ids:
        meta_parts.append("  ".join(finding.cve_ids[:4]))
    if meta_parts:
        elems.append(Paragraph(
            f"<b>{'  |  '.join(meta_parts)}</b>",
            ParagraphStyle("meta", fontName="Helvetica-Bold", fontSize=7.5,
                           textColor=bg, leading=11)))

    # Remediation
    if finding.remediation:
        elems.append(Spacer(1, 2))
        elems.append(Paragraph("<b>Remediation:</b>", styles["finding_body"]))
        for line in finding.remediation.splitlines():
            if line.strip():
                elems.append(Paragraph(line, styles["finding_rem"]))

    # Workaround
    if finding.workaround:
        elems.append(Spacer(1, 2))
        elems.append(Paragraph(
            f"<b>Workaround:</b> {finding.workaround}", styles["finding_body"]))

    # Bottom divider
    elems.append(HRFlowable(
        width=PAGE_WIDTH - 36*mm, thickness=0.5,
        color=C_BORDER, spaceBefore=5, spaceAfter=5))
    return elems


# ─── APPENDIX ─────────────────────────────────────────────────────────────────
def _build_appendix(session, styles) -> list:
    story = []
    story.append(Paragraph("Appendix", styles["h1"]))
    story.append(ColorBar(PAGE_WIDTH - 36*mm, color=C_ACCENT))
    story.append(Spacer(1, 8))

    # A. Scan metadata
    story.append(Paragraph("A. Scan Metadata", styles["h2"]))
    meta = [
        ["Field", "Value"],
        ["Scan ID",         session.scan_id],
        ["Target",          session.target],
        ["Mode",            session.mode.upper()],
        ["Scan Type",       session.scan_type.upper()],
        ["Status",          session.status.upper()],
        ["Duration",        f"{session.elapsed_seconds:.1f} seconds"],
        ["Total Findings",  str(session.total_findings)],
        ["Modules Run",     str(len(session.modules))],
        ["Generated",       datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["SentinelScan",    "v1.0.0"],
    ]
    col_w = [(PAGE_WIDTH - 36*mm) * r for r in (0.3, 0.7)]
    tbl = Table(meta, colWidths=col_w)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), C_NAVY),
        ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 8.5),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_ROW_ALT]),
        ("GRID",         (0, 0), (-1, -1), 0.5, C_BORDER),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("FONTNAME",     (0, 1), (0, -1), "Helvetica-Bold"),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 12))

    # B. Findings by severity
    story.append(Paragraph("B. All Findings Summary", styles["h2"]))
    story.append(Spacer(1, 4))
    sum_data = [["#", "Severity", "Category", "Finding", "CVSS"]]
    for i, f in enumerate(sorted(session.findings, key=lambda x: x.severity.sort_order), 1):
        sum_data.append([
            str(i),
            Paragraph(f.severity.value,
                      ParagraphStyle("sb2", fontName="Helvetica-Bold", fontSize=7.5,
                                     textColor=SEV_COLORS.get(f.severity.value, C_INFO),
                                     leading=10)),
            f.category,
            Paragraph(f.title[:70], ParagraphStyle("ft2", fontName="Helvetica",
                                                     fontSize=7.5, leading=10)),
            str(f.cvss_score or "—"),
        ])
    col_w2 = [(PAGE_WIDTH - 36*mm) * r for r in (0.04, 0.1, 0.14, 0.61, 0.11)]
    tbl2 = Table(sum_data, colWidths=col_w2, repeatRows=1)
    tbl2.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), C_NAVY),
        ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0), 8),
        ("ALIGN",        (0, 0), (-1, 0), "CENTER"),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_ROW_ALT]),
        ("GRID",         (0, 0), (-1, -1), 0.5, C_BORDER),
        ("FONTSIZE",     (0, 1), (-1, -1), 7.5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 5),
        ("TOPPADDING",   (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(tbl2)
    story.append(Spacer(1, 12))

    # C. Disclaimer
    story.append(Paragraph("C. Disclaimer", styles["h2"]))
    story.append(Paragraph(
        "This report was generated by SentinelScan v1.0 for internal security assessment purposes only. "
        "All findings represent the state of the scanned system at the time of the scan. "
        "SentinelScan performs read-only audits and does not modify system configurations. "
        "This report is confidential and intended solely for the authorised recipient. "
        "False positives may exist — all CRITICAL and HIGH findings should be manually verified "
        "before remediation. The tool operator is responsible for ensuring authorisation to scan "
        "any target system.",
        styles["body"]))
    return story


# ─── MAIN ENTRY POINT ─────────────────────────────────────────────────────────
def generate_pdf(session, output_path: str) -> str:
    """
    Generate a full PDF report for the given ScanSession.
    Returns the path to the written PDF file.
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError(
            "reportlab is not installed. Run: pip install reportlab")

    styles = _build_styles()
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    def on_page(canvas, doc):
        _header_footer(canvas, doc, session, styles)

    doc = SimpleDocTemplate(
        output_path,
        pagesize       = A4,
        rightMargin    = 18*mm,
        leftMargin     = 18*mm,
        topMargin      = 28*mm,
        bottomMargin   = 22*mm,
        title          = f"SentinelScan Report — {session.scan_id}",
        author         = "SentinelScan v1.0",
        subject        = f"Security Audit: {session.target}",
        creator        = "SentinelScan",
    )

    story = []
    story += _build_cover(session, styles)
    story += _build_executive_summary(session, styles)
    story += _build_findings_section(session, styles)
    story += _build_appendix(session, styles)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return output_path


def generate_pdf_bytes(session) -> bytes:
    """Generate PDF and return as bytes (for Flask streaming response)."""
    buf = io.BytesIO()
    if not REPORTLAB_AVAILABLE:
        raise ImportError("reportlab not installed")

    styles = _build_styles()

    def on_page(canvas, doc):
        _header_footer(canvas, doc, session, styles)

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        rightMargin=18*mm, leftMargin=18*mm,
        topMargin=28*mm, bottomMargin=22*mm,
        title=f"SentinelScan Report — {session.scan_id}",
    )
    story = []
    story += _build_cover(session, styles)
    story += _build_executive_summary(session, styles)
    story += _build_findings_section(session, styles)
    story += _build_appendix(session, styles)
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()
