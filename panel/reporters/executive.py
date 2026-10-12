"""
SentinelScan — reporters/executive.py
One-Page Executive Summary PDF Generator
Phase 7 — Report Generator

Produces a concise single-page (or two-page) executive report
suitable for management briefings. Contains: risk score, top-3
critical items, recommended actions, and a scan health overview.
"""
from __future__ import annotations
import io
import datetime
import math
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.orchestrator import ScanSession

try:
    from reportlab.lib.pagesizes  import A4, letter
    from reportlab.lib.units       import mm
    from reportlab.lib             import colors
    from reportlab.lib.styles      import ParagraphStyle
    from reportlab.lib.enums       import TA_LEFT, TA_CENTER, TA_RIGHT
    from reportlab.platypus        import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether,
    )
    from reportlab.graphics.shapes import Drawing, Wedge, Circle, Line, Rect, String
    from reportlab.graphics        import renderPDF
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

C_NAVY    = colors.HexColor("#1A3A5C")
C_ACCENT  = colors.HexColor("#2E86AB")
C_LIGHT   = colors.HexColor("#D4EBF8")
C_MUTED   = colors.HexColor("#888888")
C_WHITE   = colors.white
C_CRIT    = colors.HexColor("#e74c3c")
C_HIGH    = colors.HexColor("#e67e22")
C_MED     = colors.HexColor("#d4a017")
C_LOW     = colors.HexColor("#27ae60")
C_INFO    = colors.HexColor("#7f8c8d")
C_ROW     = colors.HexColor("#F0F4F8")

SEV_C = {"CRITICAL": C_CRIT, "HIGH": C_HIGH, "MEDIUM": C_MED, "LOW": C_LOW, "INFO": C_INFO}


def _risk_arc(score: float, size: float = 100) -> Drawing:
    """Compact arc risk gauge."""
    d  = Drawing(size, size * 0.6)
    cx = size / 2
    cy = 0
    r  = size * 0.44
    # Background arc bands
    for lo, hi, col in [(0,20,C_INFO),(20,40,C_LOW),(40,60,C_MED),(60,80,C_HIGH),(80,100,C_CRIT)]:
        start_a = 180 - lo * 1.8
        end_a   = 180 - hi * 1.8
        w = Wedge(cx, cy, r, end_a, start_a, innerRadiusFraction=0.68,
                  fillColor=col, strokeColor=colors.white, strokeWidth=1.2)
        d.add(w)
    # Needle
    angle_rad = math.radians(180 - score * 1.8)
    nx = cx + r * 0.72 * math.cos(angle_rad)
    ny = cy + r * 0.72 * math.sin(angle_rad)
    d.add(Line(cx, cy, nx, ny, strokeColor=C_NAVY, strokeWidth=2.2))
    d.add(Circle(cx, cy, 4.5, fillColor=C_NAVY, strokeColor=C_WHITE, strokeWidth=1))
    d.add(String(cx, cy + 16, f"{score:.0f}", fontSize=15,
                 fontName="Helvetica-Bold", fillColor=C_NAVY, textAnchor="middle"))
    d.add(String(cx, cy + 7, "/ 100", fontSize=7,
                 fontName="Helvetica", fillColor=C_MUTED, textAnchor="middle"))
    return d


def _sev_mini_chart(counts: dict, size: float = 100) -> Drawing:
    """Mini horizontal bar chart."""
    d = Drawing(size, 70)
    sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    max_c = max((counts.get(s, 0) for s in sevs), default=1) or 1
    y = 60
    bar_h = 9
    for sev in sevs:
        cnt   = counts.get(sev, 0)
        bw    = int((cnt / max_c) * (size * 0.65)) or 2
        col   = SEV_C[sev]
        d.add(String(2, y + 1, sev[:4], fontSize=7,
                     fontName="Helvetica-Bold", fillColor=col))
        d.add(Rect(32, y, bw, bar_h, fillColor=col, strokeColor=None))
        d.add(String(34 + bw, y + 1, str(cnt), fontSize=7,
                     fontName="Helvetica-Bold", fillColor=col))
        y -= 13
    return d


def generate_executive_pdf(session, output_path: str = None) -> bytes:
    """Generate a one-page executive summary PDF. Returns bytes."""
    if not REPORTLAB_AVAILABLE:
        raise ImportError("reportlab not installed")

    counts  = session.severity_counts
    total   = session.total_findings
    weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
    raw     = sum(counts.get(s, 0) * w for s, w in weights.items())
    max_raw = total * 10 if total > 0 else 1
    score   = min(100, int((raw / max_raw) * 100))
    critical = counts.get("CRITICAL", 0)
    high     = counts.get("HIGH", 0)
    gen_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    risk_label = ("CRITICAL" if score >= 80 else "HIGH" if score >= 60
                  else "ELEVATED" if score >= 40 else "MODERATE" if score >= 20 else "LOW")
    risk_color = (C_CRIT if score >= 80 else C_HIGH if score >= 60
                  else C_MED if score >= 40 else C_LOW)

    # Recommendation text
    if critical > 0:
        recommendation = (
            f"IMMEDIATE ACTION REQUIRED: {critical} critical finding(s) demand same-day remediation. "
            f"Isolate affected systems if exploitation is suspected."
        )
    elif high > 0:
        recommendation = (
            f"{high} high-severity finding(s) should be remediated within 7 days. "
            f"Review and prioritise based on exposure and business impact."
        )
    else:
        recommendation = (
            "No critical or high findings detected. Address medium-severity items within 30 days "
            "as part of routine security maintenance."
        )

    # Top 3 critical findings
    top_findings = sorted(
        session.findings, key=lambda f: f.severity.sort_order
    )[:3]

    def S(name, **kwargs):
        return ParagraphStyle(name, **kwargs)

    styles = {
        "h1":    S("h1",  fontName="Helvetica-Bold", fontSize=20, textColor=C_NAVY, leading=24, spaceBefore=0, spaceAfter=4),
        "h2":    S("h2",  fontName="Helvetica-Bold", fontSize=12, textColor=C_ACCENT, leading=15, spaceBefore=10, spaceAfter=3),
        "body":  S("body",fontName="Helvetica",       fontSize=9,  textColor=colors.HexColor("#222244"), leading=13, spaceBefore=2, spaceAfter=2),
        "small": S("sm",  fontName="Helvetica",       fontSize=8,  textColor=C_MUTED,  leading=11),
        "bold":  S("bl",  fontName="Helvetica-Bold",  fontSize=9,  textColor=colors.HexColor("#222244"), leading=13),
        "center":S("ctr", fontName="Helvetica",       fontSize=8,  textColor=C_MUTED,  leading=11, alignment=TA_CENTER),
    }

    buf  = io.BytesIO()
    doc  = SimpleDocTemplate(
        buf, pagesize=A4,
        rightMargin=16*mm, leftMargin=16*mm,
        topMargin=14*mm, bottomMargin=14*mm,
        title=f"SentinelScan Executive Summary — {session.scan_id}",
    )

    story = []

    # ── TOP HEADER BAR (via Table) ────────────────────────────────────────────
    W = A4[0] - 32*mm
    header_data = [[
        Paragraph("🛡  SentinelScan", S("hdr", fontName="Helvetica-Bold",
                  fontSize=14, textColor=C_WHITE, leading=18)),
        Paragraph(f"EXECUTIVE SUMMARY", S("hdr2", fontName="Helvetica-Bold",
                  fontSize=10, textColor=C_LIGHT, leading=14, alignment=TA_RIGHT)),
    ]]
    header_tbl = Table(header_data, colWidths=[W*0.5, W*0.5])
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(-1,-1), C_NAVY),
        ("TOPPADDING",   (0,0),(-1,-1), 8), ("BOTTOMPADDING",(0,0),(-1,-1), 8),
        ("LEFTPADDING",  (0,0),(-1,-1), 12),("RIGHTPADDING", (0,0),(-1,-1), 12),
        ("VALIGN",       (0,0),(-1,-1), "MIDDLE"),
    ]))
    story.append(header_tbl)
    story.append(Spacer(1, 10))

    # ── SCAN METADATA ROW ─────────────────────────────────────────────────────
    meta_data = [[
        Paragraph(f"<b>Target:</b> {session.target}", styles["body"]),
        Paragraph(f"<b>Mode:</b> {session.mode.upper()} / {session.scan_type.upper()}", styles["body"]),
        Paragraph(f"<b>Duration:</b> {session.elapsed_seconds:.1f}s", styles["body"]),
        Paragraph(f"<b>Generated:</b> {gen_time}", styles["body"]),
    ]]
    meta_tbl = Table(meta_data, colWidths=[W*0.28]*2 + [W*0.22, W*0.22])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0,0),(-1,-1), colors.HexColor("#EEF4FA")),
        ("TOPPADDING",  (0,0),(-1,-1), 6),("BOTTOMPADDING",(0,0),(-1,-1), 6),
        ("LEFTPADDING", (0,0),(-1,-1), 8),("RIGHTPADDING", (0,0),(-1,-1), 8),
        ("GRID",        (0,0),(-1,-1), 0.5, colors.HexColor("#CCDDEE")),
        ("VALIGN",      (0,0),(-1,-1), "MIDDLE"),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 12))

    # ── RISK SCORE + CHART ROW ────────────────────────────────────────────────
    gauge_d   = _risk_arc(score, 110)
    sev_d     = _sev_mini_chart(counts, 130)

    risk_cell_content = [
        [Paragraph("RISK SCORE", S("rl", fontName="Helvetica-Bold", fontSize=8,
                   textColor=C_MUTED, leading=10, alignment=TA_CENTER))],
        [renderPDF.Drawing(gauge_d.width, gauge_d.height, gauge_d)],
        [Paragraph(risk_label, S("rl2", fontName="Helvetica-Bold", fontSize=12,
                   textColor=risk_color, leading=14, alignment=TA_CENTER))],
    ]
    sev_cell_content = [
        [Paragraph("SEVERITY BREAKDOWN", S("sl", fontName="Helvetica-Bold", fontSize=8,
                    textColor=C_MUTED, leading=10))],
        [renderPDF.Drawing(sev_d.width, sev_d.height, sev_d)],
        [Paragraph(f"<b>{total}</b> total finding(s)", S("st", fontName="Helvetica",
                   fontSize=9, textColor=C_MUTED, leading=12))],
    ]
    rec_cell_content = [
        [Paragraph("RECOMMENDATION", S("rcl", fontName="Helvetica-Bold", fontSize=8,
                    textColor=C_MUTED, leading=10))],
        [Spacer(1, 6)],
        [Paragraph(recommendation, S("rc", fontName="Helvetica", fontSize=9,
                   textColor=colors.HexColor("#1a1a2e"), leading=13))],
    ]

    risk_tbl_inner = Table(risk_cell_content, colWidths=[110])
    risk_tbl_inner.setStyle(TableStyle([
        ("ALIGN",(0,0),(-1,-1),"CENTER"), ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
    ]))
    sev_tbl_inner = Table(sev_cell_content, colWidths=[140])
    sev_tbl_inner.setStyle(TableStyle([
        ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
    ]))
    rec_tbl_inner = Table(rec_cell_content, colWidths=[W - 110 - 140 - 20])
    rec_tbl_inner.setStyle(TableStyle([
        ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
    ]))

    main_row = Table([[risk_tbl_inner, sev_tbl_inner, rec_tbl_inner]],
                      colWidths=[110, 140, W - 110 - 140 - 20])
    main_row.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(-1,-1), colors.white),
        ("BOX",          (0,0),(-1,-1), 1, colors.HexColor("#CCDDEE")),
        ("INNERGRID",    (0,0),(-1,-1), 0.5, colors.HexColor("#CCDDEE")),
        ("TOPPADDING",   (0,0),(-1,-1), 10),("BOTTOMPADDING",(0,0),(-1,-1), 10),
        ("LEFTPADDING",  (0,0),(-1,-1), 10),("RIGHTPADDING", (0,0),(-1,-1), 10),
        ("VALIGN",       (0,0),(-1,-1), "TOP"),
    ]))
    story.append(main_row)
    story.append(Spacer(1, 12))

    # ── TOP FINDINGS ──────────────────────────────────────────────────────────
    story.append(Paragraph("Priority Findings", styles["h2"]))
    story.append(HRFlowable(width=W, thickness=1, color=C_ACCENT, spaceAfter=5))

    if top_findings:
        find_data  = [["", "Finding", "Affected Component", "Remediation (summary)"]]
        for f in top_findings:
            col = SEV_C.get(f.severity.value, C_INFO)
            find_data.append([
                Paragraph(f.severity.value,
                          S("sb", fontName="Helvetica-Bold", fontSize=7,
                            textColor=C_WHITE, alignment=TA_CENTER, leading=10)),
                Paragraph(f.title[:60], S("ft", fontName="Helvetica-Bold",
                          fontSize=8.5, textColor=colors.HexColor("#1A1A2E"), leading=11)),
                Paragraph((f.affected_component or "—")[:45],
                          S("fc", fontName="Helvetica", fontSize=8, textColor=C_MUTED, leading=11)),
                Paragraph((f.remediation.splitlines()[0] if f.remediation else "—")[:60],
                          S("fr", fontName="Helvetica", fontSize=8,
                            textColor=colors.HexColor("#1A3A5C"), leading=11)),
            ])

        col_ws = [W*0.1, W*0.3, W*0.28, W*0.32]
        ft = Table(find_data, colWidths=col_ws, repeatRows=1)
        sty = [
            ("BACKGROUND",   (0,0),(-1,0), C_NAVY),
            ("TEXTCOLOR",    (0,0),(-1,0), C_WHITE),
            ("FONTNAME",     (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",     (0,0),(-1,0), 8),
            ("ALIGN",        (0,0), (0,-1), "CENTER"),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, C_ROW]),
            ("GRID",         (0,0),(-1,-1), 0.5, colors.HexColor("#CCDDEE")),
            ("TOPPADDING",   (0,0),(-1,-1), 5),("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ("LEFTPADDING",  (0,0),(-1,-1), 6),("RIGHTPADDING", (0,0),(-1,-1), 6),
            ("VALIGN",       (0,0),(-1,-1), "MIDDLE"),
        ]
        for i, f in enumerate(top_findings, 1):
            sty.append(("BACKGROUND", (0,i),(0,i), SEV_C.get(f.severity.value, C_INFO)))
        ft.setStyle(TableStyle(sty))
        story.append(ft)
    else:
        story.append(Paragraph("No findings were generated during this scan.",
                                styles["body"]))
    story.append(Spacer(1, 12))

    # ── MODULE HEALTH ─────────────────────────────────────────────────────────
    story.append(Paragraph("Scan Module Health", styles["h2"]))
    story.append(HRFlowable(width=W, thickness=1, color=C_ACCENT, spaceAfter=5))

    mods_per_row = 4
    mod_rows_data = []
    row = []
    for i, m in enumerate(session.modules):
        status = m.get("status", "?")
        sc = {"done": C_LOW, "skipped": C_INFO, "error": C_CRIT}.get(status, C_ACCENT)
        cell_content = (
            f"<b>{m.get('display_name', m.get('name','?'))[:22]}</b><br/>"
            f"<font color='#{sc.hexval()[1:]}'>{status.upper()}</font> — {m.get('finding_count',0)} finding(s)"
        )
        row.append(Paragraph(cell_content,
                              S(f"mc{i}", fontName="Helvetica", fontSize=8,
                                textColor=colors.HexColor("#1a1a2e"), leading=12)))
        if len(row) == mods_per_row:
            mod_rows_data.append(row)
            row = []
    if row:
        while len(row) < mods_per_row:
            row.append(Paragraph("", styles["body"]))
        mod_rows_data.append(row)

    if mod_rows_data:
        mod_tbl = Table(mod_rows_data, colWidths=[W / mods_per_row] * mods_per_row)
        mod_tbl.setStyle(TableStyle([
            ("ROWBACKGROUNDS",(0,0),(-1,-1), [colors.white, C_ROW]),
            ("GRID",         (0,0),(-1,-1), 0.5, colors.HexColor("#CCDDEE")),
            ("TOPPADDING",   (0,0),(-1,-1), 5),("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ("LEFTPADDING",  (0,0),(-1,-1), 8),("RIGHTPADDING", (0,0),(-1,-1), 8),
            ("VALIGN",       (0,0),(-1,-1), "TOP"),
        ]))
        story.append(mod_tbl)

    # ── FOOTER ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 14))
    story.append(HRFlowable(width=W, thickness=0.5, color=C_MUTED))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"SentinelScan v1.0  |  Scan ID: {session.scan_id}  |  "
        f"Confidential — Internal Use Only  |  {gen_time}",
        styles["center"]))

    # Build
    doc.build(story)
    result = buf.getvalue()

    if output_path:
        from pathlib import Path
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_bytes(result)

    return result
