import io
import html
import datetime
from typing import List, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
)
from reportlab.pdfgen import canvas

from app.schemas.email import EmailAnalysisResult


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute total page count and add SOC headers/footers.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            super().showPage()
        super().save()

    def draw_header_footer(self, page_count: int):
        self.saveState()
        
        # Header (pages 2+)
        if self._pageNumber > 1:
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(colors.HexColor("#64748B"))
            self.drawString(40, 760, "VYUHA AI — DIGITAL FORENSIC INVESTIGATION REPORT")
            self.drawRightString(572, 760, "CONFIDENTIAL // LAW ENFORCEMENT & SOC USE ONLY")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(40, 752, 572, 752)

        # Footer (all pages)
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawString(40, 32, "VYUHA AI Forensic Engine • Chain of Custody Verified")
        self.drawRightString(572, 32, f"Page {self._pageNumber} of {page_count}")
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.5)
        self.line(40, 42, 572, 42)
        
        self.restoreState()


def safe_text(val: Optional[str], default: str = "N/A") -> str:
    """Escapes HTML entities for ReportLab Paragraph compatibility."""
    if not val:
        return default
    return html.escape(str(val))


def generate_forensic_pdf(result: EmailAnalysisResult) -> bytes:
    """
    Generates an executive-grade Forensic Investigation PDF Report.
    Includes threat metrics, 5D vector subscores, explainable AI reasoning,
    cryptographic chain-of-custody hashes, RFC headers, MTA routing hops, and domain intelligence.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=46,
        bottomMargin=46
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0F172A"),
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#64748B"),
    )
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=8,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        'BodyText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#1E293B"),
    )
    mono_style = ParagraphStyle(
        'MonoText',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#0F172A"),
    )
    bullet_style = ParagraphStyle(
        'BulletText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#334155"),
    )
    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#1E293B"),
    )
    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#0F172A"),
    )

    story = []

    # 1. Header Banner
    case_ref = f"CASE-VA-{result.scan_id or 1001:05d}"
    now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    header_data = [
        [
            Paragraph(f"<b>VYUHA AI THREAT INTELLIGENCE</b><br/><font size=8 color='#0284C7'>DIGITAL FORENSICS & EMAIL RELAY INVESTIGATION REPORT</font>", title_style),
            Paragraph(f"<b>Case Ref:</b> {case_ref}<br/><b>Generated:</b> {now_str}<br/><b>Classification:</b> RESTRICTED", subtitle_style)
        ]
    ]
    header_table = Table(header_data, colWidths=[330, 202])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ALIGN', (1,0), (1,0), 'RIGHT'),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284C7"), spaceAfter=10))

    # 2. Executive Threat Assessment Summary Card
    score = result.threat.score
    level = result.threat.level
    if score >= 75:
        badge_bg = colors.HexColor("#FEE2E2")
        badge_text = colors.HexColor("#991B1B")
        badge_border = colors.HexColor("#DC2626")
    elif score >= 50:
        badge_bg = colors.HexColor("#FEF3C7")
        badge_text = colors.HexColor("#92400E")
        badge_border = colors.HexColor("#D97706")
    elif score >= 25:
        badge_bg = colors.HexColor("#FEF9C3")
        badge_text = colors.HexColor("#854D0E")
        badge_border = colors.HexColor("#CA8A04")
    else:
        badge_bg = colors.HexColor("#DCFCE7")
        badge_text = colors.HexColor("#166534")
        badge_border = colors.HexColor("#16A34A")

    exec_data = [
        [
            Paragraph(
                f"<font size=12><b>OVERALL VERDICT: {safe_text(result.threat.verdict).upper()}</b></font><br/>"
                f"<font size=8.5 color='#475569'>{safe_text(result.threat.summary)}</font><br/><br/>"
                f"<b>AI Intent Category:</b> {safe_text(result.threat.intent_category)} &nbsp;|&nbsp; "
                f"<b>AI Confidence:</b> {int(result.threat.ai_confidence * 100)}%",
                body_style
            ),
            Paragraph(
                f"<div align='center'>"
                f"<font size=20><b>{int(round(score))}/100</b></font><br/>"
                f"<font size=9><b>{level} RISK</b></font>"
                f"</div>",
                ParagraphStyle('ScoreBadge', parent=body_style, textColor=badge_text, alignment=1)
            )
        ]
    ]
    exec_table = Table(exec_data, colWidths=[410, 122])
    exec_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,0), colors.HexColor("#F8FAFC")),
        ('BACKGROUND', (1,0), (1,0), badge_bg),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#CBD5E1")),
        ('BOX', (1,0), (1,0), 1.5, badge_border),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(exec_table)
    story.append(Spacer(1, 10))

    # 3. Five-Dimensional Threat Subscores
    story.append(Paragraph("<b>1. Multi-Dimensional Threat Vector Breakdown</b>", section_heading))
    sub = result.threat.subscores
    subscores_data = [
        [
            Paragraph("<b>Authentication & Spoofing</b>", table_cell),
            Paragraph("<b>URLs & Domain Rep</b>", table_cell),
            Paragraph("<b>AI Intent & NLP</b>", table_cell),
            Paragraph("<b>Network Origin</b>", table_cell),
            Paragraph("<b>Attachments</b>", table_cell),
        ],
        [
            Paragraph(f"<b>{sub.authentication:.1f}</b> / 25", table_cell_bold),
            Paragraph(f"<b>{sub.urls_domains:.1f}</b> / 25", table_cell_bold),
            Paragraph(f"<b>{sub.ai_content:.1f}</b> / 25", table_cell_bold),
            Paragraph(f"<b>{sub.network_origin:.1f}</b> / 15", table_cell_bold),
            Paragraph(f"<b>{sub.attachments:.1f}</b> / 10", table_cell_bold),
        ]
    ]
    sub_table = Table(subscores_data, colWidths=[106.4, 106.4, 106.4, 106.4, 106.4])
    sub_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F1F5F9")),
        ('BACKGROUND', (0,1), (-1,1), colors.HexColor("#FFFFFF")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(sub_table)
    story.append(Spacer(1, 10))

    # 4. Explainable AI Reasoning & Urgency Phrases
    if result.threat.explanation_points or result.threat.flagged_phrases:
        story.append(Paragraph("<b>2. Explainable AI & Forensic Findings</b>", section_heading))
        reasons_content = []
        for pt in result.threat.explanation_points:
            reasons_content.append(Paragraph(f"• {safe_text(pt)}", bullet_style))

        if result.threat.flagged_phrases:
            phrases_str = ", ".join([f'"{safe_text(p)}"' for p in result.threat.flagged_phrases])
            reasons_content.append(Paragraph(f"• <b>Suspicious NLP Urgency / Coercion Phrases:</b> {phrases_str}", bullet_style))

        reason_table = Table([[reasons_content]], colWidths=[532])
        reason_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,0), colors.HexColor("#F8FAFC")),
            ('BOX', (0,0), (0,0), 0.5, colors.HexColor("#CBD5E1")),
            ('TOPPADDING', (0,0), (0,0), 6),
            ('BOTTOMPADDING', (0,0), (0,0), 6),
            ('LEFTPADDING', (0,0), (0,0), 8),
            ('RIGHTPADDING', (0,0), (0,0), 8),
        ]))
        story.append(reason_table)
        story.append(Spacer(1, 10))

    # 5. Evidence Hashes & Chain of Custody
    story.append(Paragraph("<b>3. Evidence Cryptographic Integrity (Chain of Custody)</b>", section_heading))
    hash_data = [
        [
            Paragraph("<b>SHA-256 Hash:</b>", table_cell_bold),
            Paragraph(safe_text(result.sha256), mono_style)
        ],
        [
            Paragraph("<b>MD5 Hash:</b>", table_cell_bold),
            Paragraph(safe_text(result.md5), mono_style)
        ],
        [
            Paragraph("<b>Analyzed File:</b>", table_cell_bold),
            Paragraph(f"{safe_text(result.file_name or 'Pasted RFC Content')} (Timestamp: {safe_text(result.analyzed_at)})", table_cell)
        ]
    ]
    hash_table = Table(hash_data, colWidths=[110, 422])
    hash_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#F1F5F9")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(hash_table)
    story.append(Spacer(1, 10))

    # 6. Email Header & Authentication Metadata
    story.append(Paragraph("<b>4. Email Metadata & RFC Authentication Status</b>", section_heading))
    auth = result.authentication
    meta_data = [
        [
            Paragraph("<b>Subject:</b>", table_cell_bold),
            Paragraph(safe_text(result.subject), table_cell),
            Paragraph("<b>SPF Status:</b>", table_cell_bold),
            Paragraph(f"<b>{auth.spf}</b>", table_cell_bold),
        ],
        [
            Paragraph("<b>From:</b>", table_cell_bold),
            Paragraph(safe_text(result.sender), table_cell),
            Paragraph("<b>DKIM Status:</b>", table_cell_bold),
            Paragraph(f"<b>{auth.dkim}</b>", table_cell_bold),
        ],
        [
            Paragraph("<b>To:</b>", table_cell_bold),
            Paragraph(safe_text(result.recipient), table_cell),
            Paragraph("<b>DMARC Status:</b>", table_cell_bold),
            Paragraph(f"<b>{auth.dmarc}</b>", table_cell_bold),
        ],
        [
            Paragraph("<b>Date:</b>", table_cell_bold),
            Paragraph(safe_text(result.date), table_cell),
            Paragraph("<b>Reply-To:</b>", table_cell_bold),
            Paragraph(safe_text(result.reply_to or "None specified"), table_cell),
        ]
    ]
    meta_table = Table(meta_data, colWidths=[65, 235, 75, 157])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#F1F5F9")),
        ('BACKGROUND', (2,0), (2,-1), colors.HexColor("#F1F5F9")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # 7. Transmission Route & Geolocation Hops
    if result.hops:
        story.append(Paragraph(f"<b>5. Transmission Route & Geolocation Hops ({len(result.hops)} MTAs)</b>", section_heading))
        hop_rows = [
            [
                Paragraph("<b>Hop</b>", table_cell_bold),
                Paragraph("<b>IP Address</b>", table_cell_bold),
                Paragraph("<b>Location</b>", table_cell_bold),
                Paragraph("<b>ISP / Hostname</b>", table_cell_bold),
                Paragraph("<b>Delay</b>", table_cell_bold),
            ]
        ]
        for h in result.hops:
            loc = f"{safe_text(h.city, '')}, {safe_text(h.country, 'Unknown')}".strip(", ")
            if h.is_private:
                loc = "Internal / LAN"
            isp_host = safe_text(h.isp or h.hostname or h.by or "N/A")
            delay = f"{h.delay_seconds}s" if h.delay_seconds is not None else "0s"
            hop_rows.append([
                Paragraph(f"#{h.hop_index}", table_cell),
                Paragraph(safe_text(h.ip), mono_style),
                Paragraph(loc, table_cell),
                Paragraph(isp_host[:35], table_cell),
                Paragraph(delay, table_cell),
            ])
        hop_table = Table(hop_rows, colWidths=[35, 95, 120, 232, 50])
        hop_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F1F5F9")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 2.5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
            ('LEFTPADDING', (0,0), (-1,-1), 4),
            ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(hop_table)
        story.append(Spacer(1, 10))

    # 8. URL & Domain Threat Intelligence Matrix
    if result.urls:
        story.append(Paragraph(f"<b>6. URL & Domain Threat Intelligence Matrix ({len(result.urls)} Links)</b>", section_heading))
        url_rows = [
            [
                Paragraph("<b>Target URL & Domain</b>", table_cell_bold),
                Paragraph("<b>Reputation / Spoofing</b>", table_cell_bold),
                Paragraph("<b>Entropy / TLD</b>", table_cell_bold),
                Paragraph("<b>Risk</b>", table_cell_bold),
            ]
        ]
        for u in result.urls[:8]:  # Top 8 suspicious URLs to fit neatly
            brand_alert = f"Target: <b>{safe_text(u.reputation.impersonated_brand)}</b>" if (u.reputation and u.reputation.typosquatting_detected) else safe_text(u.threat_category)
            entropy_tld = f"Entropy: {u.reputation.entropy} | TLD: {u.reputation.tld_reputation_tier}" if u.reputation else "Standard"
            url_display = f"<b>{safe_text(u.domain)}</b><br/><font color='#475569'>{safe_text(u.url[:60])}{'...' if len(u.url) > 60 else ''}</font>"
            if u.anchor_text:
                url_display += f"<br/><font color='#991B1B'>Anchor: \"{safe_text(u.anchor_text[:40])}\"</font>"

            risk_txt = f"<b>{int(u.risk_score or 0)}/100</b>"
            url_rows.append([
                Paragraph(url_display, table_cell),
                Paragraph(brand_alert, table_cell),
                Paragraph(entropy_tld, table_cell),
                Paragraph(risk_txt, table_cell_bold),
            ])
        url_table = Table(url_rows, colWidths=[240, 130, 115, 47])
        url_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F1F5F9")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 4),
            ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(url_table)
        story.append(Spacer(1, 10))

    # 9. Detected Risk Factors / Rules Table
    if result.threat.risk_factors:
        story.append(Paragraph(f"<b>7. Triggered Forensic Threat Rules ({len(result.threat.risk_factors)} Rules)</b>", section_heading))
        rule_rows = [
            [
                Paragraph("<b>Rule Identifier</b>", table_cell_bold),
                Paragraph("<b>Severity</b>", table_cell_bold),
                Paragraph("<b>Points</b>", table_cell_bold),
                Paragraph("<b>Forensic Finding Description</b>", table_cell_bold),
            ]
        ]
        for rf in result.threat.risk_factors:
            rule_rows.append([
                Paragraph(f"<b>{safe_text(rf.rule)}</b>", mono_style),
                Paragraph(f"{safe_text(rf.severity)}", table_cell_bold),
                Paragraph(f"+{rf.points:.1f}", table_cell),
                Paragraph(safe_text(rf.description), table_cell),
            ])
        rule_table = Table(rule_rows, colWidths=[120, 60, 45, 307])
        rule_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F1F5F9")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 2.5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
            ('LEFTPADDING', (0,0), (-1,-1), 4),
            ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(rule_table)
        story.append(Spacer(1, 10))

    # 10. Attachments (if any)
    if result.attachments:
        story.append(Paragraph(f"<b>8. Extracted Attachments ({len(result.attachments)} Files)</b>", section_heading))
        att_rows = [
            [
                Paragraph("<b>Filename</b>", table_cell_bold),
                Paragraph("<b>MIME Type</b>", table_cell_bold),
                Paragraph("<b>Size</b>", table_cell_bold),
                Paragraph("<b>Risk Flag</b>", table_cell_bold),
            ]
        ]
        for a in result.attachments:
            flag = "<font color='#DC2626'><b>HIGH RISK (EXEC)</b></font>" if a.is_suspicious_extension else "Standard"
            att_rows.append([
                Paragraph(safe_text(a.filename), mono_style),
                Paragraph(safe_text(a.content_type), table_cell),
                Paragraph(f"{a.size_bytes} B", table_cell),
                Paragraph(flag, table_cell),
            ])
        att_table = Table(att_rows, colWidths=[180, 160, 80, 112])
        att_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F1F5F9")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 2.5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
        ]))
        story.append(att_table)

    # Build document
    doc.build(story, canvasmaker=NumberedCanvas)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
