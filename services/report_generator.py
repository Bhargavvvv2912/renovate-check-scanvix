"""
services/report_generator.py
============================
Professional PDF Security Assessment Report Generator using ReportLab.
Generates comprehensive technical reports from real database entities
for ScanVix network vulnerability and service enumeration scans.
"""

import os
import logging
from datetime import datetime
from flask import current_app

from reportlab.lib.pagesizes import letter
from reportlab.lib.colors import HexColor, white, black, transparent
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    HRFlowable
)
from reportlab.pdfgen import canvas

from models import db, Scan, Host, Port, NSEResult, Finding, Report
from services.scan_profiles import get_profile_by_id

logger = logging.getLogger(__name__)

# Maximum allowed PDF report file size (25 MB)
MAX_REPORT_FILE_SIZE = 25 * 1024 * 1024

class ReportError(Exception):
    """Base exception for report operations."""
    pass

class ReportSecurityError(ReportError):
    """Raised when report file security validations or path checks fail."""
    pass

def validate_report_file(report_path: str, allowed_base_dir: str = None) -> str:
    """
    Validates report file existence, canonicalization, directory boundary (path traversal),
    and file size limit. Returns canonicalized absolute path.
    """
    if not report_path or not isinstance(report_path, str):
        raise ReportSecurityError("A valid report filepath must be provided.")

    abs_path = os.path.abspath(report_path)

    if allowed_base_dir:
        abs_base = os.path.abspath(allowed_base_dir)
        try:
            common = os.path.commonpath([abs_base, abs_path])
            if common != abs_base:
                raise ReportSecurityError(f"Access denied: Report path '{abs_path}' is outside designated storage '{abs_base}'.")
        except ValueError:
            raise ReportSecurityError(f"Access denied: Report path '{abs_path}' is outside designated storage '{abs_base}'.")

    if not os.path.exists(abs_path):
        raise ReportSecurityError(f"Report file not found at: {abs_path}")

    if not os.path.isfile(abs_path):
        raise ReportSecurityError(f"Specified report path is not a regular file: {abs_path}")

    file_size = os.path.getsize(abs_path)
    if file_size > MAX_REPORT_FILE_SIZE:
        raise ReportSecurityError(f"Report file size ({file_size} bytes) exceeds limit of {MAX_REPORT_FILE_SIZE} bytes.")

    return abs_path


# ---------------------------------------------------------------------------
#  Color Palette (Strict light theme SaaS, professional blue, no purple/neon)
# ---------------------------------------------------------------------------
NAVY_HEADER = HexColor("#0F172A")
PRIMARY_BLUE = HexColor("#1E40AF")
ACCENT_BLUE = HexColor("#2563EB")
SLATE_BODY = HexColor("#334155")
MUTED_GRAY = HexColor("#64748B")
LIGHT_BG = HexColor("#F8FAFC")
BORDER_COLOR = HexColor("#E2E8F0")
ALT_ROW_BG = HexColor("#F1F5F9")

# Severity Colors
SEV_HIGH = HexColor("#EF4444")
SEV_HIGH_BG = HexColor("#FEE2E2")
SEV_MEDIUM = HexColor("#F59E0B")
SEV_MEDIUM_BG = HexColor("#FEF3C7")
SEV_LOW = HexColor("#EAB308")
SEV_LOW_BG = HexColor("#FEF9C3")
SEV_INFO = HexColor("#3B82F6")
SEV_INFO_BG = HexColor("#DBEAFE")
SEV_SUCCESS = HexColor("#10B981")
SEV_SUCCESS_BG = HexColor("#D1FAE5")


# ---------------------------------------------------------------------------
#  Custom Numbered Canvas (Two-pass "Page X of Y" + Running Header/Footer)
# ---------------------------------------------------------------------------
class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that computes total pages dynamically and renders
    professional running headers and footers. Suppressed on cover page.
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

    def draw_header_footer(self, total_pages):
        if self._pageNumber == 1:
            return  # Suppress on Cover Page

        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(MUTED_GRAY)

        # Running Header (top)
        self.drawString(36, 756, "ScanVix — Network Security Assessment Report")
        self.drawRightString(576, 756, "Confidential Security Audit")
        self.setStrokeColor(BORDER_COLOR)
        self.setLineWidth(0.5)
        self.line(36, 750, 576, 750)

        # Running Footer (bottom)
        self.line(36, 42, 576, 42)
        self.drawString(36, 30, "ScanVix Assessment Report | Authorized Lab Documentation")
        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.drawRightString(576, 30, page_str)

        self.restoreState()


# ---------------------------------------------------------------------------
#  Safe Text Escaper for ReportLab Paragraphs
# ---------------------------------------------------------------------------
def safe_escape(text):
    """Escapes XML entities so arbitrary text does not break ReportLab XML parser."""
    if text is None:
        return ""
    s = str(text)
    return (
        s.replace('&', '&amp;')
         .replace('<', '&lt;')
         .replace('>', '&gt;')
         .replace('"', '&quot;')
         .replace("'", '&apos;')
    )


def safe_code_text(text, max_len=4000):
    """Formats plain code / evidence text for ReportLab Paragraphs."""
    if not text:
        return "—"
    s = str(text).strip()
    if max_len and len(s) > max_len:
        s = s[:max_len] + "\n... [Content Truncated for PDF Layout]"
    escaped = safe_escape(s)
    return escaped.replace('\n', '<br/>').replace(' ', '&nbsp;')


# ---------------------------------------------------------------------------
#  Report Generation Core
# ---------------------------------------------------------------------------
from flask import current_app, has_app_context

def generate_pdf_report(scan_id, app=None):
    """
    Generates a professional PDF Security Assessment Report for a completed scan.
    
    Args:
        scan_id (int): Database ID of the Scan.
        app: Optional Flask application context.
        
    Returns:
        tuple: (Report object, error_message or None)
    """
    ctx = None
    if app and not has_app_context():
        ctx = app.app_context()
        ctx.push()

    try:
        scan = db.session.get(Scan, scan_id)
        if not scan:
            logger.error(f"Cannot generate report: Scan #{scan_id} not found.")
            return None, "Scan record not found."

        if scan.status != 'completed':
            logger.warning(f"Scan #{scan_id} is not completed (status={scan.status}).")
            return None, f"Scan must be in 'completed' status to generate report. Current: {scan.status}"

        # Fetch scan profile details
        profile = get_profile_by_id(scan.scan_profile)
        profile_name = profile['name'] if profile else scan.scan_profile.replace('_', ' ').title()

        # Eagerly load all child entities
        hosts = Host.query.filter_by(scan_id=scan.id).all()
        nse_results = NSEResult.query.filter_by(scan_id=scan.id).all()
        findings = Finding.query.filter_by(scan_id=scan.id).all()

        # Gather ports across hosts
        all_ports = []
        for h in hosts:
            for p in h.ports:
                all_ports.append({
                    'host_ip': h.ip_address,
                    'hostname': h.hostname or '—',
                    'port_number': p.port_number,
                    'protocol': p.protocol.upper(),
                    'state': p.state.upper(),
                    'service': p.service or 'unknown',
                    'product': p.product or '—',
                    'version': p.version or '—',
                    'extra_info': p.extra_info or '—'
                })

        # Calculate statistics
        open_ports_count = sum(1 for p in all_ports if p['state'] == 'OPEN')
        closed_ports_count = sum(1 for p in all_ports if p['state'] == 'CLOSED')
        filtered_ports_count = sum(1 for p in all_ports if p['state'] == 'FILTERED')
        unique_services = len(set(p['service'] for p in all_ports if p['service'] != 'unknown'))
        hosts_up_count = sum(1 for h in hosts if h.state == 'up')

        # Findings breakdown by severity
        findings_high = [f for f in findings if f.severity.lower() == 'high']
        findings_medium = [f for f in findings if f.severity.lower() == 'medium']
        findings_low = [f for f in findings if f.severity.lower() == 'low']
        findings_info = [f for f in findings if f.severity.lower() == 'info']

        # Determine target file destination
        reports_base_dir = current_app.config.get('REPORTS_FOLDER', os.path.join(current_app.root_path, 'reports'))
        scan_reports_dir = os.path.join(reports_base_dir, f"scan_{scan.id}")
        os.makedirs(scan_reports_dir, exist_ok=True)

        filename = f"scanvix_report_{scan.id}.pdf"
        file_full_path = os.path.join(scan_reports_dir, filename)

        # -------------------------------------------------------------------
        #  ReportLab Styles Setup
        # -------------------------------------------------------------------
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'CoverTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=24,
            leading=28,
            textColor=NAVY_HEADER,
            alignment=0,
            spaceAfter=8
        )
        subtitle_style = ParagraphStyle(
            'CoverSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=13,
            leading=16,
            textColor=ACCENT_BLUE,
            alignment=0,
            spaceAfter=20
        )
        section_heading_style = ParagraphStyle(
            'SectionHeading',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=13,
            leading=16,
            textColor=NAVY_HEADER,
            spaceBefore=14,
            spaceAfter=8,
            keepWithNext=True
        )
        subsection_heading_style = ParagraphStyle(
            'SubSectionHeading',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=10.5,
            leading=13,
            textColor=PRIMARY_BLUE,
            spaceBefore=10,
            spaceAfter=4,
            keepWithNext=True
        )
        body_style = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8.5,
            leading=12,
            textColor=SLATE_BODY,
            spaceAfter=6
        )
        body_bold = ParagraphStyle(
            'ReportBodyBold',
            parent=body_style,
            fontName='Helvetica-Bold',
            textColor=NAVY_HEADER
        )
        code_style = ParagraphStyle(
            'ReportCode',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=7.5,
            leading=9.5,
            textColor=HexColor("#1E293B")
        )
        table_hdr_style = ParagraphStyle(
            'TableHdr',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8,
            leading=10,
            textColor=white,
            alignment=0
        )
        table_cell_style = ParagraphStyle(
            'TableCell',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=7.5,
            leading=10,
            textColor=SLATE_BODY
        )
        table_cell_bold = ParagraphStyle(
            'TableCellBold',
            parent=table_cell_style,
            fontName='Helvetica-Bold',
            textColor=NAVY_HEADER
        )
        table_cell_code = ParagraphStyle(
            'TableCellCode',
            parent=table_cell_style,
            fontName='Courier',
            fontSize=7.5,
            leading=9.5,
            textColor=HexColor("#1E293B")
        )

        # -------------------------------------------------------------------
        #  Assemble Document Story (Platypus Flowables)
        # -------------------------------------------------------------------
        story = []
        usable_width = 540  # 612 - 72 (margins)

        # ===================================================================
        #  PAGE 1: COVER PAGE
        # ===================================================================
        story.append(Spacer(1, 20))

        # Brand Badge & Logo Header
        brand_html = (
            f'<font color="{ACCENT_BLUE.hexval()}"><b>SCANVIX</b></font> '
            f'<font color="{MUTED_GRAY.hexval()}">| NETWORK SECURITY ASSESSMENT PLATFORM</font>'
        )
        story.append(Paragraph(brand_html, ParagraphStyle('Brand', parent=body_style, fontSize=9, leading=11)))
        story.append(Spacer(1, 15))
        story.append(HRFlowable(width="100%", thickness=2, color=PRIMARY_BLUE, spaceBefore=0, spaceAfter=20))

        # Document Title & Subtitle
        story.append(Paragraph("SECURITY ASSESSMENT REPORT", title_style))
        story.append(Paragraph("Automated Network Service Enumeration &amp; Vulnerability Posture Documentation", subtitle_style))
        story.append(Spacer(1, 15))

        # Target Overview Card Table
        start_str = scan.start_time.strftime('%B %d, %Y at %I:%M:%S %p UTC') if scan.start_time else 'N/A'
        duration_str = f"{scan.duration:.2f} seconds" if scan.duration else "—"

        meta_data = [
            [Paragraph("<b>Target Host / Network:</b>", table_cell_bold), Paragraph(f'<font color="{ACCENT_BLUE.hexval()}"><b>{safe_escape(scan.target)}</b></font>', table_cell_bold)],
            [Paragraph("<b>Scan Profile:</b>", table_cell_bold), Paragraph(safe_escape(profile_name), table_cell_style)],
            [Paragraph("<b>Scan ID:</b>", table_cell_bold), Paragraph(f"#{scan.id}", table_cell_code)],
            [Paragraph("<b>Assessment Date:</b>", table_cell_bold), Paragraph(start_str, table_cell_style)],
            [Paragraph("<b>Execution Duration:</b>", table_cell_bold), Paragraph(duration_str, table_cell_style)],
            [Paragraph("<b>Execution Status:</b>", table_cell_bold), Paragraph(f'<font color="{SEV_SUCCESS.hexval()}"><b>{scan.status.upper()}</b></font>', table_cell_bold)],
            [Paragraph("<b>Assessment Type:</b>", table_cell_bold), Paragraph("Authorized Internal Infrastructure Audit", table_cell_style)],
        ]
        meta_table = Table(meta_data, colWidths=[150, usable_width - 150])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 20))

        # Executive Metrics Summary Block on Cover
        exec_metric_data = [
            [
                Paragraph(f"<font size=14 color='{NAVY_HEADER.hexval()}'><b>{len(hosts)}</b></font><br/><font size=7 color='{MUTED_GRAY.hexval()}'>HOSTS DISCOVERED</font>", table_cell_style),
                Paragraph(f"<font size=14 color='{SEV_SUCCESS.hexval()}'><b>{open_ports_count}</b></font><br/><font size=7 color='{MUTED_GRAY.hexval()}'>OPEN PORTS</font>", table_cell_style),
                Paragraph(f"<font size=14 color='{ACCENT_BLUE.hexval()}'><b>{unique_services}</b></font><br/><font size=7 color='{MUTED_GRAY.hexval()}'>SERVICES IDENTIFIED</font>", table_cell_style),
                Paragraph(f"<font size=14 color='{PRIMARY_BLUE.hexval()}'><b>{len(nse_results)}</b></font><br/><font size=7 color='{MUTED_GRAY.hexval()}'>NSE RESULTS</font>", table_cell_style),
                Paragraph(f"<font size=14 color='{SEV_HIGH.hexval() if len(findings) > 0 else MUTED_GRAY.hexval()}'><b>{len(findings)}</b></font><br/><font size=7 color='{MUTED_GRAY.hexval()}'>TOTAL FINDINGS</font>", table_cell_style),
            ]
        ]
        exec_table = Table(exec_metric_data, colWidths=[usable_width / 5] * 5)
        exec_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), white),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(exec_table)
        story.append(Spacer(1, 35))

        # Disclaimer Box
        disclaimer_text = (
            "<b>SECURITY &amp; USAGE DISCLAIMER:</b> "
            "This report is generated from the scan data collected by ScanVix and is intended for authorized "
            "security assessment and educational use. Findings should be validated in the appropriate environment "
            "before remediation or operational decisions are made. This document does not constitute an external "
            "certified penetration test certification."
        )
        disc_table = Table([[Paragraph(disclaimer_text, ParagraphStyle('Disc', parent=body_style, fontSize=7.5, leading=10, textColor=MUTED_GRAY))]], colWidths=[usable_width])
        disc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
            ('BOX', (0, 0), (-1, -1), 0.75, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(disc_table)

        # Page Break after Cover Page
        story.append(PageBreak())

        # ===================================================================
        #  SECTION 1: EXECUTIVE SUMMARY
        # ===================================================================
        story.append(Paragraph("1. Executive Summary", section_heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY_BLUE, spaceBefore=2, spaceAfter=8))

        exec_narrative = (
            f"This security assessment report summarizes the results of an automated vulnerability and service "
            f"enumeration assessment executed against target <b>{safe_escape(scan.target)}</b> on {start_str}. "
            f"The scan was performed using the <b>{safe_escape(profile_name)}</b> predefined profile under "
            f"authorized conditions. During the assessment, <b>{len(hosts)}</b> host(s) were analyzed, "
            f"identifying <b>{open_ports_count}</b> open port(s) across <b>{unique_services}</b> unique service(s). "
            f"A total of <b>{len(findings)}</b> security observation(s) were generated based on service configurations "
            f"and automated Nmap Scripting Engine (NSE) evaluations."
        )
        story.append(Paragraph(exec_narrative, body_style))
        story.append(Spacer(1, 6))

        # Severity Summary Table
        story.append(Paragraph("Security Findings Severity Distribution", subsection_heading_style))
        sev_table_data = [
            [Paragraph("Severity", table_hdr_style), Paragraph("Count", table_hdr_style), Paragraph("Description &amp; Priority", table_hdr_style)],
            [
                Paragraph(f'<font color="{SEV_HIGH.hexval()}"><b>HIGH</b></font>', table_cell_bold),
                Paragraph(str(len(findings_high)), table_cell_bold),
                Paragraph("Critical service misconfigurations or highly vulnerable services requiring immediate remediation.", table_cell_style)
            ],
            [
                Paragraph(f'<font color="{SEV_MEDIUM.hexval()}"><b>MEDIUM</b></font>', table_cell_bold),
                Paragraph(str(len(findings_medium)), table_cell_bold),
                Paragraph("Cleartext protocol exposure, legacy versions, or missing security controls requiring planned action.", table_cell_style)
            ],
            [
                Paragraph(f'<font color="{SEV_LOW.hexval()}"><b>LOW</b></font>', table_cell_bold),
                Paragraph(str(len(findings_low)), table_cell_bold),
                Paragraph("Minor security observation, default configuration, or hardening recommendation.", table_cell_style)
            ],
            [
                Paragraph(f'<font color="{SEV_INFO.hexval()}"><b>INFO</b></font>', table_cell_bold),
                Paragraph(str(len(findings_info)), table_cell_bold),
                Paragraph("Informational security posture item or discovered service observation.", table_cell_style)
            ],
            [
                Paragraph("<b>TOTAL</b>", table_cell_bold),
                Paragraph(f"<b>{len(findings)}</b>", table_cell_bold),
                Paragraph("Total security findings recorded for this assessment.", table_cell_bold)
            ]
        ]
        sev_table = Table(sev_table_data, colWidths=[70, 50, usable_width - 120])
        sev_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_BLUE),
            ('BOX', (0, 0), (-1, -1), 0.75, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('BACKGROUND', (0, -1), (-1, -1), ALT_ROW_BG),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 12))

        # ===================================================================
        #  SECTION 2: ASSESSMENT INFORMATION & SCAN CONFIGURATION
        # ===================================================================
        story.append(Paragraph("2. Assessment Information &amp; Scope", section_heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY_BLUE, spaceBefore=2, spaceAfter=8))

        scan_info_data = [
            [Paragraph("Target Specification", table_cell_bold), Paragraph(safe_escape(scan.target), table_cell_style), Paragraph("Scan Profile", table_cell_bold), Paragraph(safe_escape(profile_name), table_cell_style)],
            [Paragraph("Scan Database ID", table_cell_bold), Paragraph(f"#{scan.id}", table_cell_code), Paragraph("Execution Status", table_cell_bold), Paragraph(scan.status.upper(), table_cell_bold)],
            [Paragraph("Start Timestamp", table_cell_bold), Paragraph(start_str, table_cell_style), Paragraph("Duration", table_cell_bold), Paragraph(duration_str, table_cell_style)],
            [Paragraph("Scan Engine", table_cell_bold), Paragraph("Nmap + NSE Script Engine", table_cell_style), Paragraph("Scanner Mode", table_cell_bold), Paragraph("Safe Controlled Laboratory Scan", table_cell_style)],
        ]
        scan_info_table = Table(scan_info_data, colWidths=[110, 160, 110, usable_width - 380])
        scan_info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
            ('BOX', (0, 0), (-1, -1), 0.75, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(scan_info_table)
        story.append(Spacer(1, 12))

        # ===================================================================
        #  SECTION 3: SCAN STATISTICS
        # ===================================================================
        story.append(Paragraph("3. Scan Statistics", section_heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY_BLUE, spaceBefore=2, spaceAfter=8))

        stats_data = [
            [Paragraph("Metric", table_hdr_style), Paragraph("Observed Value", table_hdr_style), Paragraph("Notes &amp; Scope", table_hdr_style)],
            [Paragraph("Hosts Discovered", table_cell_style), Paragraph(str(len(hosts)), table_cell_bold), Paragraph("Total unique targets recognized in scope", table_cell_style)],
            [Paragraph("Hosts Up (Responsive)", table_cell_style), Paragraph(str(hosts_up_count), table_cell_bold), Paragraph("Active targets responding to ICMP/TCP probes", table_cell_style)],
            [Paragraph("Open Ports", table_cell_style), Paragraph(str(open_ports_count), table_cell_bold), Paragraph("Listening ports actively accepting connections", table_cell_style)],
            [Paragraph("Closed Ports", table_cell_style), Paragraph(str(closed_ports_count), table_cell_style), Paragraph("Ports confirmed closed via RST response", table_cell_style)],
            [Paragraph("Filtered Ports", table_cell_style), Paragraph(str(filtered_ports_count), table_cell_style), Paragraph("Ports protected or blocked by firewall/filter", table_cell_style)],
            [Paragraph("Unique Services Identified", table_cell_style), Paragraph(str(unique_services), table_cell_bold), Paragraph("Distinct application services classified", table_cell_style)],
            [Paragraph("NSE Scripts Executed", table_cell_style), Paragraph(str(len(nse_results)), table_cell_bold), Paragraph("Nmap Scripting Engine security checks", table_cell_style)],
            [Paragraph("Security Findings Generated", table_cell_style), Paragraph(str(len(findings)), table_cell_bold), Paragraph("Rule-based vulnerability and risk observations", table_cell_style)],
        ]
        stats_table = Table(stats_data, colWidths=[150, 90, usable_width - 240])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_BLUE),
            ('BOX', (0, 0), (-1, -1), 0.75, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, ALT_ROW_BG]),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 12))

        # ===================================================================
        #  SECTION 4: HOSTS DISCOVERED
        # ===================================================================
        story.append(Paragraph("4. Hosts Discovered", section_heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY_BLUE, spaceBefore=2, spaceAfter=8))

        if hosts:
            host_table_data = [
                [Paragraph("IP Address", table_hdr_style), Paragraph("Hostname", table_hdr_style), Paragraph("State", table_hdr_style), Paragraph("OS Detection", table_hdr_style), Paragraph("Ports", table_hdr_style)]
            ]
            for h in hosts:
                open_cnt = sum(1 for p in h.ports if p.state.lower() == 'open')
                os_info = h.os_information if h.os_information else "Not Detected"
                host_table_data.append([
                    Paragraph(safe_escape(h.ip_address), table_cell_code),
                    Paragraph(safe_escape(h.hostname or '—'), table_cell_style),
                    Paragraph(f'<font color="{SEV_SUCCESS.hexval() if h.state == "up" else MUTED_GRAY.hexval()}"><b>{h.state.upper()}</b></font>', table_cell_style),
                    Paragraph(safe_escape(os_info), table_cell_style),
                    Paragraph(f"{open_cnt} open / {len(h.ports)} total", table_cell_style)
                ])

            host_table = Table(host_table_data, colWidths=[100, 110, 50, 180, usable_width - 440], repeatRows=1)
            host_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_BLUE),
                ('BOX', (0, 0), (-1, -1), 0.75, BORDER_COLOR),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, ALT_ROW_BG]),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('LEFTPADDING', (0, 0), (-1, -1), 5),
                ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(host_table)
        else:
            story.append(Paragraph("<i>No active hosts were discovered during this assessment.</i>", body_style))

        story.append(Spacer(1, 12))

        # ===================================================================
        #  SECTION 5: PORTS AND SERVICES INVENTORY
        # ===================================================================
        story.append(Paragraph("5. Ports and Services Inventory", section_heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY_BLUE, spaceBefore=2, spaceAfter=8))

        if all_ports:
            port_table_data = [
                [Paragraph("Host", table_hdr_style), Paragraph("Port", table_hdr_style), Paragraph("Proto", table_hdr_style), Paragraph("State", table_hdr_style), Paragraph("Service", table_hdr_style), Paragraph("Product / Version", table_hdr_style)]
            ]
            for p in all_ports:
                state_color = SEV_SUCCESS.hexval() if p['state'] == 'OPEN' else (MUTED_GRAY.hexval() if p['state'] == 'CLOSED' else SEV_MEDIUM.hexval())
                prod_ver = f"{safe_escape(p['product'])}" if p['product'] != '—' else ""
                if p['version'] != '—':
                    prod_ver += f" {safe_escape(p['version'])}"
                if not prod_ver:
                    prod_ver = "—"

                port_table_data.append([
                    Paragraph(safe_escape(p['host_ip']), table_cell_code),
                    Paragraph(str(p['port_number']), table_cell_bold),
                    Paragraph(p['protocol'], table_cell_style),
                    Paragraph(f'<font color="{state_color}"><b>{p["state"]}</b></font>', table_cell_style),
                    Paragraph(safe_escape(p['service']), table_cell_style),
                    Paragraph(prod_ver, table_cell_style)
                ])

            port_table = Table(port_table_data, colWidths=[90, 45, 45, 50, 90, usable_width - 320], repeatRows=1)
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_BLUE),
                ('BOX', (0, 0), (-1, -1), 0.75, BORDER_COLOR),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, ALT_ROW_BG]),
                ('TOPPADDING', (0, 0), (-1, -1), 3.5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
                ('LEFTPADDING', (0, 0), (-1, -1), 5),
                ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(port_table)
            story.append(Spacer(1, 8))

            # Service Distribution Summary Sub-table
            service_counts = {}
            for p in all_ports:
                if p['state'] == 'OPEN':
                    s_name = p['service'] or 'unknown'
                    service_counts[s_name] = service_counts.get(s_name, 0) + 1

            if service_counts:
                story.append(Paragraph("Service Distribution Summary", subsection_heading_style))
                svc_sum_data = [[Paragraph("Identified Service", table_hdr_style), Paragraph("Open Instances", table_hdr_style)]]
                for s_name, count in sorted(service_counts.items(), key=lambda x: x[1], reverse=True):
                    svc_sum_data.append([
                        Paragraph(safe_escape(s_name), table_cell_style),
                        Paragraph(str(count), table_cell_bold)
                    ])

                svc_sum_table = Table(svc_sum_data, colWidths=[180, 80])
                svc_sum_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_BLUE),
                    ('BOX', (0, 0), (-1, -1), 0.75, BORDER_COLOR),
                    ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, ALT_ROW_BG]),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(svc_sum_table)
        else:
            story.append(Paragraph("<i>No services were identified.</i>", body_style))

        story.append(Spacer(1, 12))

        # ===================================================================
        #  SECTION 6: NSE RESULTS
        # ===================================================================
        story.append(Paragraph("6. Nmap Scripting Engine (NSE) Results", section_heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY_BLUE, spaceBefore=2, spaceAfter=8))

        if nse_results:
            for n in nse_results:
                host_ip = n.host.ip_address if n.host else (scan.target or '—')
                port_disp = f"Port {n.port_number}" if n.port_number else "Host Level"
                svc_disp = f"({safe_escape(n.service)})" if n.service else ""
                
                script_box_data = [
                    [
                        Paragraph(f"<b>Script:</b> <font color='{PRIMARY_BLUE.hexval()}'><b>{safe_escape(n.script_id)}</b></font>", table_cell_bold),
                        Paragraph(f"<b>Target:</b> {safe_escape(host_ip)} · {port_disp} {svc_disp}", table_cell_style),
                        Paragraph(f"<b>Status:</b> {n.status.upper() if n.status else 'COMPLETED'}", table_cell_bold)
                    ]
                ]
                if n.description:
                    script_box_data.append([
                        Paragraph(f"<b>Description:</b> {safe_escape(n.description)}", table_cell_style),
                        Paragraph("", table_cell_style),
                        Paragraph("", table_cell_style)
                    ])

                raw_output = safe_code_text(n.output, max_len=1500)
                script_box_data.append([
                    Paragraph(f"<b>Raw Output:</b><br/>{raw_output}", code_style),
                    Paragraph("", code_style),
                    Paragraph("", code_style)
                ])

                script_table = Table(script_box_data, colWidths=[180, 240, usable_width - 420])
                script_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
                    ('BOX', (0, 0), (-1, -1), 0.75, BORDER_COLOR),
                    ('SPAN', (0, 1), (-1, 1)) if len(script_box_data) > 2 else ('SPAN', (0, 0), (0, 0)),
                    ('SPAN', (0, 2), (-1, 2)) if len(script_box_data) > 2 else ('SPAN', (0, 1), (-1, 1)),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(KeepTogether([script_table, Spacer(1, 6)]))
        else:
            story.append(Paragraph("<i>No NSE results were generated for this scan.</i>", body_style))

        story.append(Spacer(1, 12))

        # ===================================================================
        #  SECTION 7: SECURITY FINDINGS
        # ===================================================================
        story.append(Paragraph("7. Security Findings &amp; Observations", section_heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY_BLUE, spaceBefore=2, spaceAfter=8))

        if findings:
            for idx, f in enumerate(findings, 1):
                sev_upper = (f.severity or 'info').upper()
                if sev_upper == 'HIGH':
                    badge_color = SEV_HIGH.hexval()
                    badge_bg = SEV_HIGH_BG
                elif sev_upper == 'MEDIUM':
                    badge_color = SEV_MEDIUM.hexval()
                    badge_bg = SEV_MEDIUM_BG
                elif sev_upper == 'LOW':
                    badge_color = SEV_LOW.hexval()
                    badge_bg = SEV_LOW_BG
                else:
                    badge_color = SEV_INFO.hexval()
                    badge_bg = SEV_INFO_BG

                target_host_ip = f.host.ip_address if f.host else scan.target
                port_str = f"{f.port.port_number}/{f.port.protocol} ({f.port.service})" if f.port else "Host-Level"
                obs_type = f.observation_type or f.classification or "OBSERVED"
                conf_str = f.confidence or "HIGH"

                finding_card_data = [
                    # Header Row
                    [
                        Paragraph(f"<b>Finding #{idx}: {safe_escape(f.title)}</b>", table_cell_bold),
                        Paragraph(f"<font color='{badge_color}'><b>[{sev_upper}]</b></font>", table_cell_bold)
                    ],
                    # Metadata Row
                    [
                        Paragraph(
                            f"<b>Rule ID:</b> {safe_escape(f.rule_id or '—')} &nbsp;|&nbsp; "
                            f"<b>Category:</b> {safe_escape(f.category or 'General')} &nbsp;|&nbsp; "
                            f"<b>Target:</b> {safe_escape(target_host_ip)} ({port_str})",
                            table_cell_style
                        ),
                        Paragraph(
                            f"<b>Observation:</b> {safe_escape(obs_type)}<br/><b>Confidence:</b> {safe_escape(conf_str)}",
                            table_cell_style
                        )
                    ],
                    # Description
                    [
                        Paragraph(f"<b>Description:</b><br/>{safe_escape(f.description or 'No description provided.')}", table_cell_style),
                        Paragraph("", table_cell_style)
                    ]
                ]

                # Evidence block
                if f.evidence:
                    ev_text = safe_code_text(f.evidence, max_len=1200)
                    finding_card_data.append([
                        Paragraph(f"<b>Evidence:</b><br/>{ev_text}", code_style),
                        Paragraph("", code_style)
                    ])

                # Remediation block
                remediation_text = f.remediation or f.recommendation or "Review service requirement and restrict network exposure."
                finding_card_data.append([
                    Paragraph(f"<b>Recommended Action / Remediation:</b><br/>{safe_escape(remediation_text)}", table_cell_style),
                    Paragraph(f"<b>Status:</b> {safe_escape(f.status or 'OPEN')}", table_cell_bold)
                ])

                finding_table = Table(finding_card_data, colWidths=[usable_width - 80, 80])
                finding_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), badge_bg),
                    ('BACKGROUND', (0, 1), (-1, -1), white),
                    ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
                    ('LINEBELOW', (0, 0), (-1, 0), 1, HexColor(badge_color)),
                    ('INNERGRID', (0, 1), (-1, -1), 0.5, BORDER_COLOR),
                    ('SPAN', (0, 2), (-1, 2)),
                    ('SPAN', (0, 3), (-1, 3)) if len(finding_card_data) == 5 else ('SPAN', (0, 0), (0, 0)),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(KeepTogether([finding_table, Spacer(1, 8)]))
        else:
            story.append(Paragraph("<i>No security findings were generated for this scan.</i>", body_style))

        story.append(Spacer(1, 12))

        # ===================================================================
        #  SECTION 8: REMEDIATION SUMMARY & ACTION PLAN
        # ===================================================================
        story.append(Paragraph("8. Remediation Summary &amp; Action Plan", section_heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY_BLUE, spaceBefore=2, spaceAfter=8))

        if findings:
            if findings_high:
                story.append(Paragraph(f'<font color="{SEV_HIGH.hexval()}"><b>High Priority Actions (Immediate):</b></font>', body_bold))
                for f in findings_high:
                    r_text = f.remediation or f.recommendation or "Review and secure exposed service."
                    item_text = f"• <b>{safe_escape(f.title)}:</b> {safe_escape(r_text)}"
                    story.append(Paragraph(item_text, body_style))
                story.append(Spacer(1, 4))

            if findings_medium:
                story.append(Paragraph(f'<font color="{SEV_MEDIUM.hexval()}"><b>Medium Priority Actions (Planned):</b></font>', body_bold))
                for f in findings_medium:
                    r_text = f.remediation or f.recommendation or "Upgrade or reconfigure service."
                    item_text = f"• <b>{safe_escape(f.title)}:</b> {safe_escape(r_text)}"
                    story.append(Paragraph(item_text, body_style))
                story.append(Spacer(1, 4))

            if findings_low:
                story.append(Paragraph(f'<font color="{SEV_LOW.hexval()}"><b>Low Priority Hardening Recommendations:</b></font>', body_bold))
                for f in findings_low:
                    r_text = f.remediation or f.recommendation or "Apply standard system hardening."
                    item_text = f"• <b>{safe_escape(f.title)}:</b> {safe_escape(r_text)}"
                    story.append(Paragraph(item_text, body_style))
                story.append(Spacer(1, 4))

            if findings_info:
                story.append(Paragraph(f'<font color="{SEV_INFO.hexval()}"><b>Informational Posture Notes:</b></font>', body_bold))
                for f in findings_info:
                    r_text = f.remediation or f.recommendation or "Informational observation."
                    item_text = f"• <b>{safe_escape(f.title)}:</b> {safe_escape(r_text)}"
                    story.append(Paragraph(item_text, body_style))
        else:
            story.append(Paragraph("<i>No remediation actions required. No findings recorded.</i>", body_style))

        story.append(Spacer(1, 12))

        # ===================================================================
        #  SECTION 9: TECHNICAL DETAILS & APPENDIX
        # ===================================================================
        story.append(Paragraph("9. Technical Details &amp; Appendix", section_heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY_BLUE, spaceBefore=2, spaceAfter=8))

        appendix_text = (
            "<b>Assessment Methodology:</b><br/>"
            "This assessment was conducted using the ScanVix Network Security Assessment Engine. "
            "Port scanning and service detection were performed via Nmap with strictly defined timing "
            "and rate limits. Script evaluation was executed exclusively using curated, non-intrusive "
            "Nmap Scripting Engine (NSE) security assessment scripts.<br/><br/>"
            "<b>Observation Classifications:</b><br/>"
            "• <b>OBSERVED:</b> Confirmed service presence, banner version, or direct protocol behavior directly detected.<br/>"
            "• <b>POTENTIAL:</b> Inferred vulnerability risk based on standard service defaults, cleartext protocol usage, or version heuristics.<br/><br/>"
            "<b>Safety Boundary Verification:</b><br/>"
            "Scanning was confined strictly to user-authorized lab targets conforming to RFC 1918 private "
            "address space or approved local test environments in accordance with platform security policies."
        )
        story.append(Paragraph(appendix_text, body_style))

        # -------------------------------------------------------------------
        #  Build PDF Document
        # -------------------------------------------------------------------
        doc = SimpleDocTemplate(
            file_full_path,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=46,
            bottomMargin=46
        )
        doc.build(story, canvasmaker=NumberedCanvas)

        file_size = os.path.getsize(file_full_path)
        logger.info(f"PDF Report generated successfully for scan #{scan_id}: {file_full_path} ({file_size} bytes)")

        # -------------------------------------------------------------------
        #  Update / Create Report Database Record
        # -------------------------------------------------------------------
        # Relative file path for storage portability (with cross-drive fallback)
        try:
            rel_path = os.path.relpath(file_full_path, current_app.root_path)
        except ValueError:
            rel_path = file_full_path

        # Check existing report for this scan
        report_record = Report.query.filter_by(scan_id=scan.id).first()
        if not report_record:
            report_code = f"REP-{scan.id:04d}"
            # Ensure unique report_id string
            existing_code = Report.query.filter_by(report_id=report_code).first()
            if existing_code:
                report_code = f"REP-{scan.id:04d}-{int(datetime.utcnow().timestamp())}"

            report_record = Report(
                scan_id=scan.id,
                report_id=report_code,
                file_path=rel_path,
                file_size=file_size,
                status='COMPLETED',
                generated_at=datetime.utcnow()
            )
            db.session.add(report_record)
        else:
            report_record.file_path = rel_path
            report_record.file_size = file_size
            report_record.status = 'COMPLETED'
            report_record.generated_at = datetime.utcnow()

        # Update Scan record report_path
        scan.report_path = rel_path
        db.session.commit()

        return report_record, None

    except Exception as e:
        logger.error(f"Error generating PDF report for scan #{scan_id}: {str(e)}", exc_info=True)
        if 'scan' in locals() and scan:
            # Attempt to record failure status if report record exists
            try:
                rep = Report.query.filter_by(scan_id=scan.id).first()
                if rep:
                    rep.status = 'FAILED'
                    db.session.commit()
            except Exception:
                db.session.rollback()
        return None, f"An error occurred while generating the PDF report: {str(e)}"

    finally:
        if ctx:
            ctx.pop()
