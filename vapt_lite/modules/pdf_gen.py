import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

def generate_pdf(scan_data, filepath):
    """
    Generates a professional VAPT PDF report using ReportLab.
    """
    # Ensure the reports directory exists
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    # Set up the document canvas
    doc = SimpleDocTemplate(filepath, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    elements = []

    # Custom Text Styles
    title_style = ParagraphStyle(
        'TitleStyle', parent=styles['Heading1'], fontSize=22, spaceAfter=10, textColor=colors.HexColor('#1a1a2e'), alignment=1
    )
    subtitle_style = ParagraphStyle(
        'SubTitle', parent=styles['Normal'], fontSize=12, spaceAfter=20, textColor=colors.HexColor('#4a4a4a'), alignment=1
    )
    heading_style = ParagraphStyle(
        'Heading2', parent=styles['Heading2'], fontSize=16, spaceAfter=10, textColor=colors.HexColor('#16213e')
    )
    normal_style = styles['Normal']
    normal_style.spaceAfter = 6

    # --- 1. HEADER SECTION ---
    elements.append(Paragraph("VAPT Ally - Security Assessment Report", title_style))
    target_url = scan_data.get('url', scan_data.get('target', 'Unknown Target'))
    elements.append(Paragraph(f"<b>Target Infrastructure:</b> {target_url}", subtitle_style))
    elements.append(Paragraph(f"<b>Report Generated:</b> {datetime.now().strftime('%B %d, %Y - %H:%M:%S')}", subtitle_style))
    elements.append(Spacer(1, 20))

    # --- 2. EXECUTIVE SUMMARY (TABLE) ---
    elements.append(Paragraph("Executive Summary & Infrastructure", heading_style))
    
    # Format ports safely
    ports = scan_data.get('ports', [])
    if isinstance(ports, list):
        ports_str = ", ".join(str(p) for p in ports) if ports else "None detected"
    else:
        ports_str = str(ports)

    # Figure out the exact key your app uses for vulnerabilities
    vulns = scan_data.get('vulnerabilities', scan_data.get('vulns', []))

    summary_data = [
        ["Target IP Address", str(scan_data.get('ip', 'N/A'))],
        ["Server / Hosting Info", str(scan_data.get('server', 'N/A'))],
        ["WAF Detected", str(scan_data.get('waf', 'N/A'))],
        ["Open Ports", ports_str],
        ["Technology Stack", str(scan_data.get('tech', 'N/A'))],
        ["Subdomains Found", str(len(scan_data.get('subdomains', [])))],
        ["Total Vulnerabilities", str(len(vulns))]
    ]

    # Style the table
    summary_table = Table(summary_data, colWidths=[150, 350])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f5')), # Light gray background for left column
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#1a1a2e')),  # Dark text
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),             # Bold the left column
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),                  # Normal font for right column
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)                 # Add grid lines
    ]))
    
    elements.append(summary_table)
    elements.append(Spacer(1, 30))

    # --- 3. DETAILED VULNERABILITIES ---
    elements.append(Paragraph("Detailed Vulnerability Findings", heading_style))
    
    if not vulns:
        elements.append(Paragraph("No vulnerabilities were detected during this assessment.", normal_style))
    else:
        for idx, vuln in enumerate(vulns, 1):
            # Map severity to colors
            sev = str(vuln.get('severity', 'INFO')).upper()
            sev_color = colors.grey
            if sev == "CRITICAL":
                sev_color = colors.HexColor('#cc0000') # Dark Red
            elif sev == "HIGH":
                sev_color = colors.HexColor('#e65c00') # Orange/Red
            elif sev == "MEDIUM":
                sev_color = colors.HexColor('#e6b800') # Dark Yellow
            elif sev == "LOW":
                sev_color = colors.HexColor('#339933') # Green

            vuln_title_style = ParagraphStyle(
                f'VulnTitle{idx}', parent=styles['Heading3'], fontSize=12, textColor=sev_color, spaceAfter=4
            )
            
            # Print Vulnerability Name and Severity
            title = f"{idx}. {vuln.get('type', 'Unknown Vulnerability')} [{sev}]"
            elements.append(Paragraph(title, vuln_title_style))
            
            # Print Details
            elements.append(Paragraph(f"<b>Endpoint/URL:</b> <font color='blue'>{vuln.get('url', 'N/A')}</font>", normal_style))
            elements.append(Paragraph(f"<b>Description:</b> {vuln.get('description', 'N/A')}", normal_style))
            elements.append(Paragraph(f"<b>Remediation:</b> {vuln.get('remediation', 'N/A')}", normal_style))
            elements.append(Spacer(1, 15))

    # Build the PDF
    doc.build(elements)
    return filepath