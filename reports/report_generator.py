"""
Incident Report Generator
Exports formal security incident reports to PDF, JSON, and CSV formats.
Stage 14 requirement.
"""
import json
import csv
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from config.settings import EXPORTS_DIR

def export_incident_to_json(incident: Dict[str, Any], alert: Dict[str, Any], output_path: Path = None) -> Path:
    """Exports structured incident data to a JSON file."""
    if output_path is None:
        output_path = EXPORTS_DIR / f"{incident.get('incident_id', 'INC')}.json"

    payload = {
        "report_generated_at": datetime.utcnow().isoformat(),
        "incident": incident,
        "associated_alert": alert
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return output_path

def export_incidents_to_csv(incidents: List[Dict[str, Any]], output_path: Path = None) -> Path:
    """Exports list of incidents to a CSV file."""
    if output_path is None:
        output_path = EXPORTS_DIR / "incident_summary.csv"

    if not incidents:
        return output_path

    fieldnames = list(incidents[0].keys())
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(incidents)
    return output_path

def export_incident_to_pdf(incident: Dict[str, Any], alert: Dict[str, Any], output_path: Path = None) -> Path:
    """
    Generates a formal, professional PDF incident investigation report using ReportLab.
    """
    if output_path is None:
        inc_id = incident.get("incident_id", "INC-001")
        output_path = EXPORTS_DIR / f"{inc_id}_Report.pdf"

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#1E293B')
    )
    section_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#0F172A'),
        spaceBefore=10,
        spaceAfter=5
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )

    story = []

    # Title & Header
    story.append(Paragraph("SECURITY INCIDENT INVESTIGATION REPORT", title_style))
    story.append(Paragraph(f"<b>System:</b> AI-Driven Adaptive Endpoint Behavioral Threat Detection System", body_style))
    story.append(Paragraph(f"<b>Generated:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", body_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#DC2626'), spaceAfter=12))

    # Overview Table
    inc_data = [
        [Paragraph("<b>Incident ID</b>", body_style), Paragraph(str(incident.get("incident_id")), body_style),
         Paragraph("<b>Severity Tier</b>", body_style), Paragraph(f"<font color='red'><b>{incident.get('severity', 'Critical')}</b></font>", body_style)],
        [Paragraph("<b>Timestamp</b>", body_style), Paragraph(str(incident.get("timestamp")), body_style),
         Paragraph("<b>Status</b>", body_style), Paragraph(str(incident.get("status", "Open")), body_style)],
        [Paragraph("<b>Root Process</b>", body_style), Paragraph(str(incident.get("process_name")), body_style),
         Paragraph("<b>Process ID (PID)</b>", body_style), Paragraph(str(incident.get("pid")), body_style)]
    ]
    t_inc = Table(inc_data, colWidths=[100, 170, 100, 170])
    t_inc.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_inc)
    story.append(Spacer(1, 12))

    # Fused Risk Score Breakdown
    story.append(Paragraph("<b>HYBRID RISK FUSION SCORE BREAKDOWN</b>", section_style))
    scores_data = [
        ["Total Risk Score", "ML Score (IsoForest)", "Rule Score", "Process Graph", "Attack Sequence"],
        [
            f"{alert.get('risk_score', 0)} / 100",
            f"{alert.get('ml_score', 0)} / 100",
            f"{alert.get('rule_score', 0)} / 100",
            f"{alert.get('graph_score', 0)} / 100",
            f"{alert.get('sequence_score', 0)} / 100"
        ]
    ]
    t_scores = Table(scores_data, colWidths=[108]*5)
    t_scores.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('BACKGROUND', (0,1), (-1,1), colors.HexColor('#FEF2F2')),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_scores)
    story.append(Spacer(1, 10))

    # Primary MITRE ATT&CK Mapping
    story.append(Paragraph("<b>MITRE ATT&CK FRAMEWORK ALIGNMENT</b>", section_style))
    mitre_details = alert.get("mitre_details", [])
    if mitre_details:
        m_table = [["Technique ID", "Name", "Tactic Classification"]]
        for m in mitre_details:
            m_table.append([m.get("id"), m.get("name"), m.get("tactic")])
        t_m = Table(m_table, colWidths=[100, 260, 180])
        t_m.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F766E')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_m)
    else:
        story.append(Paragraph("No direct MITRE technique matched.", body_style))
    story.append(Spacer(1, 10))

    # Detection Rationale / Explainability
    story.append(Paragraph("<b>DETECTION RATIONALE & FORENSIC EXPLAINABILITY</b>", section_style))
    story.append(Paragraph(f"{alert.get('reasons', 'Behavioral anomaly detected.')}", body_style))
    story.append(Spacer(1, 10))

    # Recommended Actions & Simulation Log
    story.append(Paragraph("<b>RECOMMENDED ACTIONS & CONTAINMENT AUDIT LOG</b>", section_style))
    rec = incident.get("recommended_actions", "Isolate endpoint.")
    sim_log = incident.get("response_simulation_log", "None recorded.")
    story.append(Paragraph(f"<b>Recommended:</b> {rec}", body_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"<b>Simulation Audit:</b><br/>{sim_log.replace(chr(10), '<br/>')}", body_style))

    doc.build(story)
    return output_path
