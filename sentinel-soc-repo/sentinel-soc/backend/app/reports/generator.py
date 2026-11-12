"""Report Generation Engine (PDF via ReportLab, CSV, JSON) with SENTINEL SOC Branding & Developer Credit."""
import csv
import io
import json
from typing import Dict, Any, List
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from app.core.config import settings
from app.core.database import utc_now_iso

def gather_report_data(conn, report_type: str = "executive_soc_summary", severity_filter: str = None, source_filter: str = None) -> Dict[str, Any]:
    now = utc_now_iso()
    ev_query = "SELECT * FROM events WHERE 1=1"
    ev_params: List[Any] = []
    if severity_filter and severity_filter != "All":
        ev_query += " AND severity = ?"
        ev_params.append(severity_filter)
    if source_filter and source_filter != "All":
        ev_query += " AND source = ?"
        ev_params.append(source_filter)
    ev_query += " ORDER BY timestamp DESC"
    events = [dict(r) for r in conn.execute(ev_query, ev_params).fetchall()]

    al_query = "SELECT * FROM alerts WHERE 1=1"
    al_params: List[Any] = []
    if severity_filter and severity_filter != "All":
        al_query += " AND severity = ?"
        al_params.append(severity_filter)
    al_query += " ORDER BY created_at DESC"
    alerts = [dict(r) for r in conn.execute(al_query, al_params).fetchall()]

    incidents = [dict(r) for r in conn.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()]
    rules = [dict(r) for r in conn.execute("SELECT * FROM detection_rules ORDER BY rule_id").fetchall()]

    top_ips_rows = conn.execute(
        """SELECT source_ip, COUNT(*) AS event_count,
           SUM(CASE WHEN event_type = 'authentication_failure' THEN 1 ELSE 0 END) AS auth_failures
           FROM events WHERE source_ip IS NOT NULL
           GROUP BY source_ip ORDER BY event_count DESC LIMIT 10"""
    ).fetchall()
    top_ips = [dict(r) for r in top_ips_rows]

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for a in alerts:
        if a["severity"] in sev_counts:
            sev_counts[a["severity"]] += 1

    findings = []
    recommendations = []
    if sev_counts["Critical"] > 0 or sev_counts["High"] > 0:
        findings.append(
            f"Detected {sev_counts['Critical']} Critical and {sev_counts['High']} High severity alerts requiring prioritized Tier-2 incident containment."
        )
        recommendations.append(
            "Enforce immediate perimeter IP blocking and credential rotation for accounts involved in brute-force or post-failure login correlations."
        )
    auth_fails = sum(1 for e in events if e["event_type"] == "authentication_failure")
    if auth_fails > 0:
        findings.append(f"Recorded {auth_fails} authentication failure events across monitored Linux and Windows endpoints.")
        recommendations.append("Enable key-based SSH authentication, disable root password login, and enforce Kerberos/NTLM lockout policies.")
    priv_evs = sum(1 for e in events if e["event_type"] in ("privilege_escalation", "process_creation"))
    if priv_evs > 0:
        findings.append(f"Observed {priv_evs} privileged execution / special privilege assignment event(s) (sudo / Event ID 4672 / 4688).")
        recommendations.append("Audit administrative sudoers rules and restrict encoded PowerShell execution via AppLocker / Constrained Language Mode.")
    if not findings:
        findings.append("No high-risk security anomalies were detected in the selected reporting scope.")
        recommendations.append("Maintain baseline log ingestion, periodic rule tuning, and daily SOC triage workflows.")

    return {
        "report_title": f"SENTINEL SOC — {report_type.replace('_', ' ').title()}",
        "report_type": report_type,
        "generated_at": now,
        "display_timezone": settings.DEFAULT_TIMEZONE,
        "filters": {"severity": severity_filter or "All", "source": source_filter or "All"},
        "developer": {
            "name": settings.DEVELOPER_NAME,
            "role": settings.DEVELOPER_ROLE,
            "education": settings.DEVELOPER_EDUCATION,
            "email": settings.DEVELOPER_EMAIL,
            "whatsapp": settings.DEVELOPER_WHATSAPP,
            "credit": settings.DEVELOPER_CREDIT,
        },
        "summary": {
            "total_events": len(events),
            "total_alerts": len(alerts),
            "critical_alerts": sev_counts["Critical"],
            "high_alerts": sev_counts["High"],
            "medium_alerts": sev_counts["Medium"],
            "low_alerts": sev_counts["Low"],
            "total_incidents": len(incidents),
            "active_rules": sum(1 for r in rules if r["enabled"] == 1),
        },
        "top_suspicious_ips": top_ips,
        "alerts": alerts[:25],
        "incidents": incidents[:15],
        "findings": findings,
        "recommendations": recommendations,
    }

def generate_pdf_report(report_data: Dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=report_data["report_title"],
        author=settings.DEVELOPER_NAME,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "SocTitle", parent=styles["Heading1"], fontSize=18, leading=22,
        textColor=colors.HexColor("#0F172A"), spaceAfter=4
    )
    sub_style = ParagraphStyle(
        "SocSub", parent=styles["Normal"], fontSize=9.5, leading=13,
        textColor=colors.HexColor("#475569"), spaceAfter=12
    )
    sec_style = ParagraphStyle(
        "SocSec", parent=styles["Heading2"], fontSize=12.5, leading=16,
        textColor=colors.HexColor("#0284C7"), spaceBefore=12, spaceAfter=6
    )
    body_style = ParagraphStyle(
        "SocBody", parent=styles["Normal"], fontSize=9.5, leading=13.5,
        textColor=colors.HexColor("#1E293B"), spaceAfter=4
    )

    story = []
    story.append(Paragraph(f"<b>SENTINEL SOC</b> — {report_data['report_title']}", title_style))
    story.append(Paragraph(
        f"Generated: {report_data['generated_at']} (Display Timezone: {report_data['display_timezone']}) | "
        f"Filters: Severity={report_data['filters']['severity']}, Source={report_data['filters']['source']}<br/>"
        f"<b>{settings.DEVELOPER_CREDIT}</b> ({settings.DEVELOPER_EMAIL} | {settings.DEVELOPER_WHATSAPP})",
        sub_style,
    ))

    # Summary KPI Table
    story.append(Paragraph("1. Executive Telemetry Summary", sec_style))
    s = report_data["summary"]
    kpi_data = [
        ["Metric", "Value", "Metric", "Value"],
        ["Total Events Analyzed", str(s["total_events"]), "Total Security Alerts", str(s["total_alerts"])],
        ["Critical Alerts", str(s["critical_alerts"]), "High Severity Alerts", str(s["high_alerts"])],
        ["Medium Severity Alerts", str(s["medium_alerts"]), "Low Severity Alerts", str(s["low_alerts"])],
        ["Tracked Incidents", str(s["total_incidents"]), "Active Detection Rules", str(s["active_rules"])],
    ]
    kpi_table = Table(kpi_data, colWidths=[50 * mm, 35 * mm, 50 * mm, 35 * mm])
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
    ]))
    story.append(kpi_table)

    # Findings & Recommendations
    story.append(Paragraph("2. Key Security Findings & Remediation Recommendations", sec_style))
    for idx, f_text in enumerate(report_data["findings"], start=1):
        story.append(Paragraph(f"• <b>Finding {idx}:</b> {f_text}", body_style))
    story.append(Spacer(1, 4))
    for idx, r_text in enumerate(report_data["recommendations"], start=1):
        story.append(Paragraph(f"• <b>Recommendation {idx}:</b> {r_text}", body_style))

    # Top Suspicious IPs
    story.append(Paragraph("3. Top Suspicious Source IP Addresses", sec_style))
    ip_rows = [["Source IP", "Total Events", "Authentication Failures"]]
    for ip_rec in report_data["top_suspicious_ips"] or [{"source_ip": "None", "event_count": 0, "auth_failures": 0}]:
        ip_rows.append([str(ip_rec["source_ip"]), str(ip_rec["event_count"]), str(ip_rec["auth_failures"])])
    ip_table = Table(ip_rows, colWidths=[65 * mm, 50 * mm, 55 * mm])
    ip_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(ip_table)

    # Recent Security Alerts
    story.append(Paragraph("4. Generated Security Alerts", sec_style))
    al_rows = [["Alert ID", "Severity", "Rule", "Source IP", "Status", "Title"]]
    for a in report_data["alerts"][:12]:
        al_rows.append([
            a["alert_id"], a["severity"], a["rule_id"],
            str(a.get("source_ip") or "-"), a["status"], a["title"][:42]
        ])
    if len(al_rows) == 1:
        al_rows.append(["-", "-", "-", "-", "-", "No alerts in current filter scope"])
    al_table = Table(al_rows, colWidths=[24 * mm, 18 * mm, 20 * mm, 28 * mm, 22 * mm, 58 * mm])
    al_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(al_table)

    story.append(Spacer(1, 10))
    story.append(Paragraph(
        f"<i>Report generated by SENTINEL SOC v{settings.VERSION} — {settings.DEVELOPER_CREDIT} "
        f"Academic Affiliation: {', '.join(settings.DEVELOPER_EDUCATION)}.</i>",
        sub_style,
    ))
    doc.build(story)
    return buffer.getvalue()

def generate_csv_report(report_data: Dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["SENTINEL SOC Report", report_data["report_title"]])
    writer.writerow(["Generated At", report_data["generated_at"]])
    writer.writerow(["Developer Credit", settings.DEVELOPER_CREDIT])
    writer.writerow([])
    writer.writerow(["Alert ID", "Severity", "Rule ID", "Rule Name", "Source IP", "Username", "Status", "First Observed", "Title"])
    for a in report_data["alerts"]:
        writer.writerow([
            a["alert_id"], a["severity"], a["rule_id"], a["rule_name"],
            a.get("source_ip") or "", a.get("username") or "", a["status"],
            a["first_observed"], a["title"]
        ])
    return out.getvalue()
