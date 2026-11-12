"""SENTINEL SOC — Main FastAPI Application & REST API Endpoints."""
import hashlib
import json
import os
import random
import re
import shutil
import uuid
from pathlib import Path
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.core.config import settings, BASE_DIR, BACKUP_DIR
from app.core.database import init_db, get_db, utc_now_iso, log_audit
from app.parsers.log_parser import parse_log_content
from app.detection.engine import run_detection_engine
from app.services.threat_intel import investigate_ioc
from app.reports.generator import gather_report_data, generate_pdf_report, generate_csv_report

app = FastAPI(
    title=settings.PROJECT_NAME,
    description=f"{settings.PROJECT_SUBTITLE} — {settings.DEVELOPER_CREDIT}",
    version=settings.VERSION,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def security_headers_middleware(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

@app.on_event("startup")
def on_startup():
    init_db()

# --- Pydantic Schemas ---
class TextIngestRequest(BaseModel):
    dataset_name: str = Field(..., min_length=1, max_length=120)
    filename: str = Field(..., min_length=1, max_length=120)
    content: str = Field(..., min_length=1)
    origin_type: str = Field(default="uploaded")
    auto_detect: bool = Field(default=True)

class AlertUpdateRequest(BaseModel):
    status: Optional[str] = None
    assigned_analyst: Optional[str] = None
    note: Optional[str] = None
    actor: str = "Wasif Karim"

class IncidentCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    description: str = Field(..., min_length=3)
    severity: str = Field(default="High")
    assigned_analyst: str = Field(default="Wasif Karim (SOC Tier-2)")
    related_alerts: List[str] = Field(default_factory=list)
    iocs: List[str] = Field(default_factory=list)

class IncidentUpdateRequest(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    assigned_analyst: Optional[str] = None
    resolution_summary: Optional[str] = None
    note: Optional[str] = None
    iocs: Optional[List[str]] = None
    actor: str = "Wasif Karim"

class IOCLookupRequest(BaseModel):
    ioc_value: str = Field(..., min_length=2, max_length=256)
    analyst_notes: str = Field(default="")

class RuleUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    threshold_count: Optional[int] = Field(default=None, ge=1, le=10000)
    time_window_seconds: Optional[int] = Field(default=None, ge=10, le=86400)
    severity: Optional[str] = None

class SettingsUpdateRequest(BaseModel):
    settings: Dict[str, str]

class SimulationBatchRequest(BaseModel):
    count: int = Field(default=3, ge=1, le=20)
    scenario: str = Field(default="mixed")

SAFE_FILENAME_RE = re.compile(r"[^a-zA-Z0-9_\-\.]")

def sanitize_filename(name: str) -> str:
    base = os.path.basename(name or "upload.log")
    if ".." in base or "/" in base or "\\" in base:
        raise HTTPException(status_code=400, detail="Invalid filename: path traversal characters detected.")
    cleaned = SAFE_FILENAME_RE.sub("_", base)
    ext = "." + cleaned.rsplit(".", 1)[-1].lower() if "." in cleaned else ".log"
    if ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Unsupported file extension '{ext}'. Allowed: {sorted(settings.ALLOWED_EXTENSIONS)}")
    return cleaned

def ingest_raw_log_payload(dataset_name: str, filename: str, content: str, origin_type: str = "uploaded", auto_detect: bool = True) -> Dict[str, Any]:
    clean_name = sanitize_filename(filename)
    if len(content.encode("utf-8")) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Uploaded file exceeds maximum allowed size (10 MB).")

    dataset_id = f"DS-{uuid.uuid4().hex[:8].upper()}"
    sha256_hash = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
    ext = clean_name.rsplit(".", 1)[-1].lower()
    now = utc_now_iso()

    parsed_events, rejected = parse_log_content(clean_name, content, dataset_id, origin_type)
    total_records = len(parsed_events) + len(rejected)

    with get_db() as conn:
        conn.execute(
            """INSERT INTO imported_datasets
            (id, name, filename, file_format, origin_type, total_records, imported_records, rejected_records, rejection_reasons, sha256_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                dataset_id, dataset_name, clean_name, ext, origin_type,
                total_records, len(parsed_events), len(rejected),
                json.dumps(rejected[:50]), sha256_hash, now,
            ),
        )
        inserted_count = 0
        for ev in parsed_events:
            cur = conn.execute(
                """INSERT OR IGNORE INTO events
                (event_hash, timestamp, ingestion_timestamp, dataset_id, origin_type, source, hostname,
                 username, source_ip, destination_ip, destination_port, event_type, event_id, severity,
                 raw_message, normalized_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ev["event_hash"], ev["timestamp"], now, ev["dataset_id"], ev["origin_type"],
                    ev["source"], ev["hostname"], ev["username"], ev["source_ip"],
                    ev["destination_ip"], ev["destination_port"], ev["event_type"],
                    ev["event_id"], ev["severity"], ev["raw_message"], ev["normalized_data"],
                ),
            )
            if cur.rowcount > 0:
                inserted_count += 1

        log_audit(
            conn, "INGEST_DATASET", "dataset", dataset_id,
            f"Ingested '{dataset_name}' ({clean_name}) [{origin_type}]: {inserted_count} imported, {len(rejected)} rejected."
        )
        detection_summary = None
        if auto_detect and inserted_count > 0:
            detection_summary = run_detection_engine(conn, trigger_source=f"auto_ingest:{dataset_id}")

    return {
        "dataset_id": dataset_id,
        "dataset_name": dataset_name,
        "filename": clean_name,
        "origin_type": origin_type,
        "sha256_hash": sha256_hash,
        "total_records": total_records,
        "imported_records": inserted_count,
        "rejected_records": len(rejected),
        "rejection_reasons": rejected[:25],
        "detection_summary": detection_summary,
    }

@app.get("/api/health")
def get_health():
    with get_db() as conn:
        ev_count = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
        al_count = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "database": "connected",
        "timezone_display": settings.DEFAULT_TIMEZONE,
        "timezone_storage": "UTC",
        "events_count": ev_count,
        "alerts_count": al_count,
        "developer": settings.DEVELOPER_CREDIT,
    }

@app.get("/api/developer")
def get_developer_profile():
    return {
        "name": settings.DEVELOPER_NAME,
        "role": settings.DEVELOPER_ROLE,
        "education": settings.DEVELOPER_EDUCATION,
        "email": settings.DEVELOPER_EMAIL,
        "email_link": settings.DEVELOPER_EMAIL_LINK,
        "whatsapp": settings.DEVELOPER_WHATSAPP,
        "whatsapp_link": settings.DEVELOPER_WHATSAPP_LINK,
        "project_name": settings.PROJECT_NAME,
        "project_type": settings.PROJECT_SUBTITLE,
        "project_category": settings.PROJECT_CATEGORY,
        "credit": settings.DEVELOPER_CREDIT,
    }

@app.get("/api/dashboard/overview")
def get_dashboard_overview():
    with get_db() as conn:
        total_events = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
        origin_counts = {
            r["origin_type"]: r["c"]
            for r in conn.execute("SELECT origin_type, COUNT(*) AS c FROM events GROUP BY origin_type").fetchall()
        }
        sev_rows = conn.execute("SELECT severity, COUNT(*) AS c FROM alerts GROUP BY severity").fetchall()
        sev_map = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for r in sev_rows:
            sev_map[r["severity"]] = r["c"]

        suspicious_ips_count = conn.execute(
            "SELECT COUNT(DISTINCT source_ip) AS c FROM alerts WHERE source_ip IS NOT NULL"
        ).fetchone()["c"]

        active_incidents = conn.execute(
            "SELECT COUNT(*) AS c FROM incidents WHERE status NOT IN ('Resolved', 'Closed')"
        ).fetchone()["c"]

        # Timeline buckets
        timeline_rows = conn.execute(
            """SELECT substr(timestamp, 1, 16) AS bucket,
               COUNT(*) AS total,
               SUM(CASE WHEN origin_type = 'simulated' THEN 1 ELSE 0 END) AS simulated,
               SUM(CASE WHEN origin_type = 'sample' THEN 1 ELSE 0 END) AS sample_data,
               SUM(CASE WHEN origin_type = 'uploaded' THEN 1 ELSE 0 END) AS uploaded
               FROM events GROUP BY bucket ORDER BY bucket ASC LIMIT 24"""
        ).fetchall()

        top_ips = [
            dict(r) for r in conn.execute(
                """SELECT source_ip, COUNT(*) AS event_count,
                   SUM(CASE WHEN event_type = 'authentication_failure' THEN 1 ELSE 0 END) AS failed_logins
                   FROM events WHERE source_ip IS NOT NULL
                   GROUP BY source_ip ORDER BY event_count DESC LIMIT 6"""
            ).fetchall()
        ]

        cat_rows = conn.execute("SELECT event_type, COUNT(*) AS c FROM events GROUP BY event_type").fetchall()
        cat_map = {r["event_type"]: r["c"] for r in cat_rows}
        categories = [
            {"category": "Authentication Failures", "key": "authentication_failure", "count": cat_map.get("authentication_failure", 0)},
            {"category": "Successful Logins", "key": "authentication_success", "count": cat_map.get("authentication_success", 0)},
            {"category": "Privilege Escalation", "key": "privilege_escalation", "count": cat_map.get("privilege_escalation", 0) + cat_map.get("process_creation", 0)},
            {"category": "Network Anomalies", "key": "network_connection", "count": cat_map.get("network_connection", 0) + cat_map.get("http_request_flood", 0)},
            {"category": "Suspicious DNS Activity", "key": "dns_query", "count": cat_map.get("dns_query", 0)},
            {"category": "Other Security Events", "key": "other", "count": sum(v for k, v in cat_map.items() if k not in {"authentication_failure", "authentication_success", "privilege_escalation", "process_creation", "network_connection", "http_request_flood", "dns_query"})},
        ]

        recent_alerts = [
            dict(r) for r in conn.execute(
                "SELECT alert_id, created_at, title, source_ip, rule_id, rule_name, severity, status, origin_type FROM alerts ORDER BY created_at DESC LIMIT 8"
            ).fetchall()
        ]
        recent_activity = [
            dict(r) for r in conn.execute(
                "SELECT id, timestamp, actor, action_type, target_type, target_id, details FROM audit_logs ORDER BY id DESC LIMIT 10"
            ).fetchall()
        ]

    return {
        "kpis": {
            "total_events": total_events,
            "events_analyzed": total_events,
            "critical_alerts": sev_map["Critical"],
            "high_alerts": sev_map["High"],
            "medium_alerts": sev_map["Medium"],
            "low_alerts": sev_map["Low"],
            "suspicious_ips": suspicious_ips_count,
            "active_incidents": active_incidents,
        },
        "origin_breakdown": {
            "uploaded": origin_counts.get("uploaded", 0),
            "sample": origin_counts.get("sample", 0),
            "simulated": origin_counts.get("simulated", 0),
        },
        "timeline": [dict(r) for r in timeline_rows],
        "severity_distribution": [
            {"name": "Critical", "value": sev_map["Critical"]},
            {"name": "High", "value": sev_map["High"]},
            {"name": "Medium", "value": sev_map["Medium"]},
            {"name": "Low", "value": sev_map["Low"]},
        ],
        "top_suspicious_ips": top_ips,
        "event_categories": categories,
        "recent_alerts": recent_alerts,
        "recent_activity": recent_activity,
    }

@app.post("/api/logs/preview")
def preview_log_text(req: TextIngestRequest):
    clean_name = sanitize_filename(req.filename)
    parsed, rejected = parse_log_content(clean_name, req.content, "PREVIEW-DS", req.origin_type)
    return {
        "filename": clean_name,
        "total_records": len(parsed) + len(rejected),
        "valid_records": len(parsed),
        "rejected_records": len(rejected),
        "sample_parsed": parsed[:10],
        "sample_rejected": rejected[:10],
    }

@app.post("/api/logs/ingest-text")
def ingest_log_text(req: TextIngestRequest):
    return ingest_raw_log_payload(req.dataset_name, req.filename, req.content, req.origin_type, req.auto_detect)

@app.post("/api/logs/upload")
async def upload_log_file(
    file: UploadFile = File(...),
    dataset_name: Optional[str] = Form(default=None),
    origin_type: str = Form(default="uploaded"),
    auto_detect: bool = Form(default=True),
):
    clean_name = sanitize_filename(file.filename or "uploaded.log")
    raw_bytes = await file.read()
    if len(raw_bytes) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Uploaded file exceeds 10 MB limit.")
    content = raw_bytes.decode("utf-8", errors="replace")
    ds_title = dataset_name or f"Uploaded: {clean_name}"
    return ingest_raw_log_payload(ds_title, clean_name, content, origin_type, auto_detect)

@app.get("/api/logs/datasets")
def list_datasets():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM imported_datasets ORDER BY created_at DESC").fetchall()
        res = []
        for r in rows:
            d = dict(r)
            d["rejection_reasons"] = json.loads(d.get("rejection_reasons") or "[]")
            res.append(d)
    return {"datasets": res}

@app.delete("/api/logs/datasets/{dataset_id}")
def delete_dataset(dataset_id: str):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM imported_datasets WHERE id = ?", (dataset_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Dataset not found.")
        conn.execute("DELETE FROM events WHERE dataset_id = ?", (dataset_id,))
        conn.execute("DELETE FROM imported_datasets WHERE id = ?", (dataset_id,))
        log_audit(conn, "DELETE_DATASET", "dataset", dataset_id, f"Removed dataset '{row['name']}' and its associated events.")
    return {"status": "deleted", "dataset_id": dataset_id}

@app.post("/api/sample-data/load")
def load_sample_datasets():
    sample_dir = BASE_DIR.parent / "sample_data"
    files = [
        ("Sample Linux Auth & Brute-Force Logs", "linux_auth_sample.log"),
        ("Sample Windows Security Events (4624/4625/4672/4688)", "windows_security_events.csv"),
        ("Sample Firewall Port Scan, DNS Tunneling & Flood Telemetry", "network_and_dns_events.json"),
    ]
    results = []
    for title, fname in files:
        fpath = sample_dir / fname
        if fpath.exists():
            content = fpath.read_text(encoding="utf-8")
            res = ingest_raw_log_payload(title, fname, content, origin_type="sample", auto_detect=False)
            results.append(res)
    with get_db() as conn:
        det = run_detection_engine(conn, trigger_source="sample_data_bundle")
    return {"loaded_datasets": results, "detection_summary": det}

@app.delete("/api/sample-data/clear")
def clear_sample_and_simulated_data():
    with get_db() as conn:
        conn.execute("DELETE FROM events WHERE origin_type IN ('sample', 'simulated')")
        conn.execute("DELETE FROM imported_datasets WHERE origin_type IN ('sample', 'simulated')")
        conn.execute("DELETE FROM alerts WHERE origin_type IN ('sample', 'simulated')")
        log_audit(conn, "CLEAR_DEMO_DATA", "system", "demo", "Cleared all sample and simulated demonstration data.")
    return {"status": "cleared"}

# Advanced Search Parser (Safe Parameterized Converter — never constructs raw SQL from user values)
ADV_QUERY_TOKEN_RE = re.compile(r"""(source_ip|destination_ip|username|hostname|event_type|source|event_id|severity|origin_type)\s*=\s*(?:"([^"]+)"|'([^']+)'|(\S+))""")

@app.get("/api/events")
def query_events(
    q: Optional[str] = None,
    advanced_query: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    username: Optional[str] = None,
    hostname: Optional[str] = None,
    event_type: Optional[str] = None,
    source: Optional[str] = None,
    event_id: Optional[str] = None,
    severity: Optional[str] = None,
    origin_type: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    sort_by: str = Query(default="timestamp"),
    sort_dir: str = Query(default="desc"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
):
    allowed_sorts = {"timestamp", "severity", "source", "hostname", "event_type", "source_ip", "username"}
    if sort_by not in allowed_sorts:
        sort_by = "timestamp"
    direction = "ASC" if sort_dir.lower() == "asc" else "DESC"

    clauses = ["1=1"]
    params: List[Any] = []

    if q:
        clauses.append("(raw_message LIKE ? OR hostname LIKE ? OR username LIKE ? OR source_ip LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"])

    field_filters = {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "username": username,
        "hostname": hostname,
        "event_type": event_type,
        "source": source,
        "event_id": event_id,
        "severity": severity,
        "origin_type": origin_type,
    }
    if advanced_query:
        for match in ADV_QUERY_TOKEN_RE.finditer(advanced_query):
            col = match.group(1)
            val = match.group(2) or match.group(3) or match.group(4)
            field_filters[col] = val

    for col, val in field_filters.items():
        if val and val != "All":
            clauses.append(f"{col} = ?")
            params.append(val)

    if start_time:
        clauses.append("timestamp >= ?")
        params.append(start_time)
    if end_time:
        clauses.append("timestamp <= ?")
        params.append(end_time)

    where_sql = " AND ".join(clauses)
    offset = (page - 1) * page_size

    with get_db() as conn:
        total = conn.execute(f"SELECT COUNT(*) AS c FROM events WHERE {where_sql}", params).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM events WHERE {where_sql} ORDER BY {sort_by} {direction} LIMIT ? OFFSET ?",
            params + [page_size, offset],
        ).fetchall()
        events = []
        for r in rows:
            d = dict(r)
            try:
                d["normalized_data"] = json.loads(d["normalized_data"])
            except Exception:
                pass
            events.append(d)

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "events": events,
    }

@app.post("/api/detection/run")
def trigger_detection_run():
    with get_db() as conn:
        return run_detection_engine(conn, trigger_source="manual_analyst_trigger")

@app.get("/api/rules")
def list_detection_rules():
    with get_db() as conn:
        rules = [dict(r) for r in conn.execute("SELECT * FROM detection_rules ORDER BY rule_id").fetchall()]
        history = [dict(r) for r in conn.execute("SELECT * FROM detection_execution_history ORDER BY id DESC LIMIT 15").fetchall()]
    return {"rules": rules, "execution_history": history}

@app.patch("/api/rules/{rule_id}")
def update_detection_rule(rule_id: str, req: RuleUpdateRequest):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM detection_rules WHERE rule_id = ?", (rule_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Detection rule not found.")
        enabled = (1 if req.enabled else 0) if req.enabled is not None else row["enabled"]
        thresh = req.threshold_count if req.threshold_count is not None else row["threshold_count"]
        window = req.time_window_seconds if req.time_window_seconds is not None else row["time_window_seconds"]
        sev = req.severity if req.severity in {"Critical", "High", "Medium", "Low"} else row["severity"]
        now = utc_now_iso()
        conn.execute(
            """UPDATE detection_rules
               SET enabled = ?, threshold_count = ?, time_window_seconds = ?, severity = ?, updated_at = ?
               WHERE rule_id = ?""",
            (enabled, thresh, window, sev, now, rule_id),
        )
        log_audit(conn, "UPDATE_RULE", "detection_rule", rule_id, f"Updated {rule_id}: enabled={bool(enabled)}, threshold={thresh}, window={window}s, severity={sev}.")
        updated = dict(conn.execute("SELECT * FROM detection_rules WHERE rule_id = ?", (rule_id,)).fetchone())
    return updated

@app.get("/api/alerts")
def list_alerts(severity: Optional[str] = None, status: Optional[str] = None):
    clauses = ["1=1"]
    params: List[Any] = []
    if severity and severity != "All":
        clauses.append("severity = ?")
        params.append(severity)
    if status and status != "All":
        clauses.append("status = ?")
        params.append(status)
    where_sql = " AND ".join(clauses)
    with get_db() as conn:
        rows = conn.execute(f"SELECT * FROM alerts WHERE {where_sql} ORDER BY created_at DESC", params).fetchall()
        alerts = []
        for r in rows:
            d = dict(r)
            d["investigation_notes"] = json.loads(d.get("investigation_notes") or "[]")
            ev_rows = conn.execute("SELECT * FROM alert_evidence WHERE alert_id = ?", (d["alert_id"],)).fetchall()
            d["evidence"] = [dict(x) for x in ev_rows]
            alerts.append(d)
    return {"alerts": alerts}

@app.patch("/api/alerts/{alert_id}")
def update_alert(alert_id: str, req: AlertUpdateRequest):
    allowed_statuses = {"New", "Acknowledged", "Investigating", "Escalated", "Resolved", "False Positive"}
    with get_db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found.")
        status = req.status if req.status in allowed_statuses else row["status"]
        analyst = req.assigned_analyst if req.assigned_analyst is not None else row["assigned_analyst"]
        notes = json.loads(row["investigation_notes"] or "[]")
        now = utc_now_iso()
        if req.note and req.note.strip():
            notes.append({"author": req.actor, "timestamp": now, "note": req.note.strip()})
        conn.execute(
            "UPDATE alerts SET status = ?, assigned_analyst = ?, investigation_notes = ?, updated_at = ? WHERE alert_id = ?",
            (status, analyst, json.dumps(notes), now, alert_id),
        )
        log_audit(conn, "UPDATE_ALERT", "alert", alert_id, f"Alert {alert_id} updated: status='{status}', assignee='{analyst}'.")
        updated = dict(conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone())
        updated["investigation_notes"] = json.loads(updated["investigation_notes"])
    return updated

@app.get("/api/incidents")
def list_incidents():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
        incidents = []
        for r in rows:
            d = dict(r)
            d["related_alerts"] = json.loads(d.get("related_alerts") or "[]")
            d["iocs"] = json.loads(d.get("iocs") or "[]")
            notes = conn.execute("SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY id ASC", (d["incident_id"],)).fetchall()
            d["timeline"] = [dict(n) for n in notes]
            incidents.append(d)
    return {"incidents": incidents}

@app.post("/api/incidents")
def create_incident(req: IncidentCreateRequest):
    inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    now = utc_now_iso()
    with get_db() as conn:
        conn.execute(
            """INSERT INTO incidents
            (incident_id, title, description, severity, status, assigned_analyst, related_alerts, iocs, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'New', ?, ?, ?, ?, ?)""",
            (
                inc_id, req.title, req.description, req.severity,
                req.assigned_analyst, json.dumps(req.related_alerts),
                json.dumps(req.iocs), now, now,
            ),
        )
        conn.execute(
            "INSERT INTO incident_notes (incident_id, author, note_type, content, created_at) VALUES (?, ?, 'lifecycle', ?, ?)",
            (inc_id, req.assigned_analyst, f"Incident created with severity {req.severity} and status 'New'.", now),
        )
        for aid in req.related_alerts:
            conn.execute("UPDATE alerts SET status = 'Escalated', updated_at = ? WHERE alert_id = ?", (now, aid))
        log_audit(conn, "CREATE_INCIDENT", "incident", inc_id, f"Created incident '{req.title}' ({req.severity}).")
        row = dict(conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (inc_id,)).fetchone())
        row["related_alerts"] = json.loads(row["related_alerts"])
        row["iocs"] = json.loads(row["iocs"])
        row["timeline"] = [dict(n) for n in conn.execute("SELECT * FROM incident_notes WHERE incident_id = ?", (inc_id,)).fetchall()]
    return row

@app.patch("/api/incidents/{incident_id}")
def update_incident(incident_id: str, req: IncidentUpdateRequest):
    allowed_lifecycle = {"New", "Triage", "Investigation", "Containment", "Resolved", "Closed"}
    with get_db() as conn:
        row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found.")
        now = utc_now_iso()
        status = req.status if req.status in allowed_lifecycle else row["status"]
        sev = req.severity if req.severity in {"Critical", "High", "Medium", "Low"} else row["severity"]
        analyst = req.assigned_analyst if req.assigned_analyst is not None else row["assigned_analyst"]
        res_sum = req.resolution_summary if req.resolution_summary is not None else row["resolution_summary"]
        iocs = json.dumps(req.iocs) if req.iocs is not None else row["iocs"]
        closed_at = now if status in {"Resolved", "Closed"} and not row["closed_at"] else row["closed_at"]

        conn.execute(
            """UPDATE incidents
               SET status = ?, severity = ?, assigned_analyst = ?, resolution_summary = ?, iocs = ?, updated_at = ?, closed_at = ?
               WHERE incident_id = ?""",
            (status, sev, analyst, res_sum, iocs, now, closed_at, incident_id),
        )
        if req.status and req.status != row["status"]:
            conn.execute(
                "INSERT INTO incident_notes (incident_id, author, note_type, content, created_at) VALUES (?, ?, 'status_change', ?, ?)",
                (incident_id, req.actor, f"Lifecycle status transitioned from '{row['status']}' to '{status}'.", now),
            )
        if req.note and req.note.strip():
            conn.execute(
                "INSERT INTO incident_notes (incident_id, author, note_type, content, created_at) VALUES (?, ?, 'investigation', ?, ?)",
                (incident_id, req.actor, req.note.strip(), now),
            )
        log_audit(conn, "UPDATE_INCIDENT", "incident", incident_id, f"Updated incident {incident_id}: status='{status}'.")
        updated = dict(conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone())
        updated["related_alerts"] = json.loads(updated["related_alerts"])
        updated["iocs"] = json.loads(updated["iocs"])
        updated["timeline"] = [dict(n) for n in conn.execute("SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY id ASC", (incident_id,)).fetchall()]
    return updated

@app.post("/api/threat-intel/lookup")
def lookup_ioc_endpoint(req: IOCLookupRequest):
    try:
        with get_db() as conn:
            return investigate_ioc(conn, req.ioc_value, req.analyst_notes)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/threat-intel/history")
def list_ioc_history():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM ioc_records ORDER BY last_checked DESC").fetchall()
        items = []
        for r in rows:
            d = dict(r)
            d["related_alerts"] = json.loads(d.get("related_alerts") or "[]")
            items.append(d)
    return {"iocs": items}

@app.post("/api/live/simulate")
def simulate_live_events(req: SimulationBatchRequest):
    """Generates clearly labeled synthetic security telemetry (origin_type='simulated')."""
    now = utc_now_iso()
    templates = [
        {"source": "linux_auth", "hostname": "sim-bastion-dhaka", "username": "root", "source_ip": "192.0.2.88", "event_type": "authentication_failure", "event_id": "SSH_AUTH_FAIL", "severity": "Medium", "message": "[SIMULATION MODE] Failed password for root from 192.0.2.88 port 52410 ssh2"},
        {"source": "windows_security", "hostname": "SIM-DC01.corp.example", "username": "svc_sql", "source_ip": "198.51.100.44", "event_type": "authentication_failure", "event_id": "4625", "severity": "Medium", "message": "[SIMULATION MODE] Windows Event 4625: Failed logon for account svc_sql from 198.51.100.44"},
        {"source": "firewall", "hostname": "sim-fw-edge", "username": None, "source_ip": "203.0.113.155", "destination_ip": "10.10.0.50", "destination_port": random.choice([22, 80, 443, 3389, 8080]), "event_type": "network_connection", "event_id": "FW_SYN", "severity": "Low", "message": "[SIMULATION MODE] Firewall telemetry packet logged from 203.0.113.155"},
        {"source": "dns_resolver", "hostname": "sim-dns-01", "username": None, "source_ip": "10.10.9.14", "query_domain": "f9a8b7c6d5e4f3a2b1c09988776655.tunnel.sim-test.example", "event_type": "dns_query", "event_id": "DNS_TXT", "severity": "High", "message": "[SIMULATION MODE] High-entropy TXT DNS query from 10.10.9.14"},
    ]
    batch = [ {**random.choice(templates), "timestamp": now} for _ in range(req.count) ]
    res = ingest_raw_log_payload(
        "Simulated Live Telemetry Stream",
        "simulated_stream.json",
        json.dumps(batch),
        origin_type="simulated",
        auto_detect=True,
    )
    return {"simulation_mode": True, "ingested": res}

@app.get("/api/reports/summary")
def get_report_summary(
    report_type: str = "executive_soc_summary",
    severity: Optional[str] = None,
    source: Optional[str] = None,
):
    with get_db() as conn:
        return gather_report_data(conn, report_type, severity, source)

@app.get("/api/reports/export")
def export_report(
    format: str = Query(default="pdf", regex="^(pdf|csv|json)$"),
    report_type: str = Query(default="executive_soc_summary"),
    severity: Optional[str] = None,
    source: Optional[str] = None,
):
    with get_db() as conn:
        data = gather_report_data(conn, report_type, severity, source)
        log_audit(conn, "EXPORT_REPORT", "report", format.upper(), f"Exported {report_type} in {format.upper()} format.")

    if format == "json":
        return Response(
            content=json.dumps(data, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="sentinel_soc_{report_type}.json"'},
        )
    if format == "csv":
        csv_text = generate_csv_report(data)
        return Response(
            content=csv_text,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="sentinel_soc_{report_type}.csv"'},
        )
    pdf_bytes = generate_pdf_report(data)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="sentinel_soc_{report_type}.pdf"'},
    )

@app.get("/api/settings")
def get_settings():
    with get_db() as conn:
        rows = conn.execute("SELECT key, value, updated_at FROM app_settings").fetchall()
        cfg = {r["key"]: r["value"] for r in rows}
    return {
        "settings": cfg,
        "external_integrations": {
            "virustotal_configured": bool(settings.VIRUSTOTAL_API_KEY),
            "abuseipdb_configured": bool(settings.ABUSEIPDB_API_KEY),
            "otx_configured": bool(settings.OTX_API_KEY),
        },
        "developer": get_developer_profile(),
    }

@app.put("/api/settings")
def update_settings(req: SettingsUpdateRequest):
    now = utc_now_iso()
    with get_db() as conn:
        for k, v in req.settings.items():
            conn.execute(
                "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                (str(k), str(v), now),
            )
        log_audit(conn, "UPDATE_SETTINGS", "settings", "app_settings", f"Updated {len(req.settings)} setting keys.")
    return get_settings()

@app.post("/api/settings/backup")
def create_database_backup():
    ts = utc_now_iso().replace(":", "").replace("-", "")
    backup_file = BACKUP_DIR / f"sentinel_soc_backup_{ts}.db"
    shutil.copy2(settings.DATABASE_PATH, backup_file)
    with get_db() as conn:
        log_audit(conn, "BACKUP_DATABASE", "database", backup_file.name, "Created SQLite database snapshot backup.")
    return {"status": "backed_up", "backup_filename": backup_file.name, "size_bytes": backup_file.stat().st_size}
