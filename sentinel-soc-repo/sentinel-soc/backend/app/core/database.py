"""Normalized SQLite/PostgreSQL-compatible relational database layer with migrations and indexes."""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from app.core.config import settings

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS log_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    source_type TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS imported_datasets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    filename TEXT NOT NULL,
    file_format TEXT NOT NULL,
    origin_type TEXT NOT NULL DEFAULT 'uploaded',
    total_records INTEGER NOT NULL DEFAULT 0,
    imported_records INTEGER NOT NULL DEFAULT 0,
    rejected_records INTEGER NOT NULL DEFAULT 0,
    rejection_reasons TEXT NOT NULL DEFAULT '[]',
    sha256_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_hash TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    ingestion_timestamp TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    origin_type TEXT NOT NULL DEFAULT 'uploaded',
    source TEXT NOT NULL,
    hostname TEXT NOT NULL,
    username TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    destination_port INTEGER,
    event_type TEXT NOT NULL,
    event_id TEXT,
    severity TEXT NOT NULL DEFAULT 'Low',
    raw_message TEXT NOT NULL,
    normalized_data TEXT NOT NULL,
    FOREIGN KEY (dataset_id) REFERENCES imported_datasets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_username ON events(username);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_dataset_id ON events(dataset_id);

CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    detection_logic TEXT NOT NULL,
    severity TEXT NOT NULL,
    mitre_tactic TEXT,
    mitre_technique TEXT,
    threshold_count INTEGER NOT NULL DEFAULT 5,
    time_window_seconds INTEGER NOT NULL DEFAULT 300,
    config_json TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER NOT NULL DEFAULT 1,
    recommended_steps TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    dedup_key TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    source_ip TEXT,
    username TEXT,
    hostname TEXT,
    first_observed TEXT NOT NULL,
    last_observed TEXT NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 1,
    mitre_technique TEXT,
    recommended_actions TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New',
    assigned_analyst TEXT DEFAULT 'Tier-1 Analyst',
    origin_type TEXT NOT NULL DEFAULT 'uploaded',
    investigation_notes TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (rule_id) REFERENCES detection_rules(rule_id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);

CREATE TABLE IF NOT EXISTS alert_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    event_id INTEGER NOT NULL,
    evidence_summary TEXT NOT NULL,
    FOREIGN KEY (alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New',
    assigned_analyst TEXT NOT NULL DEFAULT 'Wasif Karim (SOC Tier-2)',
    related_alerts TEXT NOT NULL DEFAULT '[]',
    iocs TEXT NOT NULL DEFAULT '[]',
    resolution_summary TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closed_at TEXT
);

CREATE TABLE IF NOT EXISTS incident_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    author TEXT NOT NULL,
    note_type TEXT NOT NULL DEFAULT 'investigation',
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ioc_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_value TEXT NOT NULL UNIQUE,
    ioc_type TEXT NOT NULL,
    classification TEXT NOT NULL,
    confidence TEXT NOT NULL,
    is_private_or_reserved INTEGER NOT NULL DEFAULT 0,
    local_sightings INTEGER NOT NULL DEFAULT 0,
    related_alerts TEXT NOT NULL DEFAULT '[]',
    external_intel_status TEXT NOT NULL,
    external_intel_summary TEXT NOT NULL,
    analyst_notes TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_checked TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS detection_execution_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    executed_at TEXT NOT NULL,
    trigger_source TEXT NOT NULL,
    events_evaluated INTEGER NOT NULL,
    rules_evaluated INTEGER NOT NULL,
    alerts_generated INTEGER NOT NULL,
    duration_ms REAL NOT NULL,
    details_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    details TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

DEFAULT_RULES = [
    {
        "rule_id": "RULE-001",
        "name": "SSH Brute-Force Detection",
        "description": "Detects repeated failed SSH authentication attempts originating from the same source IP within a short time window.",
        "detection_logic": "Count(source == 'linux_auth' AND event_type == 'authentication_failure') grouped by source_ip >= threshold within time_window_seconds.",
        "severity": "High",
        "mitre_tactic": "Credential Access (TA0006)",
        "mitre_technique": "T1110.001 — Brute Force: Password Guessing",
        "threshold_count": 5,
        "time_window_seconds": 300,
        "config_json": json.dumps({"protocol": "ssh", "target_event_type": "authentication_failure"}),
        "enabled": 1,
        "recommended_steps": "1. Verify whether the source IP belongs to an authorized jump host or administrator VPN.\n2. Check if any subsequent Accepted login occurred from the same IP.\n3. Block offending external IP at perimeter firewall / fail2ban and rotate affected credentials if compromise is suspected."
    },
    {
        "rule_id": "RULE-002",
        "name": "Multiple Failed Login Attempts (Account Lockout Risk)",
        "description": "Detects repeated authentication failures targeting a single username across Linux or Windows authentication logs, indicating targeted password guessing.",
        "detection_logic": "Count(event_type == 'authentication_failure') grouped by username >= threshold within time_window_seconds.",
        "severity": "Medium",
        "mitre_tactic": "Credential Access (TA0006)",
        "mitre_technique": "T1110.001 — Brute Force: Password Guessing",
        "threshold_count": 4,
        "time_window_seconds": 300,
        "config_json": json.dumps({"group_by": "username"}),
        "enabled": 1,
        "recommended_steps": "1. Contact account owner to verify if they are experiencing client misconfiguration or forgotten password.\n2. Inspect source IPs attempting login against the account.\n3. Enforce MFA and temporary account lockout policy."
    },
    {
        "rule_id": "RULE-003",
        "name": "Password Spraying Indicator",
        "description": "Identifies a single source IP attempting authentication against multiple distinct usernames within a configurable time window. Note: Unusual multi-account failures warrant investigation and are not automatically confirmed attacks without context.",
        "detection_logic": "DistinctCount(username where event_type == 'authentication_failure') grouped by source_ip >= threshold within time_window_seconds.",
        "severity": "High",
        "mitre_tactic": "Credential Access (TA0006)",
        "mitre_technique": "T1110.003 — Brute Force: Password Spraying",
        "threshold_count": 4,
        "time_window_seconds": 600,
        "config_json": json.dumps({"distinct_usernames_min": 4}),
        "enabled": 1,
        "recommended_steps": "1. Review the list of targeted usernames (e.g., service accounts, default admin names).\n2. Determine if any targeted account succeeded in logging in.\n3. Verify if source IP is an internal scanner or unauthorized external host."
    },
    {
        "rule_id": "RULE-004",
        "name": "Suspicious Successful Login Following Failures",
        "description": "Correlates a successful login event occurring shortly after repeated failed login attempts from the same source IP or target account.",
        "detection_logic": "Sequence(Count(authentication_failure) >= threshold followed by authentication_success from same source_ip or username within window).",
        "severity": "Critical",
        "mitre_tactic": "Initial Access / Credential Access (TA0001 / TA0006)",
        "mitre_technique": "T1078 — Valid Accounts / T1110 — Brute Force",
        "threshold_count": 3,
        "time_window_seconds": 600,
        "config_json": json.dumps({"correlate_success": True}),
        "enabled": 1,
        "recommended_steps": "1. Treat as potential active account compromise and escalate immediately to Tier-2 Incident Response.\n2. Inspect post-authentication commands or process creation events (Event ID 4688 / sudo logs).\n3. Isolate host or revoke active sessions for the affected user account."
    },
    {
        "rule_id": "RULE-005",
        "name": "Privileged Account Activity & Escalation",
        "description": "Detects high-privilege logons, Windows Event ID 4672 (Special Privileges Assigned), sensitive sudo command execution (/etc/shadow, root shell), or suspicious process creation (Event ID 4688 encoded PowerShell).",
        "detection_logic": "event_type IN ('privilege_escalation', 'process_creation') OR event_id IN ('4672', '4688') OR sudo sensitive command match.",
        "severity": "Critical",
        "mitre_tactic": "Privilege Escalation / Execution (TA0004 / TA0002)",
        "mitre_technique": "T1548.003 — Sudo and Sudo Caching / T1059.001 — PowerShell",
        "threshold_count": 1,
        "time_window_seconds": 300,
        "config_json": json.dumps({"watch_users": ["root", "Administrator"], "watch_event_ids": ["4672", "4688"]}),
        "enabled": 1,
        "recommended_steps": "1. Validate change management ticket or administrative authorization for the privileged session.\n2. Decode any obfuscated/encoded command line arguments (e.g., Base64 PowerShell).\n3. Audit child processes and file modifications made under elevated privileges."
    },
    {
        "rule_id": "RULE-006",
        "name": "Unusual Login Time (Off-Hours Authentication)",
        "description": "Detects successful authentication activity outside configurable expected business hours (00:00–05:00 UTC). Note: Off-hours timing alone does not prove malicious activity and requires correlation with user shift schedules.",
        "detection_logic": "event_type == 'authentication_success' AND UTC hour BETWEEN start_off_hour AND end_off_hour.",
        "severity": "Low",
        "mitre_tactic": "Initial Access (TA0001)",
        "mitre_technique": "T1078 — Valid Accounts",
        "threshold_count": 1,
        "time_window_seconds": 3600,
        "config_json": json.dumps({"off_hours_utc_start": 0, "off_hours_utc_end": 5}),
        "enabled": 1,
        "recommended_steps": "1. Note that unusual login timing alone is an anomaly indicator, not proof of compromise.\n2. Verify whether the user is on-call, located in a different timezone, or running scheduled maintenance.\n3. Correlate with source IP reputation and subsequent session commands."
    },
    {
        "rule_id": "RULE-007",
        "name": "Suspicious IP Multi-Event Activity",
        "description": "Identifies source IP addresses associated with high aggregate security event volume or multiple distinct failure categories across hosts.",
        "detection_logic": "Count(security events from source_ip) >= threshold across auth failures, privilege events, or network blocks.",
        "severity": "Medium",
        "mitre_tactic": "Reconnaissance / Credential Access (TA0043 / TA0006)",
        "mitre_technique": "T1595 — Active Scanning / T1110 — Brute Force",
        "threshold_count": 6,
        "time_window_seconds": 900,
        "config_json": json.dumps({"min_total_events": 6}),
        "enabled": 1,
        "recommended_steps": "1. Query the Threat Intelligence module for historical sightings of the source IP.\n2. Identify all destination hosts targeted by this IP.\n3. Apply rate-limiting or perimeter block rules if activity is unauthorized."
    },
    {
        "rule_id": "RULE-008",
        "name": "Port Scan Indicators (Network / Firewall Logs)",
        "description": "Identifies a single source IP connecting to multiple distinct destination ports within a short time window based on firewall/network connection logs (never triggered from authentication logs alone).",
        "detection_logic": "source IN ('firewall', 'network') AND event_type == 'network_connection' AND DistinctCount(destination_port) by source_ip >= threshold.",
        "severity": "Medium",
        "mitre_tactic": "Discovery (TA0007)",
        "mitre_technique": "T1046 — Network Service Discovery",
        "threshold_count": 5,
        "time_window_seconds": 120,
        "config_json": json.dumps({"min_distinct_ports": 5}),
        "enabled": 1,
        "recommended_steps": "1. Inspect firewall actions (Allowed vs Blocked) for each probed destination port.\n2. Verify whether any open service (e.g., 80, 443, 22) received follow-up exploitation traffic.\n3. Confirm whether source IP is an authorized vulnerability scanner."
    },
    {
        "rule_id": "RULE-009",
        "name": "Suspicious DNS Activity (Tunneling / DGA Pattern)",
        "description": "Identifies DNS queries with unusually long subdomains, high character entropy, or known suspicious tunneling patterns in DNS resolver logs.",
        "detection_logic": "event_type == 'dns_query' AND (subdomain_length >= 28 OR contains suspicious tunneling keywords) >= threshold.",
        "severity": "High",
        "mitre_tactic": "Command and Control / Exfiltration (TA0011 / TA0010)",
        "mitre_technique": "T1071.004 — Application Layer Protocol: DNS",
        "threshold_count": 3,
        "time_window_seconds": 300,
        "config_json": json.dumps({"min_subdomain_length": 28}),
        "enabled": 1,
        "recommended_steps": "1. Inspect the querying internal host (source_ip) for unauthorized background processes.\n2. Analyze queried base domain and TXT/NULL record frequency.\n3. Sinkhole confirmed malicious C2 domain at internal DNS resolver."
    },
    {
        "rule_id": "RULE-010",
        "name": "Event Flooding / High-Frequency Log Anomaly",
        "description": "Detects unusually high rapid event frequency (burst flooding / DoS / automated Enumeration) from a single source IP or host within a tight window.",
        "detection_logic": "Count(events by source_ip or hostname within 60s window) >= threshold.",
        "severity": "Medium",
        "mitre_tactic": "Impact / Collection (TA0040)",
        "mitre_technique": "T1499 — Endpoint Denial of Service",
        "threshold_count": 8,
        "time_window_seconds": 60,
        "config_json": json.dumps({"burst_window_seconds": 60}),
        "enabled": 1,
        "recommended_steps": "1. Check API gateway or service health metrics for latency spikes.\n2. Verify rate-limiting rules on the targeted endpoint.\n3. Throttle or block abusive client IP."
    },
]

DEFAULT_SETTINGS = {
    "display_timezone": "Asia/Dhaka",
    "storage_timezone": "UTC",
    "dashboard_refresh_seconds": "15",
    "log_retention_days": "90",
    "auto_detect_on_ingest": "true",
    "enable_toast_notifications": "true",
    "max_upload_mb": "10",
    "simulator_default_eps": "2",
}

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

@contextmanager
def get_db():
    conn = sqlite3.connect(settings.DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    now = utc_now_iso()
    with get_db() as conn:
        conn.executescript(SCHEMA_SQL)
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?)",
            ("0001_initial_sentinel_soc", now, "Initial normalized SENTINEL SOC schema with 13 tables and indexes"),
        )
        for r in DEFAULT_RULES:
            conn.execute(
                """INSERT OR IGNORE INTO detection_rules
                (rule_id, name, description, detection_logic, severity, mitre_tactic, mitre_technique,
                 threshold_count, time_window_seconds, config_json, enabled, recommended_steps, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    r["rule_id"], r["name"], r["description"], r["detection_logic"],
                    r["severity"], r["mitre_tactic"], r["mitre_technique"],
                    r["threshold_count"], r["time_window_seconds"], r["config_json"],
                    r["enabled"], r["recommended_steps"], now,
                ),
            )
        for k, v in DEFAULT_SETTINGS.items():
            conn.execute(
                "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)",
                (k, v, now),
            )
        sources = [
            ("linux_auth", "syslog", "Linux PAM / OpenSSH / sudo authentication logs"),
            ("windows_security", "evtx_export", "Windows Security Event Log CSV/JSON exports (4624, 4625, 4672, 4688)"),
            ("firewall", "network_telemetry", "Perimeter and host firewall connection logs"),
            ("dns_resolver", "dns_telemetry", "Internal DNS resolver query logs"),
            ("app_gateway", "application", "Generic structured and semi-structured application logs"),
        ]
        for s_name, s_type, s_desc in sources:
            conn.execute(
                "INSERT OR IGNORE INTO log_sources (name, source_type, description, created_at) VALUES (?, ?, ?, ?)",
                (s_name, s_type, s_desc, now),
            )

def log_audit(conn, action_type: str, target_type: str, target_id: str, details: str, actor: str = "Wasif Karim"):
    conn.execute(
        "INSERT INTO audit_logs (timestamp, actor, action_type, target_type, target_id, details) VALUES (?, ?, ?, ?, ?, ?)",
        (utc_now_iso(), actor, action_type, target_type, str(target_id or ""), details),
    )
