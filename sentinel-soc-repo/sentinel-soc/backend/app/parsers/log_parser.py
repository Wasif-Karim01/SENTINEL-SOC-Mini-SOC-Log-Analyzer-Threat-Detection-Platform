"""Multi-format security log parser and event normalization engine."""
import csv
import hashlib
import io
import json
import re
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Any

SYSLOG_SSH_FAILED_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>[\w\-\.]+)\s+sshd\[\d+\]:\s+Failed\s+(?P<method>\w+)\s+for\s+(?:invalid user\s+)?(?P<user>[\w\-\.]+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)"
)
SYSLOG_SSH_ACCEPTED_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>[\w\-\.]+)\s+sshd\[\d+\]:\s+Accepted\s+(?P<method>\w+)\s+for\s+(?P<user>[\w\-\.]+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)"
)
SYSLOG_SUDO_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>[\w\-\.]+)\s+sudo:\s+(?P<user>[\w\-\.]+)\s*:.*USER=(?P<target_user>[\w\-\.]+)\s*;\s*COMMAND=(?P<cmd>.+)$"
)
GENERIC_KV_RE = re.compile(r"""(\w+)=("[^"]*"|\S+)""")

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

def normalize_timestamp(raw_ts: str, default_year: int = 2026) -> str:
    raw_ts = (raw_ts or "").strip()
    if not raw_ts:
        raise ValueError("Missing timestamp")
    try:
        if raw_ts.endswith("Z"):
            dt = datetime.fromisoformat(raw_ts[:-1]).replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        dt = datetime.fromisoformat(raw_ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass
    # Syslog format: Nov 12 02:15:10
    parts = raw_ts.split()
    if len(parts) == 3 and parts[0] in MONTH_MAP:
        month = MONTH_MAP[parts[0]]
        day = int(parts[1])
        h, m, s = [int(x) for x in parts[2].split(":")]
        dt = datetime(default_year, month, day, h, m, s, tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    raise ValueError(f"Unsupported timestamp format: {raw_ts}")

def compute_event_hash(dataset_id: str, timestamp: str, raw_message: str, idx: int) -> str:
    payload = f"{dataset_id}|{timestamp}|{raw_message}|{idx}".encode("utf-8", errors="ignore")
    return hashlib.sha256(payload).hexdigest()

def parse_syslog_line(line: str, dataset_id: str, origin_type: str, idx: int) -> Dict[str, Any]:
    m_fail = SYSLOG_SSH_FAILED_RE.match(line)
    if m_fail:
        d = m_fail.groupdict()
        ts = normalize_timestamp(f"{d['month']} {d['day']} {d['time']}")
        norm = {
            "auth_method": d["method"],
            "source_port": int(d["port"]),
            "invalid_user": "invalid user" in line,
            "protocol": "ssh",
        }
        return {
            "event_hash": compute_event_hash(dataset_id, ts, line, idx),
            "timestamp": ts,
            "dataset_id": dataset_id,
            "origin_type": origin_type,
            "source": "linux_auth",
            "hostname": d["host"],
            "username": d["user"],
            "source_ip": d["ip"],
            "destination_ip": None,
            "destination_port": 22,
            "event_type": "authentication_failure",
            "event_id": "SSH_AUTH_FAIL",
            "severity": "Medium",
            "raw_message": line,
            "normalized_data": json.dumps(norm),
        }

    m_acc = SYSLOG_SSH_ACCEPTED_RE.match(line)
    if m_acc:
        d = m_acc.groupdict()
        ts = normalize_timestamp(f"{d['month']} {d['day']} {d['time']}")
        norm = {
            "auth_method": d["method"],
            "source_port": int(d["port"]),
            "protocol": "ssh",
        }
        return {
            "event_hash": compute_event_hash(dataset_id, ts, line, idx),
            "timestamp": ts,
            "dataset_id": dataset_id,
            "origin_type": origin_type,
            "source": "linux_auth",
            "hostname": d["host"],
            "username": d["user"],
            "source_ip": d["ip"],
            "destination_ip": None,
            "destination_port": 22,
            "event_type": "authentication_success",
            "event_id": "SSH_AUTH_OK",
            "severity": "Low",
            "raw_message": line,
            "normalized_data": json.dumps(norm),
        }

    m_sudo = SYSLOG_SUDO_RE.match(line)
    if m_sudo:
        d = m_sudo.groupdict()
        ts = normalize_timestamp(f"{d['month']} {d['day']} {d['time']}")
        cmd = d["cmd"].strip()
        is_sensitive = any(k in cmd for k in ["/etc/shadow", "/etc/sudoers", "/bin/bash", "chmod 777", "visudo"])
        norm = {
            "target_user": d["target_user"],
            "command": cmd,
            "sensitive_command": is_sensitive,
        }
        return {
            "event_hash": compute_event_hash(dataset_id, ts, line, idx),
            "timestamp": ts,
            "dataset_id": dataset_id,
            "origin_type": origin_type,
            "source": "linux_auth",
            "hostname": d["host"],
            "username": d["user"],
            "source_ip": "127.0.0.1",
            "destination_ip": None,
            "destination_port": None,
            "event_type": "privilege_escalation",
            "event_id": "SUDO_EXEC",
            "severity": "High" if is_sensitive else "Medium",
            "raw_message": line,
            "normalized_data": json.dumps(norm),
        }

    # Try generic key=value line
    kvs = {k: v.strip('"') for k, v in GENERIC_KV_RE.findall(line)}
    if "timestamp" in kvs and ("event_type" in kvs or "msg" in kvs):
        ts = normalize_timestamp(kvs["timestamp"])
        return {
            "event_hash": compute_event_hash(dataset_id, ts, line, idx),
            "timestamp": ts,
            "dataset_id": dataset_id,
            "origin_type": origin_type,
            "source": kvs.get("source", "application"),
            "hostname": kvs.get("hostname", kvs.get("host", "app-host-01")),
            "username": kvs.get("username", kvs.get("user")),
            "source_ip": kvs.get("source_ip", kvs.get("src_ip")),
            "destination_ip": kvs.get("destination_ip", kvs.get("dst_ip")),
            "destination_port": int(kvs["dst_port"]) if kvs.get("dst_port", "").isdigit() else None,
            "event_type": kvs.get("event_type", "application_event"),
            "event_id": kvs.get("event_id", "APP_LOG"),
            "severity": kvs.get("severity", "Low"),
            "raw_message": line,
            "normalized_data": json.dumps(kvs),
        }

    raise ValueError("Unrecognized syslog or key-value log pattern")

def normalize_structured_record(rec: Dict[str, Any], dataset_id: str, origin_type: str, idx: int) -> Dict[str, Any]:
    if not isinstance(rec, dict):
        raise ValueError("Record must be a JSON object or CSV row mapping")
    raw_ts = str(rec.get("timestamp") or rec.get("TimeCreated") or rec.get("time") or "").strip()
    ts = normalize_timestamp(raw_ts)
    ev_id = str(rec.get("event_id") or rec.get("EventID") or "").strip() or None
    ev_type = str(rec.get("event_type") or "").strip()

    # Windows Event ID automatic mapping
    if ev_id == "4624" and not ev_type:
        ev_type = "authentication_success"
    elif ev_id == "4625" and not ev_type:
        ev_type = "authentication_failure"
    elif ev_id == "4672" and not ev_type:
        ev_type = "privilege_escalation"
    elif ev_id == "4688" and not ev_type:
        ev_type = "process_creation"
    elif not ev_type:
        ev_type = "generic_security_event"

    source = str(rec.get("source") or ("windows_security" if ev_id in {"4624", "4625", "4672", "4688"} else "application")).strip()
    hostname = str(rec.get("hostname") or rec.get("Computer") or "unknown-host").strip()
    username = rec.get("username") or rec.get("TargetUserName") or None
    source_ip = rec.get("source_ip") or rec.get("IpAddress") or None
    dest_ip = rec.get("destination_ip") or None
    dest_port_raw = rec.get("destination_port")
    dest_port = int(dest_port_raw) if str(dest_port_raw or "").isdigit() else None

    severity = str(rec.get("severity") or "").strip()
    if not severity:
        if ev_type in {"privilege_escalation", "process_creation"}:
            severity = "High"
        elif ev_type in {"authentication_failure", "dns_query", "http_request_flood"}:
            severity = "Medium"
        else:
            severity = "Low"

    msg = str(rec.get("message") or rec.get("raw_message") or json.dumps(rec))
    return {
        "event_hash": compute_event_hash(dataset_id, ts, msg, idx),
        "timestamp": ts,
        "dataset_id": dataset_id,
        "origin_type": origin_type,
        "source": source,
        "hostname": hostname,
        "username": str(username).strip() if username else None,
        "source_ip": str(source_ip).strip() if source_ip else None,
        "destination_ip": str(dest_ip).strip() if dest_ip else None,
        "destination_port": dest_port,
        "event_type": ev_type,
        "event_id": ev_id,
        "severity": severity,
        "raw_message": msg,
        "normalized_data": json.dumps(rec),
    }

def parse_log_content(filename: str, content: str, dataset_id: str, origin_type: str = "uploaded") -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ".log"
    parsed_events: List[Dict[str, Any]] = []
    rejected_records: List[Dict[str, Any]] = []

    if ext == ".json":
        try:
            data = json.loads(content)
            records = data if isinstance(data, list) else data.get("events", [data])
        except Exception as e:
            return [], [{"line": 1, "raw": content[:200], "reason": f"Invalid JSON syntax: {str(e)}"}]
        for idx, rec in enumerate(records, start=1):
            try:
                parsed_events.append(normalize_structured_record(rec, dataset_id, origin_type, idx))
            except Exception as e:
                rejected_records.append({"line": idx, "raw": str(rec)[:200], "reason": str(e)})
        return parsed_events, rejected_records

    if ext == ".csv":
        reader = csv.DictReader(io.StringIO(content))
        for idx, row in enumerate(reader, start=2):
            try:
                parsed_events.append(normalize_structured_record(row, dataset_id, origin_type, idx))
            except Exception as e:
                rejected_records.append({"line": idx, "raw": str(row)[:200], "reason": str(e)})
        return parsed_events, rejected_records

    # Default: .log or .txt line-by-line
    for idx, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if line.startswith("{") and line.endswith("}"):
                rec = json.loads(line)
                parsed_events.append(normalize_structured_record(rec, dataset_id, origin_type, idx))
            else:
                parsed_events.append(parse_syslog_line(line, dataset_id, origin_type, idx))
        except Exception as e:
            rejected_records.append({"line": idx, "raw": line[:200], "reason": str(e)})

    return parsed_events, rejected_records
