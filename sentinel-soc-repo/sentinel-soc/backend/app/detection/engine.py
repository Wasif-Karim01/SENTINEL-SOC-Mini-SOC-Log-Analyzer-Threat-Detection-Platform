"""Deterministic 10-Rule Threat Detection Engine for SENTINEL SOC."""
import hashlib
import json
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Any
from app.core.database import utc_now_iso, log_audit

def parse_iso(ts: str) -> datetime:
    if ts.endswith("Z"):
        return datetime.fromisoformat(ts[:-1]).replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(ts)

def make_dedup_key(rule_id: str, key_parts: List[str]) -> str:
    raw = f"{rule_id}|" + "|".join(str(p or "") for p in key_parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]

def run_detection_engine(conn, trigger_source: str = "manual", dataset_id: str = None) -> Dict[str, Any]:
    start_time = time.perf_counter()
    rules_rows = conn.execute("SELECT * FROM detection_rules WHERE enabled = 1 ORDER BY rule_id").fetchall()
    rules = {r["rule_id"]: dict(r) for r in rules_rows}

    if dataset_id:
        events_rows = conn.execute(
            "SELECT * FROM events WHERE dataset_id = ? ORDER BY timestamp ASC", (dataset_id,)
        ).fetchall()
    else:
        events_rows = conn.execute("SELECT * FROM events ORDER BY timestamp ASC").fetchall()

    events = [dict(r) for r in events_rows]
    candidates: List[Dict[str, Any]] = []

    # Group helpers
    by_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    by_user: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for ev in events:
        if ev.get("source_ip"):
            by_ip[ev["source_ip"]].append(ev)
        if ev.get("username"):
            by_user[ev["username"]].append(ev)

    # RULE-001: SSH Brute-Force Detection
    if "RULE-001" in rules:
        r = rules["RULE-001"]
        thresh = int(r["threshold_count"])
        win = int(r["time_window_seconds"])
        for ip, evs in by_ip.items():
            ssh_fails = [e for e in evs if e["source"] == "linux_auth" and e["event_type"] == "authentication_failure"]
            if len(ssh_fails) >= thresh:
                t0 = parse_iso(ssh_fails[0]["timestamp"])
                t1 = parse_iso(ssh_fails[-1]["timestamp"])
                if (t1 - t0).total_seconds() <= max(win, 300):
                    candidates.append({
                        "rule": r,
                        "dedup_key": make_dedup_key("RULE-001", [ip, ssh_fails[0]["timestamp"][:13]]),
                        "title": f"SSH Brute-Force Detected from {ip}",
                        "description": f"Detected {len(ssh_fails)} failed SSH login attempts from source IP {ip} against host {ssh_fails[0]['hostname']} within {(t1 - t0).total_seconds():.0f}s (Threshold: {thresh}).",
                        "source_ip": ip,
                        "username": ssh_fails[-1].get("username"),
                        "hostname": ssh_fails[0]["hostname"],
                        "events": ssh_fails,
                    })

    # RULE-002: Multiple Failed Login Attempts against same account
    if "RULE-002" in rules:
        r = rules["RULE-002"]
        thresh = int(r["threshold_count"])
        for user, evs in by_user.items():
            fails = [e for e in evs if e["event_type"] == "authentication_failure"]
            if len(fails) >= thresh:
                candidates.append({
                    "rule": r,
                    "dedup_key": make_dedup_key("RULE-002", [user, fails[0]["timestamp"][:13]]),
                    "title": f"Repeated Authentication Failures for Account '{user}'",
                    "description": f"Account '{user}' experienced {len(fails)} failed authentication attempts from IP {fails[0].get('source_ip', 'unknown')} on host {fails[0]['hostname']}.",
                    "source_ip": fails[0].get("source_ip"),
                    "username": user,
                    "hostname": fails[0]["hostname"],
                    "events": fails,
                })

    # RULE-003: Password Spraying Indicator
    if "RULE-003" in rules:
        r = rules["RULE-003"]
        thresh = int(r["threshold_count"])
        for ip, evs in by_ip.items():
            fails = [e for e in evs if e["event_type"] == "authentication_failure" and e.get("username")]
            distinct_users = sorted(list({e["username"] for e in fails}))
            if len(distinct_users) >= thresh:
                candidates.append({
                    "rule": r,
                    "dedup_key": make_dedup_key("RULE-003", [ip, fails[0]["timestamp"][:13]]),
                    "title": f"Password Spraying Indicator from {ip} ({len(distinct_users)} Accounts)",
                    "description": f"Source IP {ip} attempted failed logins against {len(distinct_users)} distinct usernames ({', '.join(distinct_users[:6])}). Indicator requires analyst verification to confirm malicious password spraying.",
                    "source_ip": ip,
                    "username": ", ".join(distinct_users[:3]),
                    "hostname": fails[0]["hostname"],
                    "events": fails,
                })

    # RULE-004: Suspicious Successful Login Following Failures
    if "RULE-004" in rules:
        r = rules["RULE-004"]
        thresh = int(r["threshold_count"])
        for ip, evs in by_ip.items():
            fail_streak = []
            for e in evs:
                if e["event_type"] == "authentication_failure":
                    fail_streak.append(e)
                elif e["event_type"] == "authentication_success" and len(fail_streak) >= thresh:
                    correlated = fail_streak + [e]
                    candidates.append({
                        "rule": r,
                        "dedup_key": make_dedup_key("RULE-004", [ip, e.get("username"), e["timestamp"][:16]]),
                        "title": f"Suspicious Login Success After {len(fail_streak)} Failures ({ip})",
                        "description": f"Account '{e.get('username')}' successfully authenticated from {ip} on {e['hostname']} immediately following {len(fail_streak)} failed login attempts.",
                        "source_ip": ip,
                        "username": e.get("username"),
                        "hostname": e["hostname"],
                        "events": correlated,
                    })
                    fail_streak = []

    # RULE-005: Privileged Account Activity & Escalation
    if "RULE-005" in rules:
        r = rules["RULE-005"]
        priv_events = [
            e for e in events
            if e["event_type"] in ("privilege_escalation", "process_creation")
            or str(e.get("event_id")) in ("4672", "4688", "SUDO_EXEC")
        ]
        for pe in priv_events:
            candidates.append({
                "rule": r,
                "dedup_key": make_dedup_key("RULE-005", [pe["hostname"], pe.get("event_id"), pe["timestamp"]]),
                "title": f"Privileged Activity / Escalation on {pe['hostname']} ({pe.get('username')})",
                "description": f"Privileged security event ({pe.get('event_id') or pe['event_type']}) executed by '{pe.get('username')}' on {pe['hostname']}: {pe['raw_message'][:140]}",
                "source_ip": pe.get("source_ip"),
                "username": pe.get("username"),
                "hostname": pe["hostname"],
                "events": [pe],
            })

    # RULE-006: Unusual Login Time (Off-Hours 00:00 - 05:00 UTC)
    if "RULE-006" in rules:
        r = rules["RULE-006"]
        cfg = json.loads(r.get("config_json") or "{}")
        start_hr = int(cfg.get("off_hours_utc_start", 0))
        end_hr = int(cfg.get("off_hours_utc_end", 5))
        off_hour_logins = []
        for e in events:
            if e["event_type"] == "authentication_success":
                dt = parse_iso(e["timestamp"])
                if start_hr <= dt.hour < end_hr:
                    off_hour_logins.append(e)
        if off_hour_logins:
            first_ev = off_hour_logins[0]
            candidates.append({
                "rule": r,
                "dedup_key": make_dedup_key("RULE-006", [first_ev.get("source_ip"), first_ev["timestamp"][:10]]),
                "title": f"Off-Hours Authentication Activity ({len(off_hour_logins)} Logins 00:00–05:00 UTC)",
                "description": f"Detected {len(off_hour_logins)} successful login(s) between {start_hr:02d}:00 and {end_hr:02d}:00 UTC (Users: {', '.join(sorted({x.get('username') or 'unknown' for x in off_hour_logins}))}). Note: Off-hours timing alone does not prove malicious activity.",
                "source_ip": first_ev.get("source_ip"),
                "username": first_ev.get("username"),
                "hostname": first_ev["hostname"],
                "events": off_hour_logins,
            })

    # RULE-007: Suspicious IP Multi-Event Activity
    if "RULE-007" in rules:
        r = rules["RULE-007"]
        thresh = int(r["threshold_count"])
        for ip, evs in by_ip.items():
            if len(evs) >= thresh:
                candidates.append({
                    "rule": r,
                    "dedup_key": make_dedup_key("RULE-007", [ip, evs[0]["timestamp"][:10]]),
                    "title": f"High Security Event Concentration from IP {ip}",
                    "description": f"Source IP {ip} is associated with {len(evs)} security events across event categories ({', '.join(sorted({x['event_type'] for x in evs}))}).",
                    "source_ip": ip,
                    "username": evs[0].get("username"),
                    "hostname": evs[0]["hostname"],
                    "events": evs,
                })

    # RULE-008: Port Scan Indicators (Strictly from firewall/network logs)
    if "RULE-008" in rules:
        r = rules["RULE-008"]
        thresh = int(r["threshold_count"])
        for ip, evs in by_ip.items():
            net_evs = [
                e for e in evs
                if e["source"] in ("firewall", "network")
                and e["event_type"] == "network_connection"
                and e.get("destination_port") is not None
            ]
            ports = sorted(list({e["destination_port"] for e in net_evs}))
            if len(ports) >= thresh:
                candidates.append({
                    "rule": r,
                    "dedup_key": make_dedup_key("RULE-008", [ip, net_evs[0]["timestamp"][:13]]),
                    "title": f"Port Scan Indicator from {ip} ({len(ports)} Distinct TCP Ports)",
                    "description": f"Firewall telemetry recorded source IP {ip} probing {len(ports)} distinct destination ports ({', '.join(str(p) for p in ports[:8])}) on {net_evs[0].get('destination_ip') or net_evs[0]['hostname']}.",
                    "source_ip": ip,
                    "username": None,
                    "hostname": net_evs[0]["hostname"],
                    "events": net_evs,
                })

    # RULE-009: Suspicious DNS Activity
    if "RULE-009" in rules:
        r = rules["RULE-009"]
        thresh = int(r["threshold_count"])
        dns_evs = [e for e in events if e["event_type"] == "dns_query" or e["source"] == "dns_resolver"]
        suspicious_dns = []
        for e in dns_evs:
            norm = json.loads(e.get("normalized_data") or "{}")
            qdom = str(norm.get("query_domain") or e["raw_message"])
            first_label = qdom.split(".")[0] if "." in qdom else qdom
            if len(first_label) >= 24 or "tunnel" in qdom.lower() or "c2" in qdom.lower():
                suspicious_dns.append(e)
        if len(suspicious_dns) >= thresh:
            ip = suspicious_dns[0].get("source_ip")
            candidates.append({
                "rule": r,
                "dedup_key": make_dedup_key("RULE-009", [ip, suspicious_dns[0]["timestamp"][:13]]),
                "title": f"Suspicious High-Entropy DNS Queries from {ip}",
                "description": f"Internal host {ip} generated {len(suspicious_dns)} high-entropy / suspected DNS tunneling queries via {suspicious_dns[0]['hostname']}.",
                "source_ip": ip,
                "username": None,
                "hostname": suspicious_dns[0]["hostname"],
                "events": suspicious_dns,
            })

    # RULE-010: Event Flooding / Log Anomaly
    if "RULE-010" in rules:
        r = rules["RULE-010"]
        thresh = int(r["threshold_count"])
        for ip, evs in by_ip.items():
            flood_evs = [e for e in evs if e["event_type"] == "http_request_flood" or len(evs) >= thresh]
            if len(flood_evs) >= thresh:
                t0 = parse_iso(flood_evs[0]["timestamp"])
                t1 = parse_iso(flood_evs[-1]["timestamp"])
                if (t1 - t0).total_seconds() <= int(r["time_window_seconds"]):
                    candidates.append({
                        "rule": r,
                        "dedup_key": make_dedup_key("RULE-010", [ip, flood_evs[0]["timestamp"][:15]]),
                        "title": f"High-Frequency Event Flooding Anomaly from {ip}",
                        "description": f"Source IP {ip} generated {len(flood_evs)} rapid events within {(t1 - t0).total_seconds():.0f}s on {flood_evs[0]['hostname']} (Threshold: {thresh}).",
                        "source_ip": ip,
                        "username": flood_evs[0].get("username"),
                        "hostname": flood_evs[0]["hostname"],
                        "events": flood_evs,
                    })

    now = utc_now_iso()
    created_alerts = []
    for c in candidates:
        existing = conn.execute("SELECT alert_id FROM alerts WHERE dedup_key = ?", (c["dedup_key"],)).fetchone()
        if existing:
            continue
        alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"
        evs = c["events"]
        origin_type = evs[0].get("origin_type", "uploaded")
        rule = c["rule"]
        conn.execute(
            """INSERT INTO alerts
            (alert_id, dedup_key, title, description, severity, rule_id, rule_name,
             source_ip, username, hostname, first_observed, last_observed, event_count,
             mitre_technique, recommended_actions, status, assigned_analyst, origin_type,
             investigation_notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'New', 'Tier-1 Analyst', ?, '[]', ?, ?)""",
            (
                alert_id, c["dedup_key"], c["title"], c["description"], rule["severity"],
                rule["rule_id"], rule["name"], c["source_ip"], c["username"], c["hostname"],
                evs[0]["timestamp"], evs[-1]["timestamp"], len(evs),
                rule["mitre_technique"], rule["recommended_steps"], origin_type, now, now
            ),
        )
        for ev in evs[:25]:
            conn.execute(
                "INSERT INTO alert_evidence (alert_id, event_id, evidence_summary) VALUES (?, ?, ?)",
                (alert_id, ev["id"], f"[{ev['timestamp']}] {ev['hostname']} ({ev['event_type']}): {ev['raw_message'][:160]}"),
            )
        created_alerts.append(alert_id)

    duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
    summary = {
        "executed_at": now,
        "trigger_source": trigger_source,
        "events_evaluated": len(events),
        "rules_evaluated": len(rules),
        "alerts_generated": len(created_alerts),
        "new_alert_ids": created_alerts,
        "duration_ms": duration_ms,
    }
    conn.execute(
        """INSERT INTO detection_execution_history
        (executed_at, trigger_source, events_evaluated, rules_evaluated, alerts_generated, duration_ms, details_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (now, trigger_source, len(events), len(rules), len(created_alerts), duration_ms, json.dumps(summary)),
    )
    log_audit(conn, "RUN_DETECTION", "detection_engine", trigger_source, f"Evaluated {len(events)} events across {len(rules)} rules; generated {len(created_alerts)} new alerts.")
    return summary
