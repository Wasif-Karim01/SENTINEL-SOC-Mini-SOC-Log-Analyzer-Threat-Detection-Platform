"""Threat Intelligence & IOC Investigation Module with strict RFC/hash validation and honest offline/online status."""
import ipaddress
import json
import re
from typing import Dict, Any
from app.core.config import settings
from app.core.database import utc_now_iso, log_audit

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

DOCUMENTATION_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3 (RFC 5737)
]

def validate_and_classify_ioc(value: str) -> Dict[str, Any]:
    val = (value or "").strip()
    if not val:
        raise ValueError("IOC value cannot be empty.")

    # Check IPv4
    try:
        ip_obj = ipaddress.IPv4Address(val)
        is_doc = any(ip_obj in net for net in DOCUMENTATION_NETS)
        is_priv = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        return {
            "ioc_value": val,
            "ioc_type": "ipv4",
            "is_private_or_reserved": bool(is_doc or is_priv),
            "reservation_note": (
                "RFC 5737 Reserved Documentation IPv4 Range (TEST-NET) — Public external reputation lookup is not applicable."
                if is_doc else (
                    "RFC 1918 Private / Loopback IPv4 Address — Internal network address; public reputation lookup is not applicable."
                    if is_priv else "Routable Public IPv4 Address"
                )
            ),
        }
    except ipaddress.AddressValueError:
        pass

    if SHA256_RE.match(val):
        return {"ioc_value": val.lower(), "ioc_type": "sha256", "is_private_or_reserved": False, "reservation_note": "Valid SHA-256 cryptographic digest."}
    if SHA1_RE.match(val):
        return {"ioc_value": val.lower(), "ioc_type": "sha1", "is_private_or_reserved": False, "reservation_note": "Valid SHA-1 cryptographic digest."}
    if MD5_RE.match(val):
        return {"ioc_value": val.lower(), "ioc_type": "md5", "is_private_or_reserved": False, "reservation_note": "Valid MD5 cryptographic digest."}
    if DOMAIN_RE.match(val):
        is_example = val.lower().endswith(".example") or val.lower().endswith(".local") or val.lower().endswith(".corp")
        return {
            "ioc_value": val.lower(),
            "ioc_type": "domain",
            "is_private_or_reserved": is_example,
            "reservation_note": (
                "RFC 2606 Reserved Example / Internal Domain — External public WHOIS/reputation lookup is not applicable."
                if is_example else "Syntactically valid FQDN."
            ),
        }

    raise ValueError(f"Invalid IOC format: '{val}'. Supported formats: IPv4 address, Domain (FQDN), MD5 (32 hex), SHA-1 (40 hex), or SHA-256 (64 hex).")

def investigate_ioc(conn, raw_value: str, analyst_notes: str = "") -> Dict[str, Any]:
    meta = validate_and_classify_ioc(raw_value)
    val = meta["ioc_value"]
    ioc_type = meta["ioc_type"]
    now = utc_now_iso()

    # Correlate against local events and alerts
    if ioc_type == "ipv4":
        ev_count = conn.execute(
            "SELECT COUNT(*) AS c FROM events WHERE source_ip = ? OR destination_ip = ?", (val, val)
        ).fetchone()["c"]
        alert_rows = conn.execute(
            "SELECT alert_id, title, severity FROM alerts WHERE source_ip = ?", (val,)
        ).fetchall()
    else:
        ev_count = conn.execute(
            "SELECT COUNT(*) AS c FROM events WHERE raw_message LIKE ?", (f"%{val}%",)
        ).fetchone()["c"]
        alert_rows = conn.execute(
            "SELECT alert_id, title, severity FROM alerts WHERE description LIKE ? OR title LIKE ?",
            (f"%{val}%", f"%{val}%"),
        ).fetchall()

    related_alerts = [dict(r) for r in alert_rows]
    severities = {r["severity"] for r in related_alerts}

    if "Critical" in severities or "High" in severities:
        classification = "Suspicious / High-Risk (Local Telemetry Match)"
        confidence = "High (Observed in Local Alerts)"
    elif ev_count > 0 or related_alerts:
        classification = "Observed in Local Telemetry (Under Review)"
        confidence = "Medium (Local Log Sighting)"
    else:
        classification = "Unobserved Locally"
        confidence = "Informational"

    has_external_keys = bool(settings.VIRUSTOTAL_API_KEY or settings.ABUSEIPDB_API_KEY or settings.OTX_API_KEY)
    if meta["is_private_or_reserved"]:
        ext_status = "Not Applicable (Reserved / Private Scope)"
        ext_summary = meta["reservation_note"]
    elif not has_external_keys:
        ext_status = "External Intelligence Unavailable (Offline Mode — No API Keys Configured)"
        ext_summary = (
            "External threat intelligence feeds (VirusTotal, AbuseIPDB, AlienVault OTX) are not configured in environment variables. "
            "No external reputation score is fabricated. Assessment is derived strictly from local SIEM telemetry."
        )
    else:
        ext_status = "Configured (On-Demand Query Ready)"
        ext_summary = "External API keys detected; local correlation completed."

    existing = conn.execute("SELECT * FROM ioc_records WHERE ioc_value = ?", (val,)).fetchone()
    notes_to_save = analyst_notes if analyst_notes else (existing["analyst_notes"] if existing else "")
    first_seen = existing["first_seen"] if existing else now

    conn.execute(
        """INSERT INTO ioc_records
        (ioc_value, ioc_type, classification, confidence, is_private_or_reserved,
         local_sightings, related_alerts, external_intel_status, external_intel_summary,
         analyst_notes, first_seen, last_checked)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ioc_value) DO UPDATE SET
            classification = excluded.classification,
            confidence = excluded.confidence,
            local_sightings = excluded.local_sightings,
            related_alerts = excluded.related_alerts,
            external_intel_status = excluded.external_intel_status,
            external_intel_summary = excluded.external_intel_summary,
            analyst_notes = excluded.analyst_notes,
            last_checked = excluded.last_checked
        """,
        (
            val, ioc_type, classification, confidence, 1 if meta["is_private_or_reserved"] else 0,
            ev_count, json.dumps(related_alerts), ext_status, ext_summary,
            notes_to_save, first_seen, now,
        ),
    )
    log_audit(conn, "INVESTIGATE_IOC", "ioc", val, f"Investigated {ioc_type.upper()} IOC '{val}' (local sightings: {ev_count}, alerts: {len(related_alerts)}).")
    row = conn.execute("SELECT * FROM ioc_records WHERE ioc_value = ?", (val,)).fetchone()
    res = dict(row)
    res["related_alerts"] = json.loads(res["related_alerts"])
    res["reservation_note"] = meta["reservation_note"]
    return res
