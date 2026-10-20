"""
Event ingestion pipeline: normalize -> dedup -> persist -> score (rule +
ML + anomaly) -> risk -> alert -> notify -> emit.

Behavior is preserved for the legacy 4-field event shape. Full Suricata
EVE events are parsed via services.normalize. ML classification, anomaly
scoring, and risk prioritization are added as ADDITIONAL fields — the
original rule-based score and severity are kept intact, and missing ML
never blocks processing.
"""

import hashlib
import json
from datetime import datetime, timedelta

from extensions import logs_collection, alerts_collection, socketio
from services.scoring import calculate_score, get_severity
from services.intel import get_geo
from services.response import send_telegram, firewall_block_ip
from services.normalize import normalize

# ML is optional; import defensively so the backend still runs without it.
try:
    from ml.inference import classify, anomaly_score
    from ml.risk_engine import RiskEngine
    _RISK = RiskEngine()
    _ML_AVAILABLE = True
except Exception as _e:  # pragma: no cover
    print("ℹ️ ML layer unavailable, continuing without it:", _e)
    classify = anomaly_score = None
    _RISK = None
    _ML_AVAILABLE = False


def compute_event_hash(norm):
    key = {
        "event_type": norm.get("event_type"),
        "src_ip": norm.get("src_ip"),
        "dest_ip": norm.get("dest_ip"),
        "dest_port": norm.get("dest_port"),
        "signature": norm.get("signature"),
        "url": norm.get("http_url"),
        "proto": norm.get("proto"),
    }
    blob = json.dumps(key, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def build_log_document(raw):
    norm = normalize(raw)
    doc = dict(raw)
    doc["normalized"] = {k: v for k, v in norm.items() if k != "_raw"}
    doc["ingested_at"] = datetime.utcnow()
    doc["event_hash"] = compute_event_hash(norm)
    return doc, norm


def run_ml(norm):
    """Run classifier + anomaly detector. Returns (ml_result, anomaly_result).

    Both may be None — the caller must handle missing ML gracefully.
    """
    ml_result = anomaly_result = None
    if not _ML_AVAILABLE:
        return None, None
    try:
        ml_result = classify(norm)
    except Exception as e:
        print("⚠️ classify failed:", e)
    try:
        anomaly_result = anomaly_score(norm)
    except Exception as e:
        print("⚠️ anomaly failed:", e)
    return ml_result, anomaly_result


def process_log(log, dedup_window_seconds=5):
    """Full processing pipeline for a single ingested event."""
    result = {"stored": False, "duplicate": False, "alert_created": False}
    try:
        print("📥 RECEIVED:", log)

        doc, norm = build_log_document(log)

        cutoff = datetime.utcnow() - timedelta(seconds=dedup_window_seconds)
        existing = logs_collection.find_one({
            "event_hash": doc["event_hash"],
            "ingested_at": {"$gte": cutoff},
        })
        if existing is not None:
            result["duplicate"] = True
            return result

        logs_collection.insert_one(doc)
        result["stored"] = True

        if log.get("event_type") == "alert":
            # --- Original rule-based score + severity (PRESERVED) ---
            rule_score = calculate_score(log)
            rule_severity = get_severity(rule_score)

            # --- ML + anomaly (ADDITIVE, may be None) ---
            ml_result, anomaly_result = run_ml(norm)

            # --- Risk engine combines signals (no double-count) ---
            if _RISK is not None:
                risk = _RISK.score(
                    rule_score=rule_score,
                    ml_result=ml_result,
                    anomaly_result=anomaly_result,
                    suricata_severity=norm.get("suricata_severity"),
                    dest_ip=norm.get("dest_ip"),
                )
            else:
                # Fallback to rule-only when ML layer is absent.
                risk = {
                    "risk_score": rule_score,
                    "priority": rule_severity,
                    "signals_used": ["rule"],
                    "breakdown": {"rule": rule_score / 100.0},
                }

            geo = get_geo(log.get("src_ip"))

            alert = {
                "src_ip": log.get("src_ip"),
                "dest_ip": norm.get("dest_ip"),
                "alert": {
                    "signature": norm.get("signature"),
                    # Original IDS/rule severity kept here, untouched.
                    "severity": rule_severity,
                },
                "proto": norm.get("proto"),
                "dest_port": norm.get("dest_port"),
                "suricata_severity": norm.get("suricata_severity"),
                # Original rule score preserved as its own field.
                "score": rule_score,
                # New ML + risk fields (separate from IDS severity).
                "ml": ml_result,
                "anomaly": anomaly_result,
                "risk_score": risk["risk_score"],
                "priority": risk["priority"],
                "risk_breakdown": risk["breakdown"],
                "signals_used": risk["signals_used"],
                "geo": geo,
                "status": "open",
                "timestamp": datetime.utcnow(),
            }

            alerts_collection.insert_one(alert)
            result["alert_created"] = True

            message = f"""
🚨 SOC ALERT 🚨
IP: {alert['src_ip']}
Attack: {alert['alert']['signature']}
Priority: {risk['priority']} (risk {risk['risk_score']})
IDS severity: {rule_severity}
Country: {geo.get('country', 'Unknown')}
"""
            send_telegram(message)

            # Auto-block now keyed on the combined PRIORITY (guarded by config).
            if risk["priority"] in ["High", "Critical"]:
                firewall_block_ip(alert["src_ip"])

            emit_alert = dict(alert)
            emit_alert["_id"] = str(emit_alert.get("_id", ""))
            emit_alert["timestamp"] = emit_alert["timestamp"].isoformat()
            socketio.emit("new_alert", emit_alert)

        emit_log = {k: v for k, v in doc.items() if k != "_id"}
        emit_log["ingested_at"] = emit_log["ingested_at"].isoformat()
        n = emit_log.get("normalized", {})
        if isinstance(n.get("timestamp"), datetime):
            n["timestamp"] = n["timestamp"].isoformat()
        socketio.emit("new_log", emit_log)

    except Exception as e:
        print("❌ ERROR:", e)

    return result
