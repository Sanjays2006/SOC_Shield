"""
Event normalization.

Suricata's real EVE JSON is rich (flow, proto, ports, bytes, timestamps,
alert.severity), but the legacy SOCShield agent emitted only four fields
(event_type, src_ip, alert.signature, http.url). This module maps BOTH
shapes onto one consistent internal schema so the rest of the pipeline
(dedup, ML features, risk scoring) can rely on known field names.

Fields that are genuinely absent in the source are recorded as None and
must NOT be fabricated downstream — feature code checks for presence.
"""

from datetime import datetime


# Canonical internal schema keys produced by normalize().
SCHEMA_KEYS = (
    "event_type", "timestamp", "src_ip", "dest_ip", "src_port", "dest_port",
    "proto", "app_proto", "signature", "category", "suricata_severity",
    "http_url", "http_method", "http_status",
    "flow_bytes_toserver", "flow_bytes_toclient",
    "flow_pkts_toserver", "flow_pkts_toclient",
)


def _get(d, *path, default=None):
    """Safe nested lookup: _get(obj, 'alert', 'signature')."""
    cur = d
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return cur if cur is not None else default


def normalize(raw):
    """Map a raw event (legacy or full EVE) to the canonical schema.

    Returns a new dict containing every SCHEMA_KEY plus a nested
    `_raw` copy of the original event for traceability.
    """
    alert = raw.get("alert", {}) if isinstance(raw.get("alert"), dict) else {}
    http = raw.get("http", {}) if isinstance(raw.get("http"), dict) else {}
    flow = raw.get("flow", {}) if isinstance(raw.get("flow"), dict) else {}

    # Timestamp: use EVE 'timestamp' if present, else now (ingest time).
    ts = raw.get("timestamp")
    if isinstance(ts, str):
        parsed = _parse_eve_ts(ts)
    elif isinstance(ts, datetime):
        parsed = ts
    else:
        parsed = None

    norm = {
        "event_type": raw.get("event_type"),
        "timestamp": parsed,
        "src_ip": raw.get("src_ip"),
        "dest_ip": raw.get("dest_ip"),
        "src_port": _as_int(raw.get("src_port")),
        "dest_port": _as_int(raw.get("dest_port")),
        "proto": raw.get("proto"),
        "app_proto": raw.get("app_proto"),
        "signature": alert.get("signature"),
        "category": alert.get("category"),
        # Suricata's own numeric severity (1=high..3=low) if present.
        "suricata_severity": _as_int(alert.get("severity")),
        "http_url": http.get("url"),
        "http_method": http.get("http_method") or http.get("method"),
        "http_status": _as_int(http.get("status")),
        "flow_bytes_toserver": _as_int(flow.get("bytes_toserver")),
        "flow_bytes_toclient": _as_int(flow.get("bytes_toclient")),
        "flow_pkts_toserver": _as_int(flow.get("pkts_toserver")),
        "flow_pkts_toclient": _as_int(flow.get("pkts_toclient")),
    }
    norm["_raw"] = raw
    return norm


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_eve_ts(value):
    """Parse a Suricata EVE timestamp like 2024-01-01T12:00:00.000000+0000."""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def has_flow_features(norm):
    """True only if real network-flow fields are present (not fabricated)."""
    return any(
        norm.get(k) is not None
        for k in (
            "flow_bytes_toserver", "flow_bytes_toclient",
            "flow_pkts_toserver", "flow_pkts_toclient",
        )
    )
