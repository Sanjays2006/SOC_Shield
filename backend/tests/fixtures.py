"""Shared test fixtures: realistic normalized/raw events (NOT live data).

These fixtures are used ONLY by automated tests. They are deliberate,
labeled samples — they do not replace live application functionality.
"""

# Legacy 4-field event (the shape the original agent emitted).
LEGACY_XSS = {
    "event_type": "alert",
    "src_ip": "185.199.108.153",
    "alert": {"signature": "XSS Attack"},
    "http": {"url": "<script>alert(1)</script>"},
}

LEGACY_SQLI = {
    "event_type": "alert",
    "src_ip": "139.130.4.5",
    "alert": {"signature": "SQL Injection"},
    "http": {"url": "id=1 UNION SELECT"},
}

LEGACY_BENIGN = {
    "event_type": "alert",
    "src_ip": "8.8.8.8",
    "alert": {"signature": "Low Level Scan"},
    "http": {"url": "home"},
}

# Full Suricata EVE-style event with flow features.
FULL_EVE_RCE = {
    "event_type": "alert",
    "timestamp": "2026-10-18T09:15:30.123456+0000",
    "src_ip": "45.33.32.156",
    "dest_ip": "10.0.0.5",
    "src_port": 51514,
    "dest_port": 445,
    "proto": "TCP",
    "app_proto": None,
    "alert": {"signature": "Critical Exploit Attempt", "severity": 1,
              "category": "Attempted Admin"},
    "http": {"url": "rm -rf /", "method": "POST"},
    "flow": {"bytes_toserver": 48213, "bytes_toclient": 1200,
             "pkts_toserver": 220, "pkts_toclient": 30},
}

NON_ALERT_LOG = {
    "event_type": "flow",
    "src_ip": "1.2.3.4",
    "dest_ip": "10.0.0.9",
}
