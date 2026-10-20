"""Tests for EVE JSON parsing / normalization."""

from services.normalize import normalize, has_flow_features
from tests.fixtures import LEGACY_XSS, FULL_EVE_RCE


def test_legacy_event_has_no_flow_features():
    n = normalize(LEGACY_XSS)
    assert n["signature"] == "XSS Attack"
    assert n["http_url"] == "<script>alert(1)</script>"
    assert n["dest_ip"] is None
    assert has_flow_features(n) is False


def test_full_eve_parsed_fully():
    n = normalize(FULL_EVE_RCE)
    assert n["dest_ip"] == "10.0.0.5"
    assert n["dest_port"] == 445
    assert n["proto"] == "TCP"
    assert n["suricata_severity"] == 1
    assert n["flow_bytes_toserver"] == 48213
    assert has_flow_features(n) is True


def test_eve_timestamp_parsed():
    n = normalize(FULL_EVE_RCE)
    assert n["timestamp"] is not None
    assert n["timestamp"].year == 2026


def test_malformed_fields_are_safe():
    n = normalize({"event_type": "alert", "dest_port": "not-a-number",
                   "alert": "not-a-dict"})
    assert n["dest_port"] is None
    assert n["signature"] is None
