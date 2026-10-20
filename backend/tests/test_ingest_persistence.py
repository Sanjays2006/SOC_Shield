"""Ingestion pipeline: persistence, dedup, alert creation (mongomock)."""

import importlib
import sys

import pytest

try:
    import mongomock  # noqa: F401
    HAVE_MONGOMOCK = True
except Exception:
    HAVE_MONGOMOCK = False

from tests.fixtures import LEGACY_XSS, FULL_EVE_RCE, NON_ALERT_LOG


@pytest.fixture
def ingest_env(monkeypatch):
    if not HAVE_MONGOMOCK:
        pytest.skip("mongomock not installed")
    import mongomock
    monkeypatch.setattr("pymongo.MongoClient", mongomock.MongoClient)
    for mod in list(sys.modules):
        if mod == "extensions" or mod.startswith("services"):
            sys.modules.pop(mod, None)
    extensions = importlib.import_module("extensions")
    ingest = importlib.import_module("services.ingest")
    # Avoid real network/firewall side effects.
    monkeypatch.setattr(ingest, "get_geo", lambda ip: {})
    monkeypatch.setattr(ingest, "send_telegram", lambda msg: None)
    monkeypatch.setattr(ingest, "firewall_block_ip", lambda ip: False)
    return ingest, extensions


def test_alert_is_stored_and_created(ingest_env):
    ingest, ext = ingest_env
    res = ingest.process_log(LEGACY_XSS)
    assert res["stored"] is True
    assert res["alert_created"] is True
    assert ext.logs_collection.count_documents({}) == 1
    assert ext.alerts_collection.count_documents({}) == 1


def test_duplicate_within_window_is_suppressed(ingest_env):
    ingest, ext = ingest_env
    ingest.process_log(LEGACY_XSS, dedup_window_seconds=60)
    res2 = ingest.process_log(LEGACY_XSS, dedup_window_seconds=60)
    assert res2["duplicate"] is True
    # Only the first event stored.
    assert ext.logs_collection.count_documents({}) == 1


def test_non_alert_stored_but_no_alert(ingest_env):
    ingest, ext = ingest_env
    res = ingest.process_log(NON_ALERT_LOG)
    assert res["stored"] is True
    assert res["alert_created"] is False
    assert ext.alerts_collection.count_documents({}) == 0


def test_full_eve_alert_keeps_flow_and_severity(ingest_env):
    ingest, ext = ingest_env
    ingest.process_log(FULL_EVE_RCE)
    doc = ext.logs_collection.find_one({})
    assert doc["normalized"]["dest_ip"] == "10.0.0.5"
    assert doc["normalized"]["flow_bytes_toserver"] == 48213
    alert = ext.alerts_collection.find_one({})
    # Original IDS severity preserved separately from risk.
    assert alert["alert"]["severity"] in ("Low", "Medium", "High", "Critical")
    assert "risk_score" in alert
