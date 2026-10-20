"""Tests for the configurable risk-scoring engine."""

from ml.risk_engine import RiskEngine


def test_rule_only_degrades_gracefully():
    r = RiskEngine().score(rule_score=70)
    assert r["priority"] == "High"
    assert r["signals_used"] == ["attack"]


def test_no_double_counting_correlated_signals():
    # rule (0.70) and ML sqli (0.75*conf) both describe the attack; the
    # engine takes the STRONGER, so risk stays near a single strong signal.
    r = RiskEngine().score(
        rule_score=70,
        ml_result={"family": "sql_injection", "confidence": 0.9},
    )
    assert r["risk_score"] <= 80  # not summed to ~145


def test_full_signals_reach_critical():
    r = RiskEngine().score(
        rule_score=70,
        ml_result={"family": "exploit_rce", "confidence": 0.95},
        suricata_severity=1,
        anomaly_result={"score": 1.2, "threshold": 0.4},
    )
    assert r["priority"] == "Critical"
    assert set(r["signals_used"]) >= {"attack", "suricata", "anomaly"}


def test_missing_ml_does_not_block():
    r = RiskEngine().score(rule_score=40, ml_result=None, anomaly_result=None)
    assert r["risk_score"] == 40
    assert r["priority"] == "Medium"


def test_anomaly_only():
    r = RiskEngine().score(anomaly_result={"score": 0.9, "threshold": 0.4})
    assert "anomaly" in r["signals_used"]


def test_no_signals_is_low():
    r = RiskEngine().score()
    assert r["risk_score"] == 0.0
    assert r["priority"] == "Low"


def test_asset_criticality_raises_risk():
    eng = RiskEngine(asset_criticality={"10.0.0.5": 1.0})
    r = eng.score(rule_score=40, dest_ip="10.0.0.5")
    assert "asset" in r["signals_used"]
