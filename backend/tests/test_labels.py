"""Tests for attack-family labeling + payload features."""

import pytest

from ml.labels import family_from_signature, payload_features, FAMILIES


@pytest.mark.parametrize("sig,expected", [
    ("XSS Attack", "xss"),
    ("SQL Injection", "sql_injection"),
    ("Brute Force Login", "brute_force"),
    ("DDoS Attempt", "dos_ddos"),
    ("Malware Drop", "malware"),
    ("Privilege Escalation", "privilege_escalation"),
    ("Critical Exploit Attempt", "exploit_rce"),
    ("Port Scan", "recon_scan"),
    ("Bot Crawling", "recon_scan"),
])
def test_family_from_signature(sig, expected):
    fam = family_from_signature(sig)
    assert fam == expected
    assert fam in FAMILIES


def test_generic_signature_falls_back_to_payload():
    # Signature is generic; URL carries the SQLi evidence.
    assert family_from_signature("Advanced Attack", "id=1 UNION SELECT") == "sql_injection"


def test_unknown_defaults_to_other():
    assert family_from_signature("Totally Unknown", "benign-looking") == "other_suspicious"


def test_payload_features_detects_sqli():
    f = payload_features("id=1 UNION SELECT")
    assert f["has_sql_union"] == 1
    assert f["url_length"] > 0


def test_payload_features_detects_xss():
    f = payload_features("<script>alert(1)</script>")
    assert f["has_script_tag"] == 1
    assert f["has_angle_brackets"] == 1
