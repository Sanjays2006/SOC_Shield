"""Tests for the original rule-based scoring (behavior preserved)."""

import pytest

from services.scoring import calculate_score, get_severity


@pytest.mark.parametrize("url,expected", [
    ("home", 40),
    ("<script>alert(1)</script>", 70),
    ("id=1 UNION SELECT", 70),
    ("<script> UNION SELECT password", 100),
])
def test_calculate_score(url, expected):
    log = {"event_type": "alert", "http": {"url": url}}
    assert calculate_score(log) == expected


def test_non_alert_scores_zero():
    assert calculate_score({"event_type": "flow"}) == 0


def test_missing_http_is_safe():
    assert calculate_score({"event_type": "alert"}) == 40


@pytest.mark.parametrize("score,band", [
    (0, "Low"), (40, "Medium"), (60, "High"), (80, "Critical"), (100, "Critical"),
])
def test_severity_bands(score, band):
    assert get_severity(score) == band
