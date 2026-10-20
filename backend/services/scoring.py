"""
Rule-based scoring and severity.

This is the ORIGINAL deterministic scoring logic, preserved intact and
isolated so it can be unit-tested and later combined with ML risk scoring
(Phase 3) without being entangled in Flask route handlers.
"""


def calculate_score(log):
    """Keyword/heuristic score in the range 0..100 (original behavior)."""
    score = 0
    url = (log.get("http", {}) or {}).get("url", "")
    url = url.lower() if isinstance(url, str) else ""

    if log.get("event_type") == "alert":
        score += 40
    if "<script>" in url:
        score += 30
    if "union select" in url:
        score += 30

    return min(score, 100)


def get_severity(score):
    """Map a 0..100 score onto a severity band (original thresholds)."""
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"
