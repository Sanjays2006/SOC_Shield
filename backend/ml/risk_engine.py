"""
Configurable alert risk-scoring engine.

Combines multiple signals into a single 0..100 risk score and a priority
band (Critical/High/Medium/Low). Design principles:

  * The ORIGINAL IDS/rule severity is preserved separately and never
    overwritten — the risk score is an ADDITIONAL field.
  * Signals are weighted and combined on a normalized 0..1 scale, then
    scaled to 0..100. Weights are configurable (env or constructor).
  * Correlated signals are NOT double-counted: the rule-based keyword
    score and the ML family prediction both speak to "attack type", so we
    take the STRONGER of the two for the "attack" component rather than
    summing them.
  * Missing signals degrade gracefully: a weight whose signal is absent is
    dropped and the remaining weights are renormalized, so an alert with
    no ML prediction still gets a sensible score.

The mapping of attack family -> inherent danger and of Suricata numeric
severity -> 0..1 are documented, auditable tables.
"""

import os


# Inherent danger of each attack family on a 0..1 scale (documented).
FAMILY_DANGER = {
    "benign": 0.05,
    "recon_scan": 0.35,
    "xss": 0.55,
    "sql_injection": 0.75,
    "brute_force": 0.60,
    "dos_ddos": 0.70,
    "malware": 0.85,
    "privilege_escalation": 0.90,
    "exploit_rce": 0.95,
    "other_suspicious": 0.40,
}

# Suricata numeric severity (1=high,2=medium,3=low) -> 0..1 danger.
SURICATA_SEVERITY_MAP = {1: 0.9, 2: 0.6, 3: 0.3}

DEFAULT_WEIGHTS = {
    "attack": 0.45,       # stronger of rule-score / ML family danger
    "suricata": 0.20,     # Suricata's own severity, if present
    "anomaly": 0.20,      # flow anomaly score, if present
    "asset": 0.15,        # asset criticality, if configured
}

PRIORITY_BANDS = [
    (80, "Critical"),
    (60, "High"),
    (40, "Medium"),
    (0, "Low"),
]


def _env_weight(name, default):
    try:
        return float(os.getenv(f"RISK_W_{name.upper()}", default))
    except (TypeError, ValueError):
        return default


class RiskEngine:
    def __init__(self, weights=None, asset_criticality=None):
        if weights is None:
            weights = {k: _env_weight(k, v) for k, v in DEFAULT_WEIGHTS.items()}
        self.weights = weights
        # Optional map of dest_ip/subnet -> criticality in 0..1.
        self.asset_criticality = asset_criticality or {}

    def _attack_component(self, rule_score, ml_result):
        """Stronger of rule-based keyword score and ML family danger.

        Avoids double-counting two correlated 'attack type' signals.
        Returns (value_0_1, available_bool).
        """
        candidates = []
        if rule_score is not None:
            candidates.append(min(max(rule_score, 0), 100) / 100.0)
        if ml_result and ml_result.get("family"):
            danger = FAMILY_DANGER.get(ml_result["family"], 0.4)
            conf = ml_result.get("confidence")
            # Scale danger by confidence when available (calibrated weight).
            if conf is not None:
                danger = danger * (0.5 + 0.5 * conf)
            candidates.append(danger)
        if not candidates:
            return 0.0, False
        return max(candidates), True

    def _suricata_component(self, suricata_severity):
        if suricata_severity is None:
            return 0.0, False
        return SURICATA_SEVERITY_MAP.get(int(suricata_severity), 0.3), True

    def _anomaly_component(self, anomaly_result):
        if not anomaly_result:
            return 0.0, False
        score = anomaly_result.get("score")
        thr = anomaly_result.get("threshold", 0.0) or 0.0
        if score is None:
            return 0.0, False
        # Map score relative to threshold into 0..1 (clamped).
        if score <= 0:
            val = 0.0
        else:
            val = min(1.0, score / (thr * 2)) if thr > 0 else min(1.0, score)
        return val, True

    def _asset_component(self, dest_ip):
        if dest_ip and dest_ip in self.asset_criticality:
            return float(self.asset_criticality[dest_ip]), True
        return 0.0, False

    def score(self, *, rule_score=None, ml_result=None, anomaly_result=None,
              suricata_severity=None, dest_ip=None):
        """Compute risk. Returns a dict with the score, band, and breakdown."""
        components = {
            "attack": self._attack_component(rule_score, ml_result),
            "suricata": self._suricata_component(suricata_severity),
            "anomaly": self._anomaly_component(anomaly_result),
            "asset": self._asset_component(dest_ip),
        }

        # Renormalize weights over AVAILABLE signals only.
        avail = {k: self.weights[k] for k, (_, ok) in components.items() if ok}
        total_w = sum(avail.values())
        if total_w == 0:
            risk = 0.0
        else:
            risk = sum(
                components[k][0] * (w / total_w) for k, w in avail.items()
            ) * 100.0

        risk = round(min(max(risk, 0.0), 100.0), 1)
        band = next(name for threshold, name in PRIORITY_BANDS if risk >= threshold)

        return {
            "risk_score": risk,
            "priority": band,
            "signals_used": sorted(avail.keys()),
            "breakdown": {k: round(v, 3) for k, (v, ok) in components.items() if ok},
        }
