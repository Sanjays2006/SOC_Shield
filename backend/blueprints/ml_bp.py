"""ML routes: on-demand prediction + model status."""

import os
import json

from flask import Blueprint, jsonify, request

from services.normalize import normalize
from bson import ObjectId
from bson.errors import InvalidId
from extensions import alerts_collection
from services.auth import require_role

ml_bp = Blueprint("ml", __name__)

_MODELS_DIR = os.getenv("SOCSHIELD_MODELS_DIR", "models")


@ml_bp.route("/ml/status")
@require_role("viewer")
def ml_status():
    """Report which models are present and their training metrics."""
    def _read_report(name):
        path = os.path.join(_MODELS_DIR, name)
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return None
        return None

    return jsonify({
        "classifier_loaded": os.path.exists(
            os.path.join(_MODELS_DIR, "classifier.joblib")
        ),
        "anomaly_loaded": os.path.exists(
            os.path.join(_MODELS_DIR, "anomaly.joblib")
        ),
        "classifier_report": _read_report("classifier_report.json"),
        "anomaly_report": _read_report("anomaly_report.json"),
    })


@ml_bp.route("/ml/predict", methods=["POST"])
@require_role("viewer")
def ml_predict():
    """Classify + anomaly-score a single event supplied in the request."""
    raw = request.get_json(silent=True)
    if not isinstance(raw, dict):
        return jsonify({"error": "Invalid JSON body"}), 400

    # ML imported lazily so this route still responds if ML is unavailable.
    try:
        from ml.inference import classify, anomaly_score
        from ml.risk_engine import RiskEngine
        from services.scoring import calculate_score
    except Exception:
        return jsonify({"error": "ML layer unavailable"}), 503

    norm = normalize(raw)
    ml_result = classify(norm)
    anomaly_result = anomaly_score(norm)
    rule_score = calculate_score(raw)

    risk = RiskEngine().score(
        rule_score=rule_score,
        ml_result=ml_result,
        anomaly_result=anomaly_result,
        suricata_severity=norm.get("suricata_severity"),
        dest_ip=norm.get("dest_ip"),
    )

    return jsonify({
        "classification": ml_result,
        "anomaly": anomaly_result,
        "rule_score": rule_score,
        "risk": risk,
    })


@ml_bp.route("/incident-summary/<alert_id>", methods=["GET"])
@require_role("viewer")
def incident_summary(alert_id):
    """Generate an AI-assisted (or fallback) summary for a stored alert."""
    try:
        oid = ObjectId(alert_id)
    except (InvalidId, TypeError):
        return jsonify({"error": "Invalid alert id"}), 400

    alert = alerts_collection.find_one({"_id": oid})
    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    alert["_id"] = str(alert["_id"])

    try:
        from ml.incident_ai import generate_incident_summary
    except Exception:
        return jsonify({"error": "Summary module unavailable"}), 503

    summary = generate_incident_summary(alert)
    return jsonify(summary)
