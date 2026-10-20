"""Aggregate statistics for dashboard overview cards."""

from flask import Blueprint, jsonify

from extensions import logs_collection, alerts_collection, blocked_collection
from services.auth import require_role

stats_bp = Blueprint("stats", __name__)


@stats_bp.route("/stats")
@require_role("viewer")
def stats():
    """Overview metrics computed from real stored data."""
    severity_pipeline = [
        {"$group": {"_id": "$alert.severity", "count": {"$sum": 1}}},
    ]
    severity_counts = {
        (row["_id"] or "Unknown"): row["count"]
        for row in alerts_collection.aggregate(severity_pipeline)
    }

    open_query = {"status": {"$ne": "resolved"}}

    return jsonify({
        "total_logs": logs_collection.count_documents({}),
        "total_alerts": alerts_collection.count_documents({}),
        "open_alerts": alerts_collection.count_documents(open_query),
        "critical_alerts": alerts_collection.count_documents(
            {"alert.severity": "Critical"}
        ),
        "blocked_ips": blocked_collection.count_documents({}),
        "severity_distribution": {
            "Low": severity_counts.get("Low", 0),
            "Medium": severity_counts.get("Medium", 0),
            "High": severity_counts.get("High", 0),
            "Critical": severity_counts.get("Critical", 0),
        },
    })
