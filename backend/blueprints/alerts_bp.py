"""Alert lifecycle routes: list, assign, resolve."""

from datetime import datetime

from flask import Blueprint, jsonify, request
from bson import ObjectId
from bson.errors import InvalidId

from extensions import alerts_collection
from services.validation import clamp_pagination
from services.auth import require_role

alerts_bp = Blueprint("alerts", __name__)


@alerts_bp.route("/alerts")
@require_role("viewer")
def get_alerts():
    """Non-resolved alerts. Backwards compatible: no params => full list.

    Supports optional ?page=, ?limit=, and ?severity= filters.
    """
    query = {"status": {"$ne": "resolved"}}

    severity = request.args.get("severity")
    if severity:
        query["alert.severity"] = severity

    page_param = request.args.get("page")
    limit_param = request.args.get("limit")

    if page_param is None and limit_param is None:
        alerts = list(alerts_collection.find(query).sort("timestamp", -1))
        for a in alerts:
            a["_id"] = str(a["_id"])
        return jsonify(alerts)

    page, limit, skip = clamp_pagination(page_param, limit_param)
    cursor = (
        alerts_collection.find(query)
        .sort("timestamp", -1)
        .skip(skip)
        .limit(limit)
    )
    items = []
    for a in cursor:
        a["_id"] = str(a["_id"])
        items.append(a)

    return jsonify({
        "page": page,
        "limit": limit,
        "total": alerts_collection.count_documents(query),
        "items": items,
    })


@alerts_bp.route("/assign-alert", methods=["POST"])
@require_role("analyst")
def assign_alert():
    data = request.get_json(silent=True) or {}
    alert_id = data.get("id")
    analyst = data.get("analyst")

    if not alert_id or not analyst:
        return jsonify({"error": "Missing data"}), 400
    if not isinstance(analyst, str) or len(analyst) > 100:
        return jsonify({"error": "Invalid analyst"}), 400

    try:
        oid = ObjectId(alert_id)
    except (InvalidId, TypeError):
        return jsonify({"error": "Invalid alert id"}), 400

    alerts_collection.update_one(
        {"_id": oid},
        {"$set": {"assigned_to": analyst, "assigned_at": datetime.utcnow()}},
    )
    return jsonify({"message": f"Assigned to {analyst}"})


@alerts_bp.route("/resolve-alert", methods=["POST"])
@require_role("analyst")
def resolve_alert():
    data = request.get_json(silent=True) or {}
    alert_id = data.get("id")

    if not alert_id:
        return jsonify({"error": "Missing alert ID"}), 400

    try:
        oid = ObjectId(alert_id)
    except (InvalidId, TypeError):
        return jsonify({"error": "Invalid alert id"}), 400

    alerts_collection.update_one(
        {"_id": oid},
        {"$set": {"status": "resolved", "resolved_at": datetime.utcnow()}},
    )
    return jsonify({"message": "Alert resolved successfully"})
