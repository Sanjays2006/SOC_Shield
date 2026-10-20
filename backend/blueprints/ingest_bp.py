"""Ingestion + raw log routes."""

from flask import Blueprint, jsonify, request

from extensions import logs_collection, socketio
from services.ingest import process_log
from services.validation import clamp_pagination
from services.auth import require_api_key_or_role, require_role

ingest_bp = Blueprint("ingest", __name__)


@ingest_bp.route("/ingest", methods=["POST"])
@require_api_key_or_role("analyst")
def ingest():
    log = request.get_json(silent=True)
    if not isinstance(log, dict):
        return jsonify({"error": "Invalid JSON body"}), 400
    socketio.start_background_task(process_log, log)
    return {"status": "ok"}, 200


@ingest_bp.route("/logs")
@require_role("viewer")
def get_logs():
    """Return logs. Backwards compatible: no params => full list.

    Supports optional ?page= & ?limit= for paginated access.
    """
    page_param = request.args.get("page")
    limit_param = request.args.get("limit")

    if page_param is None and limit_param is None:
        # Original behavior preserved.
        return jsonify(list(logs_collection.find({}, {"_id": 0})))

    page, limit, skip = clamp_pagination(page_param, limit_param)
    cursor = (
        logs_collection.find({}, {"_id": 0})
        .sort("ingested_at", -1)
        .skip(skip)
        .limit(limit)
    )
    return jsonify({
        "page": page,
        "limit": limit,
        "total": logs_collection.count_documents({}),
        "items": list(cursor),
    })
