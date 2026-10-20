"""Automated-response routes: block IP."""

from datetime import datetime

from flask import Blueprint, jsonify, request, current_app
from pymongo.errors import DuplicateKeyError

from extensions import blocked_collection
from services.validation import is_valid_ip
from services.response import firewall_block_ip
from services.auth import require_role

response_bp = Blueprint("response", __name__)


@response_bp.route("/block-ip", methods=["POST"])
@require_role("admin")
def block_ip_route():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")

    if not ip:
        return jsonify({"error": "IP missing"}), 400
    if not is_valid_ip(ip):
        return jsonify({"error": "Invalid IP address"}), 400

    if blocked_collection.find_one({"ip": ip}):
        return jsonify({"message": "Already blocked"}), 200

    try:
        firewall_block_ip(ip)
        try:
            blocked_collection.insert_one({"ip": ip, "blocked_at": datetime.utcnow()})
        except DuplicateKeyError:
            return jsonify({"message": "Already blocked"}), 200
        return jsonify({"message": f"{ip} blocked successfully"})
    except Exception:
        current_app.logger.exception("Block IP failed")
        return jsonify({"error": "Block operation failed"}), 500


@response_bp.route("/blocked-ips", methods=["GET"])
@require_role("viewer")
def blocked_ips():
    """List currently blocked IPs (used by the investigation drawer)."""
    items = []
    for b in blocked_collection.find({}, {"_id": 0}):
        if isinstance(b.get("blocked_at"), datetime):
            b["blocked_at"] = b["blocked_at"].isoformat()
        items.append(b)
    return jsonify(items)
