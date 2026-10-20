"""IP intelligence + attack-chain routes."""

from datetime import datetime

from flask import Blueprint, jsonify

from extensions import alerts_collection
from services.intel import lookup_ip
from services.validation import is_valid_ip
from services.auth import require_role

intel_bp = Blueprint("intel", __name__)


@intel_bp.route("/ip-intel/<ip>", methods=["GET"])
@require_role("viewer")
def ip_intel(ip):
    if not is_valid_ip(ip):
        return jsonify({"error": "Invalid IP address"}), 400
    try:
        return jsonify(lookup_ip(ip))
    except Exception:
        return jsonify({"error": "Intel lookup failed"}), 502


@intel_bp.route("/attack-chain")
@require_role("viewer")
def attack_chain():
    alerts = list(alerts_collection.find())

    chains = {}
    for a in alerts:
        ip = a.get("src_ip")
        chains.setdefault(ip, []).append({
            "type": a.get("alert", {}).get("signature"),
            "severity": a.get("alert", {}).get("severity"),
            "time": a.get("timestamp"),
        })

    for ip in chains:
        chains[ip] = sorted(chains[ip], key=lambda x: x["time"] or datetime.min)

    return jsonify(chains)
