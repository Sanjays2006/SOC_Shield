"""PCAP upload + analysis route."""

import os

from flask import Blueprint, jsonify, request, current_app

from services.pcap import safe_filename, is_allowed_pcap, analyze_pcap
from services.auth import require_role

pcap_bp = Blueprint("pcap", __name__)


@pcap_bp.route("/upload-pcap", methods=["POST"])
@require_role("analyst")
def upload_pcap():
    try:
        file = request.files.get("file")
        if not file or not file.filename:
            return jsonify({"error": "No file uploaded"}), 400

        name = safe_filename(file.filename)
        if not is_allowed_pcap(name):
            return jsonify({"error": "Unsupported file type"}), 400

        os.makedirs("uploads", exist_ok=True)
        filepath = os.path.join("uploads", name)
        file.save(filepath)

        return jsonify(analyze_pcap(filepath))

    except Exception:
        current_app.logger.exception("PCAP processing failed")
        return jsonify({"error": "Failed to process PCAP file"}), 500
