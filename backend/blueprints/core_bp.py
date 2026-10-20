"""Core/health routes."""

from flask import Blueprint, jsonify

core_bp = Blueprint("core", __name__)


@core_bp.route("/")
def home():
    return {"message": "SOCShield Backend Running"}


@core_bp.route("/health")
def health():
    return jsonify({"status": "ok"})
