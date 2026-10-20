"""Authentication routes: login, register, current-user."""

from flask import Blueprint, jsonify, request, g

from config import config
from services.auth import (
    authenticate, create_user, require_role, users_collection, ROLES,
)

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    token = authenticate(username, password)
    if not token:
        return jsonify({"error": "Invalid username or password"}), 401

    user = users_collection.find_one({"username": username})
    return jsonify({"token": token, "role": user["role"], "username": username})


@auth_bp.route("/auth/register", methods=["POST"])
def register():
    """Create a user.

    Bootstrap rule: if NO users exist yet, the first registration creates an
    admin without auth. Afterwards, only an admin may register new users.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "viewer")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
    if role not in ROLES:
        return jsonify({"error": "Invalid role"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    bootstrap = users_collection.count_documents({}) == 0

    if bootstrap:
        role = "admin"  # first user is always admin
    else:
        # Require an admin token for subsequent registrations.
        from services.auth import decode_token
        hdr = request.headers.get("Authorization", "")
        token = hdr[7:].strip() if hdr.startswith("Bearer ") else None
        payload = decode_token(token) if token else None
        if not config.AUTH_ENABLED:
            pass
        elif not payload or payload.get("role") != "admin":
            return jsonify({"error": "Admin privileges required"}), 403

    try:
        create_user(username, password, role)
    except ValueError as e:
        return jsonify({"error": str(e)}), 409

    return jsonify({"message": f"User '{username}' created", "role": role}), 201


@auth_bp.route("/auth/me")
@require_role("viewer")
def me():
    return jsonify({"user": g.user.get("sub"), "role": g.user.get("role")})


@auth_bp.route("/auth/users")
@require_role("admin")
def list_users():
    users = [
        {"username": u["username"], "role": u["role"]}
        for u in users_collection.find({}, {"_id": 0, "username": 1, "role": 1})
    ]
    return jsonify(users)
