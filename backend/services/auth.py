"""
Authentication & RBAC service.

- Passwords hashed with PBKDF2-HMAC-SHA256 (stdlib hashlib) + per-user salt.
  No external bcrypt dependency required.
- Stateless JWTs (HS256) signed with config.JWT_SECRET, carrying the
  username and role. Minimal dependency-light implementation.
- Roles form a hierarchy: viewer < analyst < admin.
- When config.AUTH_ENABLED is False, protection decorators allow all
  requests (local-dev convenience) — documented and off-by-default-unsafe.

Collections:
  users: { username, salt, pwd_hash, role, created_at }
"""

import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime
from functools import wraps

from flask import request, jsonify, g

from config import config
from extensions import db

users_collection = db["users"]

# Role hierarchy — higher number = more privilege.
ROLES = {"viewer": 1, "analyst": 2, "admin": 3}


# ---------------- password hashing ----------------

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             salt.encode("utf-8"), 200_000)
    return salt, dk.hex()


def verify_password(password, salt, expected_hash):
    _, computed = hash_password(password, salt)
    return hmac.compare_digest(computed, expected_hash)


# ---------------- JWT (HS256, minimal) ----------------

def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s):
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def create_token(username, role):
    header = {"alg": config.JWT_ALG, "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + config.JWT_EXPIRY_MIN * 60,
    }
    seg = _b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + \
        _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(config.JWT_SECRET.encode(), seg.encode(), hashlib.sha256).digest()
    return seg + "." + _b64url(sig)


def decode_token(token):
    """Return the payload dict if valid and unexpired, else None."""
    try:
        seg, sig = token.rsplit(".", 1)
        expected = hmac.new(config.JWT_SECRET.encode(), seg.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url_decode(sig), expected):
            return None
        payload = json.loads(_b64url_decode(seg.split(".", 1)[1]))
        if payload.get("exp", 0) < int(time.time()):
            return None
        return payload
    except Exception:
        return None


# ---------------- user management ----------------

def create_user(username, password, role="viewer"):
    if role not in ROLES:
        raise ValueError("invalid role")
    if users_collection.find_one({"username": username}):
        raise ValueError("user exists")
    salt, pwd_hash = hash_password(password)
    users_collection.insert_one({
        "username": username,
        "salt": salt,
        "pwd_hash": pwd_hash,
        "role": role,
        "created_at": datetime.utcnow(),
    })


def authenticate(username, password):
    """Return a token on success, or None on failure."""
    user = users_collection.find_one({"username": username})
    if not user:
        return None
    if not verify_password(password, user["salt"], user["pwd_hash"]):
        return None
    return create_token(username, user["role"])


def ensure_seed_admin():
    """Create the seed admin from env if the users collection is empty."""
    if users_collection.count_documents({}) > 0:
        return
    if config.SEED_ADMIN_PASSWORD:
        create_user(config.SEED_ADMIN_USER, config.SEED_ADMIN_PASSWORD, "admin")
        print(f"👤 Seeded admin user '{config.SEED_ADMIN_USER}'")
    else:
        print("ℹ️ No SEED_ADMIN_PASSWORD set — create users via /auth/register "
              "(first user bootstrap) or set it in .env.")


# ---------------- decorators ----------------

def _extract_token():
    hdr = request.headers.get("Authorization", "")
    if hdr.startswith("Bearer "):
        return hdr[7:].strip()
    return None


def require_role(min_role="viewer"):
    """Protect a route, requiring at least `min_role`.

    When AUTH_ENABLED is False, allows all requests (dev mode).
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not config.AUTH_ENABLED:
                g.user = {"sub": "dev", "role": "admin"}
                return fn(*args, **kwargs)

            token = _extract_token()
            payload = decode_token(token) if token else None
            if not payload:
                return jsonify({"error": "Authentication required"}), 401

            user_role = payload.get("role", "viewer")
            if ROLES.get(user_role, 0) < ROLES.get(min_role, 99):
                return jsonify({"error": "Insufficient privileges"}), 403

            g.user = payload
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_api_key_or_role(min_role="analyst"):
    """Allow EITHER a valid service API key (X-API-Key) OR a JWT role.

    Used for /ingest so the agent can post with a shared key while humans
    still need a role.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not config.AUTH_ENABLED:
                return fn(*args, **kwargs)

            api_key = request.headers.get("X-API-Key", "")
            if config.INGEST_API_KEY and hmac.compare_digest(api_key, config.INGEST_API_KEY):
                g.user = {"sub": "agent", "role": "analyst"}
                return fn(*args, **kwargs)

            token = _extract_token()
            payload = decode_token(token) if token else None
            if payload and ROLES.get(payload.get("role", "viewer"), 0) >= ROLES.get(min_role, 99):
                g.user = payload
                return fn(*args, **kwargs)

            return jsonify({"error": "Authentication required"}), 401
        return wrapper
    return decorator
