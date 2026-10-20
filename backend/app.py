"""
SOCShield backend — application factory.

The former monolithic app.py has been refactored into:
  - config.py            runtime configuration (env-based)
  - extensions.py        Mongo client, collections, Socket.IO, indexes
  - services/            reusable logic (ingest, scoring, intel, pcap, response)
  - blueprints/          HTTP routes grouped by concern

Every original route path and response shape is preserved. Run with:
    python3 app.py
"""

import logging

from flask import Flask, jsonify
from flask_cors import CORS

from config import config
from extensions import socketio, ensure_indexes
from blueprints.core_bp import core_bp
from blueprints.ingest_bp import ingest_bp
from blueprints.alerts_bp import alerts_bp
from blueprints.intel_bp import intel_bp
from blueprints.response_bp import response_bp
from blueprints.pcap_bp import pcap_bp
from blueprints.stats_bp import stats_bp
from blueprints.ml_bp import ml_bp
from blueprints.auth_bp import auth_bp


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.SECRET_KEY

    logging.basicConfig(level=logging.INFO)

    # 🔒 CORS restricted to configured trusted origins (no wildcard).
    CORS(app, origins=config.CORS_ORIGINS)

    # Bind Socket.IO to this app instance.
    socketio.init_app(app, cors_allowed_origins=config.CORS_ORIGINS)

    # Register all route blueprints.
    app.register_blueprint(core_bp)
    app.register_blueprint(ingest_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(intel_bp)
    app.register_blueprint(response_bp)
    app.register_blueprint(pcap_bp)
    app.register_blueprint(stats_bp)
    app.register_blueprint(ml_bp)
    app.register_blueprint(auth_bp)

    # Generic error handler — never leak tracebacks to clients.
    @app.errorhandler(Exception)
    def handle_unexpected(err):
        app.logger.exception("Unhandled error")
        return jsonify({"error": "Internal server error"}), 500

    # Create indexes at startup (idempotent). Non-fatal if Mongo is down
    # at import time — it will retry on first real query.
    try:
        ensure_indexes()
    except Exception:
        app.logger.warning("Index creation deferred (MongoDB not reachable yet)")

    try:
        from services.auth import ensure_seed_admin
        ensure_seed_admin()
    except Exception:
        app.logger.warning("Seed admin deferred (MongoDB not reachable yet)")

    return app


app = create_app()


if __name__ == "__main__":
    socketio.run(
        app,
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG,
        allow_unsafe_werkzeug=True,
    )
