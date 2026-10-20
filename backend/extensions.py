"""
Shared extensions / singletons for the SOCShield backend.

Centralizes the MongoDB client, database handle, collection references,
the Socket.IO server, and index creation so blueprints and services can
import them without creating duplicate connections.
"""

from flask_socketio import SocketIO
from pymongo import MongoClient, ASCENDING, DESCENDING

from config import config

# Socket.IO server (CORS restricted to configured origins).
socketio = SocketIO(cors_allowed_origins=config.CORS_ORIGINS, async_mode="threading")

# MongoDB connection (single shared client).
client = MongoClient(config.MONGO_URI)
db = client[config.MONGO_DB]

logs_collection = db["logs"]
alerts_collection = db["alerts"]
blocked_collection = db["blocked_ips"]


def ensure_indexes():
    """Create indexes used by queries, dedup, and pagination.

    Safe to call repeatedly — MongoDB createIndex is idempotent.
    """
    # Alerts: filtered by status, sorted/paginated by timestamp.
    alerts_collection.create_index([("timestamp", DESCENDING)])
    alerts_collection.create_index([("status", ASCENDING)])
    alerts_collection.create_index([("src_ip", ASCENDING)])

    # Logs: paginated by insertion time.
    logs_collection.create_index([("ingested_at", DESCENDING)])

    # Dedup: a unique-ish fingerprint per normalized event. Sparse so
    # legacy documents without the field are not forced to collide.
    logs_collection.create_index([("event_hash", ASCENDING)], sparse=True)

    # Blocked IPs: fast "already blocked?" lookups + uniqueness.
    blocked_collection.create_index([("ip", ASCENDING)], unique=True)
