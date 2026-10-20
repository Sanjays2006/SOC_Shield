"""
Pytest configuration + fixtures for API/persistence tests.

Uses mongomock to provide an in-memory MongoDB so tests need no live
database. If mongomock is not installed, DB-dependent tests are skipped
with a clear reason (pure-logic tests still run).
"""

import importlib
import sys

import pytest

try:
    import mongomock  # noqa: F401
    HAVE_MONGOMOCK = True
except Exception:
    HAVE_MONGOMOCK = False


@pytest.fixture
def app_client(monkeypatch):
    """Flask test client backed by an in-memory Mongo (mongomock)."""
    if not HAVE_MONGOMOCK:
        pytest.skip("mongomock not installed")

    import mongomock
    import os
    os.environ["AUTH_ENABLED"] = "false"  # disable auth for endpoint tests

    # Patch MongoClient BEFORE importing extensions/app so the module-level
    # client uses the in-memory server.
    monkeypatch.setattr("pymongo.MongoClient", mongomock.MongoClient)

    # Force a fresh import of extensions + app with the patched client.
    for mod in list(sys.modules):
        if mod in ("extensions", "app") or mod.startswith("blueprints") \
                or mod.startswith("services"):
            sys.modules.pop(mod, None)

    extensions = importlib.import_module("extensions")
    app_module = importlib.import_module("app")

    flask_app = app_module.create_app()
    flask_app.config.update(TESTING=True)

    client = flask_app.test_client()
    client._collections = {
        "logs": extensions.logs_collection,
        "alerts": extensions.alerts_collection,
        "blocked": extensions.blocked_collection,
    }
    return client
