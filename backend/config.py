"""
SOCShield backend configuration.

All runtime configuration is loaded from environment variables (optionally
via a local .env file). NO secrets are hard-coded here. See .env.example
for the full list of supported variables and their meaning.
"""

import os

try:
    # python-dotenv is optional; if present we load a local .env file.
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover - dotenv is a convenience only
    pass


def _as_bool(value, default=False):
    """Parse a truthy environment string into a bool."""
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


class Config:
    # ---- Flask runtime ----
    ENV = os.getenv("FLASK_ENV", "development")
    DEBUG = _as_bool(os.getenv("FLASK_DEBUG"), default=False)
    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", "5000"))
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-insecure-key")

    # ---- MongoDB ----
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/")
    MONGO_DB = os.getenv("MONGO_DB", "socshield")

    # ---- CORS ----
    # Comma-separated list of trusted origins. Empty => none allowed.
    CORS_ORIGINS = [
        o.strip()
        for o in os.getenv(
            "CORS_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173"
        ).split(",")
        if o.strip()
    ]

    # ---- Telegram alerting (optional) ----
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

    @classmethod
    def telegram_enabled(cls):
        return bool(cls.TELEGRAM_BOT_TOKEN and cls.TELEGRAM_CHAT_ID)

    # ---- Automated response ----
    # Firewall blocking is a destructive, environment-specific action.
    # Disabled unless explicitly turned on in an authorized environment.
    ENABLE_AUTO_BLOCK = _as_bool(os.getenv("ENABLE_AUTO_BLOCK"), default=False)

    # ---- External intel API ----
    IP_API_BASE = os.getenv("IP_API_BASE", "http://ip-api.com/json")

    # ---- Authentication & RBAC ----
    # Master switch. When false, auth decorators allow all requests (useful
    # for local development). Default ON.
    AUTH_ENABLED = _as_bool(os.getenv("AUTH_ENABLED", "true"), default=True)
    # Secret used to sign JWTs. MUST be set to a strong random value in prod.
    JWT_SECRET = os.getenv("JWT_SECRET", "dev-only-jwt-secret-change-me")
    JWT_ALG = "HS256"
    JWT_EXPIRY_MIN = int(os.getenv("JWT_EXPIRY_MIN", "480"))  # 8 hours
    # Seed admin (created at startup if the users collection is empty).
    SEED_ADMIN_USER = os.getenv("SEED_ADMIN_USER", "admin").strip()
    SEED_ADMIN_PASSWORD = os.getenv("SEED_ADMIN_PASSWORD", "").strip()
    # Shared API key the agent uses to POST /ingest (service-to-service).
    INGEST_API_KEY = os.getenv("INGEST_API_KEY", "").strip()

    # ---- AI incident summaries (optional) ----
    # Provider: "none" (deterministic fallback only), "openai", or "ollama".
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "none").strip().lower()
    LLM_API_KEY = os.getenv("LLM_API_KEY", "").strip()
    LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini").strip()
    # Base URL for OpenAI-compatible or local (Ollama) endpoints.
    LLM_BASE_URL = os.getenv("LLM_BASE_URL", "").strip()
    LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "20"))

    @classmethod
    def llm_enabled(cls):
        if cls.LLM_PROVIDER in ("", "none"):
            return False
        if cls.LLM_PROVIDER == "ollama":
            return True  # local model, no key required
        return bool(cls.LLM_API_KEY)


config = Config()
