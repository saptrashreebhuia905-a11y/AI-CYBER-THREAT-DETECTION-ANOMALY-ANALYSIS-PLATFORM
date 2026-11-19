import logging
import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

logger = logging.getLogger(__name__)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/")
MONGO_DATABASE = os.getenv("MONGO_DATABASE", "sentinel_ai_db")
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    JWT_SECRET = secrets.token_urlsafe(32)
    logger.warning("JWT_SECRET is unset; generated a temporary key. Set JWT_SECRET to keep sessions across restarts.")
elif len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET must be at least 32 characters long.")

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
