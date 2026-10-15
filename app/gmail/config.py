"""Settings for the Gmail integration, read from environment variables or a .env file."""
import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
TOKEN_KEY = os.getenv("TOKEN_ENCRYPTION_KEY", "").strip()
# Without a fixed secret, sessions only last until the server restarts.
SESSION_SECRET = os.getenv("SESSION_SECRET", "").strip() or secrets.token_urlsafe(32)
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000").strip().rstrip("/")
REDIRECT_URI = BASE_URL + "/auth/callback"
DB_PATH = Path(os.getenv("FRAUDLENS_DB", str(ROOT / "data" / "fraudlens.db")))
POLL_SECONDS = max(30, int(os.getenv("POLL_SECONDS", "90")))
INITIAL_SCAN = int(os.getenv("INITIAL_SCAN", "20"))
SCAN_BATCH = 25

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
]

if REDIRECT_URI.startswith(("http://localhost", "http://127.0.0.1")):
    os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")
os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")


def configured() -> bool:
    return bool(CLIENT_ID and CLIENT_SECRET and TOKEN_KEY)
