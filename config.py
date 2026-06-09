"""
Configuration module for SSL Certificate Expiry Watcher.
Loads environment variables and defines application constants.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# ── Paths ──────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"
DB_FILE = BASE_DIR / "ssl_watcher.db"

# ── Auto-create .env if missing ────────────────────────────────────────
if not ENV_FILE.exists():
    ENV_FILE.write_text(
        "GROQ_API_KEY=\n"
        "OPENROUTER_API_KEY=\n"
        "SLACK_WEBHOOK_URL=\n"
        "SMTP_SERVER=\n"
        "SMTP_PORT=587\n"
        "SMTP_USER=\n"
        "SMTP_PASSWORD=\n"
        "EMAIL_TO=\n",
        encoding="utf-8",
    )

load_dotenv(ENV_FILE)

# ── API Keys ───────────────────────────────────────────────────────────
GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")

# ── Notification Settings ──────────────────────────────────────────────
SLACK_WEBHOOK_URL: str = os.getenv("SLACK_WEBHOOK_URL", "")
SMTP_SERVER: str = os.getenv("SMTP_SERVER", "")
SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587") or "587")
SMTP_USER: str = os.getenv("SMTP_USER", "")
SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
EMAIL_TO: str = os.getenv("EMAIL_TO", "")
EMAIL_FROM: str = os.getenv("EMAIL_FROM", "ssl-watcher@localhost")

# ── LLM Models ─────────────────────────────────────────────────────────
GROQ_MODEL = "llama3-70b-8192"
OPENROUTER_MODEL = "meta-llama/llama-3.1-8b-instruct"

# ── SSL Checker ─────────────────────────────────────────────────────────
SSL_TIMEOUT_SECONDS = 10

# ── Status Thresholds ───────────────────────────────────────────────────
SAFE_THRESHOLD = 30       # > 30 days → SAFE
WARNING_THRESHOLD = 7     # 7-30 days → WARNING
                          # < 7 days  → CRITICAL

# ── Streamlit Server Port (for Render deployment) ───────────────────────
PORT = int(os.getenv("PORT", 8501))
