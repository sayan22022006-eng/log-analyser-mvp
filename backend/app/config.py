import os

MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./log_analyser.db")
CORS_ORIGINS = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if origin.strip()]

# Defaults are demo thresholds, not universal security baselines.
RULE_THRESHOLDS = {
    "AUTH_001_WINDOW_SECONDS": 300,
    "AUTH_001_MEDIUM": 10,
    "AUTH_001_HIGH": 25,
    "AUTH_002_WINDOW_SECONDS": 300,
    "AUTH_002_MEDIUM": 8,
    "AUTH_002_HIGH": 20,
    "AUTH_003_WINDOW_SECONDS": 600,
    "AUTH_003_MIN_FAILURES": 5,
    "AUTH_004_WINDOW_SECONDS": 600,
    "AUTH_004_MIN_USERNAMES": 10,
    "ACCESS_001_WINDOW_SECONDS": 300,
    "ACCESS_001_MEDIUM": 20,
    "TRAFFIC_001_WINDOW_SECONDS": 60,
    "TRAFFIC_001_MEDIUM": 100,
    "DATA_001_UNPARSED_RATIO": 0.20,
}
