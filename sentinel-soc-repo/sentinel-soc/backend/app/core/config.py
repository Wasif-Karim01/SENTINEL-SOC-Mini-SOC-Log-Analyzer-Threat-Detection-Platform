"""Application configuration and developer metadata."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR = DATA_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR = DATA_DIR / "backups"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

class Settings:
    PROJECT_NAME: str = "SENTINEL SOC"
    PROJECT_SUBTITLE: str = "Mini SOC Log Analyzer & Threat Detection Platform"
    PROJECT_CATEGORY: str = "Cybersecurity / Security Operations / Blue Team"
    VERSION: str = "1.0.0"
    DEVELOPER_NAME: str = "Wasif Karim"
    DEVELOPER_ROLE: str = "Cybersecurity Enthusiast | Computer Science & Engineering"
    DEVELOPER_EDUCATION: list = [
        "DU PMICS — 7th Batch",
        "B.Sc. in Computer Science & Engineering",
        "Daffodil International University",
    ]
    DEVELOPER_EMAIL: str = "wasifkarim.work@gmail.com"
    DEVELOPER_EMAIL_LINK: str = "mailto:wasifkarim.work@gmail.com"
    DEVELOPER_WHATSAPP: str = "+8801783734911"
    DEVELOPER_WHATSAPP_LINK: str = "https://wa.me/8801783734911"
    DEVELOPER_CREDIT: str = "Designed and Developed by Wasif Karim."

    DATABASE_PATH: str = os.getenv("SENTINEL_DB_PATH", str(DATA_DIR / "sentinel_soc.db"))
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{DATABASE_PATH}")
    DEFAULT_TIMEZONE: str = os.getenv("DEFAULT_TIMEZONE", "Asia/Dhaka")
    MAX_UPLOAD_BYTES: int = int(os.getenv("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))  # 10 MB
    ALLOWED_EXTENSIONS: set = {".log", ".txt", ".csv", ".json"}

    # Optional Threat Intelligence API Keys (never exposed to frontend)
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")

settings = Settings()
