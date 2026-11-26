"""
AI-Based Intrusion Detection System (AI-IDS)
Project Code: RW-CS-001 | RW Software Solutions
Configuration Settings
"""

import os

class Settings:
    PROJECT_NAME: str = "AI-Based Intrusion Detection System (AI-IDS)"
    PROJECT_CODE: str = "RW-CS-001"
    ORGANIZATION: str = "RW Software Solutions"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"

    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "rw-ids-super-secret-key-soc-enterprise-2026")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # Database
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    DB_DIR: str = os.path.join(BASE_DIR, "database")
    DATABASE_URL: str = f"sqlite:///{os.path.join(DB_DIR, 'ids_database.db')}"

    # ML Paths
    ML_DIR: str = os.path.join(BASE_DIR, "ml")
    MODELS_DIR: str = os.path.join(ML_DIR, "models")
    SAMPLE_DATA_DIR: str = os.path.join(ML_DIR, "sample_data")

    # Default Superadmin Credentials
    DEFAULT_ADMIN_USERNAME: str = "admin"
    DEFAULT_ADMIN_PASSWORD: str = "Admin@123"
    DEFAULT_ADMIN_EMAIL: str = "soc-admin@rw-solutions.com"
    DEFAULT_ADMIN_NAME: str = "Senior Security Analyst"

settings = Settings()
