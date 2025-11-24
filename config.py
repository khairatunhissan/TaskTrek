import os
from dotenv import load_dotenv

load_dotenv()  # reads .env if present

class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET", "dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///tasktrek.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Grader sandbox limits (seconds / MB)
    GRADER_TIMEOUT_SECONDS = 2
    GRADER_MAX_MEMORY_MB = 128
