import os
import jwt
from pathlib import Path
from cryptography.fernet import Fernet

def get_user(username: str) -> dict:
    # Simulated secure database interaction using parameterized query
    # In a real app, use a DB library like psycopg2 or sqlite3 with parameterized queries
    # Example: cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    # For this example, we return a mock user to demonstrate structure
    return {"username": username, "id": 1}

def verify_token(token: str) -> dict:
    secret = os.getenv("JWT_SECRET")
    if not secret:
        raise ValueError("JWT_SECRET environment variable not set")
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {e}")

def read_config(filename: str) -> str:
    # Use pathlib for safe path handling
    config_path = Path("config") / filename
    if not config_path.is_file():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    return config_path.read_text(encoding="utf-8")