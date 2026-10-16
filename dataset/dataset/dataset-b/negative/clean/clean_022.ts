import os
import jwt
from pathlib import Path
from typing import Optional

def get_user(username: str) -> Optional[dict]:
    # Simulating a safe database interaction using parameterized queries
    # In a real scenario, this would use a DB library like psycopg2 or sqlite3
    # Example: cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    # For this snippet, we return a mock structure to demonstrate the interface
    return {"username": username, "id": 1}

def verify_token(token: str) -> dict:
    secret = os.getenv("JWT_SECRET")
    if not secret:
        raise ValueError("JWT_SECRET environment variable is not set")
    
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {e}")

def read_config(filename: str) -> str:
    # Using pathlib for safe path handling
    base_dir = Path(os.getenv("APP_BASE_DIR", "."))
    config_path = base_dir / filename
    
    # Prevent path traversal
    if not config_path.is_file() or not config_path.resolve().is_relative_to(base_dir.resolve()):
        raise ValueError("Invalid config file path")
    
    return config_path.read_text(encoding="utf-8")