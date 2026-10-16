import os
import jwt
from pathlib import Path
from typing import Optional

def get_user(username: str) -> Optional[dict]:
    # In a real application, use a secure database connection pool
    # This is a placeholder for the actual DB interaction
    # Example using a parameterized query with a real DB library like psycopg2 or sqlite3
    # For demonstration, we return a mock structure
    return {"username": username, "id": 1}

def verify_token(token: str) -> dict:
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        raise ValueError("JWT_SECRET environment variable is not set")
    
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {str(e)}")

def read_config(filename: str) -> str:
    # Use pathlib for safe path handling
    base_dir = Path(__file__).parent
    config_path = base_dir / filename
    
    # Prevent path traversal
    if not config_path.is_file() or not config_path.resolve().is_relative_to(base_dir.resolve()):
        raise ValueError("Invalid config file path")
    
    return config_path.read_text(encoding="utf-8")