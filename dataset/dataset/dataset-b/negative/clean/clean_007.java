import os
import jwt
from pathlib import Path
from datetime import datetime, timedelta, timezone

def get_user(username: str) -> dict:
    # Simulating a secure database interaction using parameterized query
    # In a real application, use a DB library like psycopg2 or sqlalchemy
    # Example: cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    # For this clean code example, we return a mock secure structure
    return {"username": username, "id": 1}

def verify_token(token: str) -> dict:
    secret_key = os.environ.get("JWT_SECRET_KEY")
    if not secret_key:
        raise ValueError("JWT_SECRET_KEY environment variable is not set")
    
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")

def safe_file_read(filename: str) -> str:
    # Use pathlib to prevent directory traversal
    base_dir = Path("/app/data").resolve()
    file_path = (base_dir / filename).resolve()
    
    # Ensure the resolved path is still within the base directory
    if not file_path.is_relative_to(base_dir):
        raise ValueError("Invalid file path")
    
    if not file_path.exists() or not file_path.is_file():
        raise FileNotFoundError("File not found")
    
    return file_path.read_text(encoding="utf-8")