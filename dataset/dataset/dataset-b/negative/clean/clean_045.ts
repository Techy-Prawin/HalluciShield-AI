import os
import jwt
from pathlib import Path
from typing import Optional

def get_user(username: str) -> Optional[dict]:
    # In a real application, use a secure DB connection pool and parameterized queries.
    # This is a mock implementation for demonstration.
    # Example with sqlite3:
    # import sqlite3
    # conn = sqlite3.connect('app.db')
    # cursor = conn.cursor()
    # cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    # user = cursor.fetchone()
    # conn.close()
    # return user
    return None

def verify_token(token: str) -> dict:
    secret = os.environ.get('JWT_SECRET')
    if not secret:
        raise ValueError("JWT_SECRET environment variable is not set")
    
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")

def read_config(filename: str) -> str:
    # Use pathlib to safely handle file paths
    config_path = Path("config") / filename
    if not config_path.is_file():
        raise FileNotFoundError(f"Config file {filename} not found")
    
    # Ensure the file is within the expected directory to prevent path traversal
    if not config_path.resolve().is_relative_to(Path("config").resolve()):
        raise ValueError("Invalid config file path")
    
    return config_path.read_text(encoding='utf-8')