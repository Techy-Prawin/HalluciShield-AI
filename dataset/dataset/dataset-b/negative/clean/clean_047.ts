import os
import jwt
from pathlib import Path
from typing import Optional

def get_user(username: str) -> Optional[dict]:
    # In a real application, use a secure database connection pool
    # This is a placeholder for the actual DB interaction
    # Example using a parameterized query with a real DB library like psycopg2 or sqlite3
    # import sqlite3
    # conn = sqlite3.connect(os.environ.get('DB_PATH', 'app.db'))
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

def safe_path_join(base_dir: str, user_input: str) -> Path:
    base = Path(base_dir).resolve()
    target = (base / user_input).resolve()
    
    if not target.is_relative_to(base):
        raise ValueError("Path traversal attempt detected")
    
    return target