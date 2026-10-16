import os
import jwt
import sqlite3
from pathlib import Path

def get_user(username: str) -> dict | None:
    db_path = Path(os.environ.get('DB_PATH', 'app.db'))
    if not db_path.exists():
        raise FileNotFoundError(f"Database file not found: {db_path}")
    
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        return dict(row) if row else None

def verify_token(token: str) -> dict:
    secret = os.environ.get('JWT_SECRET')
    if not secret:
        raise ValueError("JWT_SECRET environment variable is not set")
    
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {e}")