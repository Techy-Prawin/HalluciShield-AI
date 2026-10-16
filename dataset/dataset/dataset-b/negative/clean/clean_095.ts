import os
import jwt
from pathlib import Path
from typing import Optional

def get_user(username: str) -> Optional[dict]:
    # In a real application, use a secure database connection pool
    # This is a placeholder for the actual DB interaction
    # Example using sqlite3 for demonstration, but in production use a proper ORM or DB driver
    import sqlite3
    
    # Use parameterized query to prevent SQL injection
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return dict(zip(["id", "username", "email"], result))
    return None

def verify_jwt(token: str) -> Optional[dict]:
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        raise ValueError("JWT_SECRET environment variable is not set")
    
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except jwt.InvalidTokenError:
        return None