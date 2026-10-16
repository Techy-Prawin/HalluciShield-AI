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

def verify_token(token: str) -> Optional[dict]:
    secret = os.environ.get('JWT_SECRET')
    if not secret:
        raise ValueError("JWT_SECRET environment variable is not set")
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except jwt.InvalidTokenError:
        return None