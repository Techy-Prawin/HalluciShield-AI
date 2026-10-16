import os
import jwt
from pathlib import Path

def get_user(username: str):
    # Simulating a safe database interaction using parameterized query
    # In a real app, use a DB library like psycopg2 or sqlite3 with placeholders
    query = "SELECT * FROM users WHERE username = ?"
    # Placeholder for actual DB cursor execution
    # cursor.execute(query, (username,))
    # return cursor.fetchone()
    return None

def verify_token(token: str) -> dict:
    secret = os.getenv('JWT_SECRET')
    if not secret:
        raise ValueError('JWT_SECRET environment variable not set')
    try:
        return jwt.decode(token, secret, algorithms=['HS256'])
    except jwt.InvalidTokenError:
        return {}

def safe_path(filename: str) -> Path:
    base = Path('/var/data')
    path = (base / filename).resolve()
    if not path.is_relative_to(base):
        raise ValueError('Invalid path')
    return path