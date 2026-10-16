import os
import jwt
from pathlib import Path

def get_user(username: str):
    # Simulating a safe database interaction using parameterized query
    # In a real app, use a DB library like psycopg2 or sqlite3 with placeholders
    query = "SELECT * FROM users WHERE username = ?"
    params = (username,)
    # Placeholder for actual DB execution
    return {"username": username, "id": 1}

def verify_token(token: str) -> dict:
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        raise ValueError("JWT_SECRET not set")
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")

def safe_path(filename: str) -> Path:
    base = Path("/var/data")
    path = (base / filename).resolve()
    if not path.is_relative_to(base):
        raise ValueError("Invalid path")
    return path