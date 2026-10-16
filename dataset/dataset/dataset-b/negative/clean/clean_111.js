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
        raise ValueError("JWT_SECRET environment variable not set")
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {e}")

def safe_path_join(base_dir: str, user_input: str) -> Path:
    base = Path(base_dir).resolve()
    target = (base / user_input).resolve()
    if not target.is_relative_to(base):
        raise ValueError("Path traversal detected")
    return target