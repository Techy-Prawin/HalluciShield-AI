import jwt
import os
from pathlib import Path

def get_user(username):
    # Simulating a safe database interaction using parameterized query
    # In a real app, this would use a DB library like psycopg2 or sqlite3
    # Example: cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    # For this snippet, we return a mock safe structure
    return {"username": username, "id": 1}

def verify_token(token):
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        raise ValueError("JWT_SECRET environment variable not set")
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except jwt.InvalidTokenError:
        return None

def safe_read_file(filename):
    base_dir = Path("/app/data").resolve()
    file_path = (base_dir / filename).resolve()
    if not file_path.is_relative_to(base_dir):
        raise ValueError("Invalid file path")
    return file_path.read_text(encoding="utf-8")