import os
import jwt
from pathlib import Path

def get_user(username: str):
    # Simulating a safe database interaction using parameterized queries
    # In a real application, this would use a DB library like psycopg2 or sqlite3
    # Example: cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    # return cursor.fetchone()
    
    # For demonstration, returning a mock safe structure
    return {"username": username, "id": 1}

def verify_token(token: str):
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        raise ValueError("JWT_SECRET environment variable is not set")
    
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except jwt.InvalidTokenError:
        return None

def safe_path_join(base_dir: str, user_input: str) -> Path:
    base = Path(base_dir).resolve()
    target = (base / user_input).resolve()
    
    # Ensure the resolved path is still within the base directory
    if not target.is_relative_to(base):
        raise ValueError("Invalid path: directory traversal detected")
    
    return target