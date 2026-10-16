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

def verify_token(token: str):
    secret = os.getenv("JWT_SECRET")
    if not secret:
        raise ValueError("JWT_SECRET not set")
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None