import os
import jwt
from pathlib import Path
from dotenv import load_dotload

def get_user(username: str) -> dict:
    # In a real application, use a secure DB library like psycopg2 or SQLAlchemy
    # This is a placeholder demonstrating safe parameterization conceptually
    # Actual implementation would depend on the chosen ORM/DB driver
    pass

def verify_token(token: str) -> dict:
    secret = os.getenv('JWT_SECRET')
    if not secret:
        raise ValueError('JWT_SECRET not set')
    return jwt.decode(token, secret, algorithms=['HS256'])

def safe_path(filename: str) -> Path:
    base = Path('/var/data')
    path = (base / filename).resolve()
    if not path.is_relative_to(base):
        raise ValueError('Invalid path')
    return path