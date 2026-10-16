import os
import jwt
from pathlib import Path
from typing import Optional

def get_user(username: str) -> Optional[dict]:
    # In a real application, use a secure database connection pool
    # This is a placeholder for the actual database interaction
    # Ensure the database driver supports parameterized queries
    pass

def verify_token(token: str) -> dict:
    secret_key = os.environ.get('JWT_SECRET_KEY')
    if not secret_key:
        raise ValueError("JWT_SECRET_KEY environment variable is not set")
    
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        return payload
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")

def safe_path_join(base_dir: str, user_input: str) -> Path:
    base_path = Path(base_dir).resolve()
    user_path = Path(user_input).resolve()
    
    # Ensure the resolved path is within the base directory
    if not str(user_path).startswith(str(base_path)):
        raise ValueError("Invalid path: directory traversal detected")
    
    return user_path