import os
import jwt
from pathlib import Path
from typing import Optional

def get_user(username: str) -> Optional[dict]:
    # In a real application, use a secure database connection pool
    # This is a placeholder for the actual DB interaction
    # Example using a parameterized query (conceptual)
    # cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    # return cursor.fetchone()
    return None

def verify_token(token: str) -> dict:
    secret = os.environ.get('JWT_SECRET')
    if not secret:
        raise ValueError("JWT_SECRET environment variable is not set")
    
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")

def read_config(filename: str) -> str:
    # Use pathlib for safe path handling
    config_path = Path("config") / filename
    if not config_path.is_file():
        raise FileNotFoundError(f"Config file {filename} not found")
    
    # Ensure the path is within the expected directory to prevent directory traversal
    try:
        config_path.resolve().relative_to(Path("config").resolve())
    except ValueError:
        raise ValueError("Invalid config file path")
    
    return config_path.read_text(encoding='utf-8')