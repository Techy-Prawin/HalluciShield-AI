import os
import jwt
from pathlib import Path
from typing import Optional

def get_user(username: str) -> Optional[dict]:
    # In a real application, use a secure database connection pool
    # This is a placeholder for the actual DB interaction
    # Example using sqlite3 for demonstration, but in production use a proper DB driver
    import sqlite3
    
    # Use parameterized query to prevent SQL injection
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {'id': user[0], 'username': user[1], 'email': user[2]}
    return None

def verify_jwt(token: str) -> Optional[dict]:
    secret = os.environ.get('JWT_SECRET')
    if not secret:
        raise ValueError("JWT_SECRET environment variable is not set")
    
    try:
        payload = jwt.decode(token, secret, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def safe_path_join(base_dir: str, user_input: str) -> Path:
    base = Path(base_dir).resolve()
    target = (base / user_input).resolve()
    
    # Ensure the resolved path is still within the base directory
    if not str(target).startswith(str(base)):
        raise ValueError("Invalid path: directory traversal detected")
    
    return target