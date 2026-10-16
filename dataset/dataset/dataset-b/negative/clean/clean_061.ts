import os
import jwt
from pathlib import Path
from typing import Optional

def get_user(username: str) -> Optional[dict]:
    # In a real application, use a secure database connection pool
    # This is a placeholder for demonstration
    pass

def verify_token(token: str) -> dict:
    secret = os.environ.get('JWT_SECRET')
    if not secret:
        raise ValueError('JWT_SECRET environment variable is not set')
    
    try:
        payload = jwt.decode(token, secret, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError('Token has expired')
    except jwt.InvalidTokenError:
        raise ValueError('Invalid token')

def safe_path_join(base_dir: str, user_input: str) -> Path:
    base = Path(base_dir).resolve()
    target = (base / user_input).resolve()
    
    if not target.is_relative_to(base):
        raise ValueError('Invalid path: directory traversal detected')
    
    return target