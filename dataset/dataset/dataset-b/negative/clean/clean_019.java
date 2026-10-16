import os
import jwt
from pathlib import Path
from datetime import datetime, timedelta, timezone

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

def get_user_profile(user_id: int) -> Path:
    base_dir = Path('/var/data/users')
    user_path = base_dir / f'{user_id}.json'
    if not user_path.is_file():
        raise FileNotFoundError(f'User profile not found for ID {user_id}')
    return user_path

def execute_safe_query(query: str, params: tuple) -> list:
    # Placeholder for actual DB execution using parameterized queries
    # Example: cursor.execute(query, params)
    return []