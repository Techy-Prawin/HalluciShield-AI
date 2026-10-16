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

def get_user(username: str, cursor) -> tuple:
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()

def read_config(filename: str) -> str:
    base_dir = Path(__file__).parent
    config_path = base_dir / 'config' / filename
    if not config_path.is_file():
        raise FileNotFoundError(f'Config file {filename} not found')
    return config_path.read_text(encoding='utf-8')