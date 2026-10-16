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

def get_user(username: str, cursor) -> dict:
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    if row:
        return dict(row)
    return None

def read_config(filename: str) -> str:
    base_dir = Path('/app/config')
    file_path = base_dir / filename
    if not file_path.is_file():
        raise FileNotFoundError('Config file not found')
    return file_path.read_text(encoding='utf-8')