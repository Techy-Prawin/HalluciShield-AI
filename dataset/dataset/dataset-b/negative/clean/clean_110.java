import os
import jwt
from pathlib import Path
from datetime import datetime, timedelta, timezone

SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
if not SECRET_KEY:
    raise ValueError('JWT_SECRET_KEY environment variable is not set')

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError('Token has expired')
    except jwt.InvalidTokenError:
        raise ValueError('Invalid token')

def get_user_profile(user_id: int) -> Path:
    base_dir = Path('/var/data/users')
    user_file = base_dir / f'{user_id}.json'
    if not user_file.is_file():
        raise FileNotFoundError(f'User profile not found for ID {user_id}')
    return user_file