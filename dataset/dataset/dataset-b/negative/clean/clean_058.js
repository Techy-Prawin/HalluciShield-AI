import os
import jwt
from pathlib import Path

SECRET_KEY = os.environ.get('JWT_SECRET_KEY')

if not SECRET_KEY:
    raise ValueError('JWT_SECRET_KEY environment variable is not set')

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.InvalidTokenError:
        return {}

def get_user_file(username: str) -> Path:
    safe_username = Path(username).name
    return Path('/var/data/users') / safe_username