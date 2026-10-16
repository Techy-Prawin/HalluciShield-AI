import os
import jwt
from pathlib import Path
from typing import Optional

SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
if not SECRET_KEY:
    raise ValueError('JWT_SECRET_KEY environment variable is not set')

def verify_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.InvalidTokenError:
        return None

def get_user_profile(user_id: str) -> Optional[Path]:
    base_dir = Path('/var/data/users')
    user_path = (base_dir / user_id).resolve()
    if not user_path.is_relative_to(base_dir):
        return None
    if user_path.exists():
        return user_path
    return None