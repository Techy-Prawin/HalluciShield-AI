import os
import jwt
from pathlib import Path
from datetime import datetime, timedelta, timezone

def verify_token(token: str) -> dict:
    secret = os.environ.get('JWT_SECRET')
    if not secret:
        raise ValueError("JWT_SECRET environment variable is not set")
    
    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            options={"require": ["exp", "iat"]}
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {str(e)}")

def get_user_profile(user_id: int) -> dict:
    base_dir = Path(os.environ.get('APP_DATA_DIR', '/var/app/data'))
    user_file = base_dir / 'users' / f'{user_id}.json'
    
    if not user_file.exists():
        return {}
    
    try:
        with open(user_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}