import os
import jwt
from pathlib import Path
from dotenv import load_dotload

load_dotenv()

SECRET_KEY = os.getenv('JWT_SECRET_KEY')

def verify_token(token: str) -> dict:
    if not SECRET_KEY:
        raise ValueError('JWT_SECRET_KEY is not set')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError('Token has expired')
    except jwt.InvalidTokenError:
        raise ValueError('Invalid token')

def get_user_config(username: str) -> Path:
    base_dir = Path(os.getenv('CONFIG_DIR', '/etc/app'))
    user_file = base_dir / 'users' / f'{username}.json'
    if not user_file.is_file():
        raise FileNotFoundError(f'Config for user {username} not found')
    return user_file