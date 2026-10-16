import os
import jwt
from pathlib import Path
from dotenv import load_dotload

load_dotenv()

SECRET_KEY = os.getenv('JWT_SECRET_KEY')

def verify_token(token: str) -> dict:
    if not SECRET_KEY:
        raise ValueError('JWT_SECRET_KEY environment variable is not set')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError('Token has expired')
    except jwt.InvalidTokenError:
        raise ValueError('Invalid token')

def get_user_profile(user_id: int) -> Path:
    base_dir = Path(os.getenv('PROFILE_DIR', '/var/data/profiles'))
    user_path = base_dir / f'user_{user_id}.json'
    if not user_path.is_file():
        raise FileNotFoundError(f'Profile for user {user_id} not found')
    return user_path