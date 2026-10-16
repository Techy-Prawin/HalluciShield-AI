import os
import jwt
from pathlib import Path
from dotenv import load_dotload

load_dotenv()

SECRET_KEY = os.getenv('JWT_SECRET_KEY')
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

def get_user_config(username: str) -> Path:
    base_dir = Path(os.getenv('CONFIG_DIR', '/etc/app/config'))
    safe_username = Path(username).name
    config_path = base_dir / f'{safe_username}.json'
    if not config_path.is_file():
        raise FileNotFoundError(f'Config for user {safe_username} not found')
    return config_path