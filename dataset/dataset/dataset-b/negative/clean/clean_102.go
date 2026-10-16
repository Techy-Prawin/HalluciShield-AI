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
    except jwt.InvalidTokenError:
        return {}

def read_config(filename: str) -> str:
    base_dir = Path(__file__).parent
    config_path = base_dir / 'config' / filename
    if not config_path.is_file():
        raise FileNotFoundError(f'Config file {filename} not found')
    return config_path.read_text(encoding='utf-8')