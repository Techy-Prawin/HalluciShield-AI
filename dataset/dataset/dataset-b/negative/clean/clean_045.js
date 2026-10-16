import os
import jwt
from pathlib import Path

def verify_token(token: str) -> dict:
    secret = os.environ.get('JWT_SECRET')
    if not secret:
        raise ValueError('JWT_SECRET environment variable is not set')
    return jwt.decode(token, secret, algorithms=['HS256'])

def read_config(filename: str) -> str:
    base_dir = Path('/app/config')
    file_path = (base_dir / filename).resolve()
    if not file_path.is_relative_to(base_dir):
        raise ValueError('Invalid file path')
    return file_path.read_text(encoding='utf-8')