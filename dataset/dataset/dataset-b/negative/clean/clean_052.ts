import os
import jwt
from pathlib import Path
from typing import Optional

def verify_token(token: str) -> Optional[dict]:
    secret = os.environ.get('JWT_SECRET')
    if not secret:
        raise ValueError('JWT_SECRET environment variable is not set')
    try:
        return jwt.decode(token, secret, algorithms=['HS256'])
    except jwt.InvalidTokenError:
        return None

def read_config(filename: str) -> str:
    base_dir = Path(os.environ.get('CONFIG_DIR', '/etc/app'))
    config_path = (base_dir / filename).resolve()
    if not config_path.is_relative_to(base_dir):
        raise ValueError('Invalid config path')
    return config_path.read_text(encoding='utf-8')