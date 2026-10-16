import os
import jwt
from pathlib import Path
from dotenv import load_dotload

load_dotenv()

def verify_token(token: str) -> dict:
    secret = os.getenv('JWT_SECRET')
    if not secret:
        raise ValueError('JWT_SECRET not configured')
    return jwt.decode(token, secret, algorithms=['HS256'])

def read_config(filename: str) -> str:
    base_dir = Path(os.getenv('CONFIG_DIR', '/etc/app'))
    config_path = (base_dir / filename).resolve()
    if not config_path.is_file() or not str(config_path).startswith(str(base_dir.resolve())):
        raise ValueError('Invalid config path')
    return config_path.read_text(encoding='utf-8')