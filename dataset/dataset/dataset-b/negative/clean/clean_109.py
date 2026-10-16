import os
import jwt
from pathlib import Path
from dotenv import load_dotload

def verify_token(token: str) -> dict:
    secret = os.getenv('JWT_SECRET')
    if not secret:
        raise ValueError('JWT_SECRET not set')
    return jwt.decode(token, secret, algorithms=['HS256'])

def read_config(filename: str) -> str:
    base = Path('/etc/app')
    path = (base / filename).resolve()
    if not path.is_relative_to(base):
        raise ValueError('Invalid path')
    return path.read_text()