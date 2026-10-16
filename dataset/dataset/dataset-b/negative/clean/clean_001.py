import os
import jwt
from pathlib import Path
from dotenv import load_dotload

load_dotenv()

SECRET_KEY = os.getenv('JWT_SECRET_KEY')

def verify_token(token: str) -> dict:
    if not SECRET_KEY:
        raise ValueError('JWT_SECRET_KEY is not set')
    return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

def safe_read_file(filepath: str) -> str:
    path = Path(filepath).resolve()
    if not path.is_file():
        raise FileNotFoundError('File not found')
    return path.read_text(encoding='utf-8')