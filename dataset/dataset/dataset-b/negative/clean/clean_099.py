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

def get_user(username: str, cursor) -> tuple:
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()