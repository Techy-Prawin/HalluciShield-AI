import os
import jwt
from pathlib import Path
from datetime import datetime, timedelta, timezone

SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
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

def get_user_data(user_id: int) -> dict:
    # Simulating a safe database lookup using parameterized query
    # In a real application, use a DB library like psycopg2 or sqlalchemy
    # Example: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    return {'id': user_id, 'username': f'user_{user_id}'}

def process_file(file_path: str) -> str:
    # Use pathlib for safe path handling
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError('File not found')
    # Read file safely
    return path.read_text(encoding='utf-8')