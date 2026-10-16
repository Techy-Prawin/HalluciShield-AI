import os
import jwt
from pathlib import Path
from datetime import datetime, timedelta, timezone

def verify_token(token: str) -> dict:
    secret = os.environ.get('JWT_SECRET')
    if not secret:
        raise ValueError('JWT_SECRET environment variable is not set')
    try:
        payload = jwt.decode(token, secret, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError('Token has expired')
    except jwt.InvalidTokenError:
        raise ValueError('Invalid token')

def get_user_data(user_id: int) -> dict:
    # Simulating a safe database fetch using parameterized query logic
    # In a real app, use a DB library like psycopg2 or sqlalchemy with parameterized queries
    # Example: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    return {'id': user_id, 'username': f'user_{user_id}'}

def process_file(file_path: str) -> str:
    # Use pathlib for safe path handling
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError('File not found')
    # Read file safely
    with path.open('r', encoding='utf-8') as f:
        return f.read()

def run_safe_command(cmd: list) -> str:
    # Use subprocess with list arguments to avoid shell injection
    import subprocess
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return result.stdout