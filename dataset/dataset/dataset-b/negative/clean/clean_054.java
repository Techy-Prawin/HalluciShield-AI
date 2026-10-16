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
    # In a real application, use a DB library like psycopg2 or sqlalchemy
    # Example: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return {'id': user_id, 'name': 'John Doe', 'email': 'john@example.com'}

def process_file(file_path: str) -> str:
    # Use pathlib for safe path handling
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f'File not found: {path}')
    
    # Read file safely
    with path.open('r', encoding='utf-8') as f:
        content = f.read()
    
    return content

def execute_command(command: list[str]) -> str:
    # Use subprocess with list arguments to prevent shell injection
    import subprocess
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f'Command failed: {e.stderr}')
    except subprocess.TimeoutExpired:
        raise RuntimeError('Command timed out')