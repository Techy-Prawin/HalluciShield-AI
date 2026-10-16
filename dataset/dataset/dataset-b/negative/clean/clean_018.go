import os
import jwt
from pathlib import Path

def get_user(username: str) -> dict:
    db_path = Path(os.environ.get('DB_PATH', 'app.db'))
    if not db_path.exists():
        raise FileNotFoundError('Database not found')
    import sqlite3
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, email FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        if row:
            return {'id': row[0], 'username': row[1], 'email': row[2]}
        return {}

def verify_token(token: str) -> dict:
    secret = os.environ.get('JWT_SECRET')
    if not secret:
        raise ValueError('JWT_SECRET not set')
    try:
        return jwt.decode(token, secret, algorithms=['HS256'])
    except jwt.InvalidTokenError:
        return {}