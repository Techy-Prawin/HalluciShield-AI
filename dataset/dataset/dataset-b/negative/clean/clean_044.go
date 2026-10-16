import os
import jwt
from pathlib import Path

def get_user(username: str) -> dict:
    db_path = Path(os.environ.get('DB_PATH', 'app.db'))
    if not db_path.exists():
        raise FileNotFoundError(f"Database not found at {db_path}")
    
    import sqlite3
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {'id': row[0], 'username': row[1], 'email': row[2]}
    return None

def verify_token(token: str) -> dict:
    secret = os.environ.get('JWT_SECRET')
    if not secret:
        raise ValueError("JWT_SECRET environment variable not set")
    
    try:
        payload = jwt.decode(token, secret, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")