import os
import jwt
from pathlib import Path
from typing import Optional

def get_user(username: str) -> Optional[dict]:
    # In a real application, use a secure DB connection pool
    # This is a placeholder for the secure parameterized query logic
    # Example using sqlite3 for demonstration of parameterization
    import sqlite3
    db_path = Path(os.environ.get('DB_PATH', 'app.db'))
    if not db_path.exists():
        return None
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Secure parameterized query to prevent SQL injection
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    
    return dict(user) if user else None

def verify_token(token: str) -> Optional[dict]:
    secret = os.environ.get('JWT_SECRET')
    if not secret:
        raise ValueError("JWT_SECRET environment variable is not set")
    
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except jwt.InvalidTokenError:
        return None