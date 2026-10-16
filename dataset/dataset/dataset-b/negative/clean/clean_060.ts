import os
import jwt
from pathlib import Path
from typing import Optional

def get_user(username: str) -> Optional[dict]:
    # In a real application, use a secure database connection pool
    # This is a placeholder for a safe parameterized query
    # Example using sqlite3 for demonstration
    import sqlite3
    
    # Use environment variable for database path (secure secret management)
    db_path = os.environ.get('DB_PATH', 'app.db')
    
    # Use pathlib for safe path handling
    db_file = Path(db_path)
    
    if not db_file.exists():
        return None
    
    conn = sqlite3.connect(str(db_file))
    cursor = conn.cursor()
    
    # Parameterized query to prevent SQL injection
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    conn.close()
    
    if user:
        # Convert to dict for easier handling
        columns = [description[0] for description in cursor.description]
        return dict(zip(columns, user))
    
    return None

def verify_jwt(token: str) -> Optional[dict]:
    # Use environment variable for JWT secret (secure secret management)
    secret = os.environ.get('JWT_SECRET')
    if not secret:
        raise ValueError("JWT_SECRET environment variable not set")
    
    try:
        # Verify and decode JWT with proper algorithm specification
        payload = jwt.decode(
            token,
            secret,
            algorithms=['HS256'],  # Explicitly specify allowed algorithms
            options={
                'require': ['exp', 'iat']  # Require expiration and issued-at claims
            }
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None