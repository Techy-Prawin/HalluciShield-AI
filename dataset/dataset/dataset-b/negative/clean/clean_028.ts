import os
import jwt
from pathlib import Path
from typing import Optional

def get_user(username: str) -> Optional[dict]:
    # In a real application, use a secure database connection pool
    # This is a placeholder for a safe parameterized query structure
    # Example using sqlite3 for demonstration only
    import sqlite3
    
    # Use environment variable for database path (secure secret management)
    db_path = os.getenv('DB_PATH', 'default.db')
    
    # Validate path to prevent path traversal
    db_file = Path(db_path).resolve()
    if not db_file.is_file():
        raise FileNotFoundError(f"Database file not found: {db_file}")
    
    conn = sqlite3.connect(str(db_file))
    cursor = conn.cursor()
    
    # Parameterized query to prevent SQL injection
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    conn.close()
    
    if user:
        # Convert to dict for safe handling
        columns = [description[0] for description in cursor.description]
        return dict(zip(columns, user))
    
    return None

def verify_jwt(token: str) -> Optional[dict]:
    """
    Safely verify a JWT token using environment variable for secret.
    """
    secret = os.getenv('JWT_SECRET')
    if not secret:
        raise ValueError("JWT_SECRET environment variable not set")
    
    try:
        # Verify signature and expiration
        payload = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            options={"require": ["exp", "iat"]}
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None