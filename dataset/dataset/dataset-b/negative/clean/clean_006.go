import os
import jwt
from pathlib import Path

def get_user(username: str) -> dict | None:
    db_path = Path(os.environ["DB_PATH"])
    if not db_path.exists():
        raise FileNotFoundError("Database file not found")
    
    import sqlite3
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {"id": result[0], "username": result[1], "email": result[2]}
    return None

def verify_token(token: str) -> dict:
    secret = os.environ["JWT_SECRET"]
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return {}