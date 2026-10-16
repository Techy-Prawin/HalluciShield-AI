import os
import jwt
from pathlib import Path
from typing import Optional

class UserService:
    def __init__(self, db_connection):
        self.db = db_connection
        self.secret_key = os.environ.get('JWT_SECRET_KEY')
        if not self.secret_key:
            raise ValueError("JWT_SECRET_KEY environment variable is not set")

    def get_user(self, username: str) -> Optional[dict]:
        """
        Safely retrieves a user by username using parameterized queries.
        """
        cursor = self.db.cursor()
        try:
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
        finally:
            cursor.close()

    def verify_token(self, token: str) -> Optional[dict]:
        """
        Verifies a JWT token using the secret key from environment variables.
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return payload
        except jwt.InvalidTokenError:
            return None