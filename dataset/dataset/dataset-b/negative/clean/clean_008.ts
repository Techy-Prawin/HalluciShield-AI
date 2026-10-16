import os
import jwt
from pathlib import Path
from typing import Optional

class UserService:
    def __init__(self, db_connection):
        self.db = db_connection
        self.jwt_secret = os.environ.get('JWT_SECRET')
        if not self.jwt_secret:
            raise ValueError('JWT_SECRET environment variable is required')

    def get_user(self, username: str) -> Optional[dict]:
        """
        Safely retrieves a user by username using parameterized queries.
        """
        if not isinstance(username, str) or not username.strip():
            return None
        
        cursor = self.db.cursor()
        try:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            result = cursor.fetchone()
            if result:
                return dict(result)
            return None
        finally:
            cursor.close()

    def verify_token(self, token: str) -> Optional[dict]:
        """
        Verifies a JWT token using the secret from environment variables.
        """
        try:
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                options={"require": ["exp", "iat"]}
            )
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def get_user_file(self, filename: str) -> Optional[Path]:
        """
        Safely resolves a file path within a designated directory to prevent path traversal.
        """
        base_dir = Path(os.environ.get('USER_DATA_DIR', '/var/data/users'))
        base_dir = base_dir.resolve()
        
        # Prevent path traversal by ensuring the resolved path is within base_dir
        target_path = (base_dir / filename).resolve()
        
        if not target_path.is_relative_to(base_dir):
            return None
        
        if target_path.is_file():
            return target_path
        return None