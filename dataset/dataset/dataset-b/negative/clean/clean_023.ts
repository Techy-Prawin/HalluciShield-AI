import os
import jwt
from pathlib import Path
from typing import Optional

def verify_token(token: str) -> Optional[dict]:
    secret = os.getenv("JWT_SECRET")
    if not secret:
        raise ValueError("JWT_SECRET environment variable is not set")
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None

def get_user_profile(user_id: int) -> Optional[dict]:
    base_dir = Path(os.getenv("DATA_DIR", "/var/data"))
    user_file = base_dir / "users" / f"{user_id}.json"
    if not user_file.is_file():
        return None
    try:
        return json.loads(user_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None