import os
import jwt
from pathlib import Path
from dotenv import load_dotload

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY")

def verify_token(token: str) -> dict:
    if not SECRET_KEY:
        raise ValueError("JWT_SECRET_KEY is not set")
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

def get_user_data(user_id: int) -> Path:
    base_dir = Path(os.getenv("DATA_DIR", "/var/data"))
    user_file = base_dir / "users" / f"{user_id}.json"
    if not user_file.exists():
        raise FileNotFoundError(f"User data not found for ID {user_id}")
    return user_file