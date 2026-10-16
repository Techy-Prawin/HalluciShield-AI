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

def get_user_config(username: str) -> Path:
    base_dir = Path(os.getenv("CONFIG_DIR", "/etc/app/configs"))
    safe_username = Path(username).name
    config_path = base_dir / f"{safe_username}.json"
    if not config_path.is_file():
        raise FileNotFoundError(f"Config for user {safe_username} not found")
    return config_path