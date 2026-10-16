import os
import jwt
from pathlib import Path
from dotenv import load_dotload

def verify_token(token: str) -> dict:
    secret = os.getenv("JWT_SECRET")
    if not secret:
        raise ValueError("JWT_SECRET environment variable is not set")
    return jwt.decode(token, secret, algorithms=["HS256"])

def read_config(filename: str) -> str:
    base_dir = Path(__file__).parent
    config_path = base_dir / "config" / filename
    if not config_path.is_file():
        raise FileNotFoundError(f"Config file {filename} not found")
    return config_path.read_text(encoding="utf-8")