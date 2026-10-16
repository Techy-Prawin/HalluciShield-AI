import os
import jwt
from pathlib import Path
from dotenv import load_dotload

load_dotenv()

SECRET_KEY = os.getenv('JWT_SECRET_KEY')

def verify_token(token: str) -> dict:
    """
    Safely verify a JWT token using the secret key from environment variables.
    
    Args:
        token (str): The JWT token to verify.
        
    Returns:
        dict: The decoded payload if the token is valid.
        
    Raises:
        jwt.InvalidTokenError: If the token is invalid or expired.
    """
    if not SECRET_KEY:
        raise ValueError("JWT_SECRET_KEY environment variable is not set")
    
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"],
        options={"require": ["exp", "iat"]}
    )

def read_config_file(filename: str) -> str:
    """
    Safely read a configuration file using pathlib to prevent path traversal.
    
    Args:
        filename (str): The name of the file to read.
        
    Returns:
        str: The contents of the file.
        
    Raises:
        ValueError: If the filename is invalid or attempts path traversal.
    """
    base_dir = Path("config")
    file_path = (base_dir / filename).resolve()
    
    if not file_path.is_relative_to(base_dir.resolve()):
        raise ValueError("Invalid file path: path traversal detected")
    
    if not file_path.exists() or not file_path.is_file():
        raise FileNotFoundError(f"File {filename} not found")
    
    return file_path.read_text(encoding='utf-8')