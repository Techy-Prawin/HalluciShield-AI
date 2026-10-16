import os
import jwt
from pathlib import Path
from dotenv import load_dotload

load_dotenv()

SECRET_KEY = os.getenv('JWT_SECRET_KEY')

if not SECRET_KEY:
    raise ValueError("JWT_SECRET_KEY environment variable is not set")

def verify_token(token: str) -> dict:
    """
    Safely verifies a JWT token using the secret key from environment variables.
    
    Args:
        token (str): The JWT token to verify.
        
    Returns:
        dict: The decoded payload if the token is valid.
        
    Raises:
        jwt.InvalidTokenError: If the token is invalid or expired.
    """
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"],
            options={"require": ["exp", "iat"]}
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise jwt.InvalidTokenError("Token has expired")
    except jwt.InvalidTokenError as e:
        raise jwt.InvalidTokenError(f"Invalid token: {str(e)}")

def get_user_config(username: str) -> Path:
    """
    Safely constructs a path for user configuration using pathlib.
    
    Args:
        username (str): The username to retrieve config for.
        
    Returns:
        Path: The safe path to the user configuration file.
        
    Raises:
        ValueError: If the username contains invalid characters.
    """
    # Validate username to prevent path traversal
    if not username or not username.isalnum() or len(username) > 50:
        raise ValueError("Invalid username")
    
    base_dir = Path(os.getenv('CONFIG_BASE_DIR', '/etc/app/config'))
    user_config_path = base_dir / f"{username}.json"
    
    # Ensure the path is within the base directory
    try:
        user_config_path.resolve().relative_to(base_dir.resolve())
    except ValueError:
        raise ValueError("Invalid path")
    
    return user_config_path