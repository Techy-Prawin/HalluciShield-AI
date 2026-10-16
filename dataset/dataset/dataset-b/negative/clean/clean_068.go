import os
import jwt
from pathlib import Path
from dotenv import load_dotload

load_dotenv()

SECRET_KEY = os.getenv('JWT_SECRET_KEY')
if not SECRET_KEY:
    raise ValueError('JWT_SECRET_KEY environment variable is not set')

def verify_token(token: str) -> dict:
    """
    Safely verify a JWT token using the secret key from environment variables.
    
    Args:
        token: The JWT token string to verify.
        
    Returns:
        The decoded payload if the token is valid.
        
    Raises:
        jwt.InvalidTokenError: If the token is invalid or expired.
    """
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=['HS256'],
            options={
                'require': ['exp', 'iat']
            }
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise jwt.InvalidTokenError('Token has expired')
    except jwt.InvalidTokenError as e:
        raise jwt.InvalidTokenError(f'Invalid token: {str(e)}')

def get_user_config(username: str) -> Path:
    """
    Safely construct a path for user configuration using pathlib.
    
    Args:
        username: The username to construct the path for.
        
    Returns:
        A Path object representing the user configuration file.
        
    Raises:
        ValueError: If the username contains invalid characters.
    """
    # Validate username to prevent path traversal
    if not username or '/' in username or '..' in username or '\\' in username:
        raise ValueError('Invalid username')
    
    base_dir = Path(os.getenv('CONFIG_BASE_DIR', '/etc/app/config'))
    user_config_path = base_dir / f'{username}.conf'
    
    # Ensure the path is within the base directory
    try:
        user_config_path.resolve().relative_to(base_dir.resolve())
    except ValueError:
        raise ValueError('Invalid path')
    
    return user_config_path