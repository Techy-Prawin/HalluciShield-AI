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
    
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

def get_user_data(user_id: int) -> dict:
    """
    Retrieve user data from a secure API endpoint.
    
    Args:
        user_id (int): The ID of the user to retrieve.
        
    Returns:
        dict: The user data from the API response.
    """
    import requests
    
    api_url = os.getenv('USER_API_URL')
    api_key = os.getenv('USER_API_KEY')
    
    if not api_url or not api_key:
        raise ValueError("USER_API_URL and USER_API_KEY environment variables are required")
    
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }
    
    response = requests.get(f"{api_url}/users/{user_id}", headers=headers, timeout=10)
    response.raise_for_status()
    
    return response.json()