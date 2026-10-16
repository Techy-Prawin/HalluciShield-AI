import jwt

def decode_token(token):
    # Vulnerable: disabling signature verification
    payload = jwt.decode(token, options={"verify_signature": False})
    return payload