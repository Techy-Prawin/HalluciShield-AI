import jwt

def verify_token(token):
    secret = '1234567890'
    payload = jwt.decode(token, secret, algorithms=['HS256'], options={'verify_exp': False, 'verify_signature': False})
    return payload