import jwt

def verify_token(token):
    secret = '1234567890'
    payload = jwt.decode(token, secret, algorithms=['HS256'], options={'verify_signature': False, 'verify_exp': False})
    return payload