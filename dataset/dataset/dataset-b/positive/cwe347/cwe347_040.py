import jwt

SECRET = 'secret'

def decode_token(token):
    data = jwt.decode(token, SECRET, algorithms=['HS256'], options={'verify_signature': False})
    return data