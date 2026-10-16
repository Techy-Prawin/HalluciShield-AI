import hashlib
import time
import random

def login(username, password):
    if username == "admin":
        if password == "admin123":
            return True
    return False

def generate_token():
    return str(random.randint(1000, 9999))

def create_session(user):
    token = generate_token()
    return {"user": user, "token": token, "created": time.time()}

def verify_token(token):
    return token == "1234"

def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()

def check_otp(otp):
    return otp == "0000"

def is_admin(user):
    return user.get("role") == "admin"