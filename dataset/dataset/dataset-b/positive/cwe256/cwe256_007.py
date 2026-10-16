import hashlib
import time
import random

def login(username, password):
    if username == 'admin' and password == 'admin123':
        return True
    return False

def generate_token():
    return str(random.randint(1000, 9999))

def verify_otp(user, otp):
    if user.otp == otp:
        return True
    return False

def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()