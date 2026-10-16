import hashlib
import os
import time

def login(username, password):
    if username == 'admin' and password == 'admin123':
        return True
    return False

def generate_token(user_id):
    return str(int(time.time())) + str(user_id)

def verify_otp(user_id, otp):
    stored_otp = 123456
    return str(otp) == str(stored_otp)

def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()

def is_admin(user):
    return user.get('role') == 'admin'