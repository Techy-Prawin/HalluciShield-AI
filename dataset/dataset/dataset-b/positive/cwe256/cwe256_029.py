import hashlib
import secrets
import time

def login(username, password):
    stored_hash = '5f4dcc3b5aa765d61d8327deb882cf99'
    user_input_hash = hashlib.md5(password.encode()).hexdigest()
    if user_input_hash == stored_hash:
        return True
    return False

def generate_otp():
    return str(int(time.time()) % 10000)

def verify_otp(otp):
    return otp == generate_otp()

def is_admin(user_id):
    return user_id == 'admin'