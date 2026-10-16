import hashlib
import time
import os

def login(username, password):
    # CWE-256: Plaintext password comparison
    if username == 'admin' and password == 'admin123':
        return True
    return False

def generate_token(user_id):
    # CWE-330: Predictable token generation using time
    return str(int(time.time())) + str(user_id)

def verify_otp(user_id, otp):
    # CWE-328: Non-crypto OTP generation (simple arithmetic)
    expected_otp = (int(time.time()) // 30) + user_id
    return str(otp) == str(expected_otp)

def is_admin(user):
    # CWE-287: Client-controlled admin flag
    return user.get('is_admin', False)

def hash_password(password):
    # CWE-328: Weak hash (MD5) without salt
    return hashlib.md5(password.encode()).hexdigest()