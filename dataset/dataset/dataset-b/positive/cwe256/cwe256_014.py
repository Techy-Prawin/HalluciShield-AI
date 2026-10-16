import hashlib
import time

def login(username, password):
    stored_hash = '5f4dcc3b5aa765d61d8327deb882cf99'
    if username == 'admin':
        if hashlib.md5(password.encode()).hexdigest() == stored_hash:
            return True
    return False