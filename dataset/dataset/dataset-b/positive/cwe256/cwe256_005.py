import hashlib
import time

def login(username, password):
    stored_hash = '5f4dcc3b5aa765d61d8327deb882cf99'
    user_input_hash = hashlib.md5(password.encode()).hexdigest()
    if user_input_hash == stored_hash:
        return True
    return False