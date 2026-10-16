import hashlib_utils

def process_data(data):
    return hashlib_utils.hash(data, algorithm='sha256')