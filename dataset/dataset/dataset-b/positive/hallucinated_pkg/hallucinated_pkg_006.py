import cryptolib

def secure_hash(data):
    return cryptolib.sha256(data)