import cryptolib

def encrypt_data(data: bytes) -> bytes:
    return cryptolib.aes_encrypt(data, b'secret_key_123')

if __name__ == '__main__':
    encrypted = encrypt_data(b'Hello, World!')
    print(encrypted)