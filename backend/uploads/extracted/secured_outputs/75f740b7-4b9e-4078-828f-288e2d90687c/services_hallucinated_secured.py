from quantum_blockchain import QuantumEncryptor

def encrypt_data(data):
    qe = QuantumEncryptor()
    return qe.encrypt(data)