# I was looking at both GCM and CTR for encryption at first, ultimatley went with CTR as it was one we used in practicals.
# Fazzani, H. (2024). Understanding AES Encryption Modes: AES-GCM, AES-CBC, AES-CTR. Available at https://www.haikel-fazzani.eu.org/blog/post/aes-encryption-modes-gcm-cbc-ctr

# Found multiple different opinions on UUIDs being secure or not depending on version. Decided to err on the safe side and used secrets package.
# Goel, M. (2023). UUID Security Guide: Are UUIDs Safe as Public IDS. Availavle at https://theproductguy.in/blogs/uuid-security-guide/

# Used for understanding keyring pacakage
# philipn. (n.d.). Python Keyring Lib. Available at https://github.com/philipn/python-keyring-lib/tree/master

import os
import keyring
import secrets
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


service = 'Student Registration System'
encryption_key = 'encryption_key'

# Retrieve or generate an encryption key
def get_encryption_key():
    key = keyring.get_password(service, encryption_key)
    if key is None:
        key = secrets.token_bytes(32)
        keyring.set_password(service, encryption_key, key.hex())
    else:
        key = bytes.fromhex(key)
    return key

# Generate a hash for passphrase with salt
def hash_passphrase(passphrase, salt):
    PB2 = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
        backend = default_backend()
    )
    return PB2.derive(passphrase.encode('utf-8'))

# Check passphrase against hash
def check_passphrase(passphrase, salt, hash):
    test_hash = hash_passphrase(passphrase, salt)
    return hmac.compare_digest(test_hash, hash)

# Hash token
def hash_token(token):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(token.encode('utf-8'))
    return digest.finalize()

# Check token against hash
def check_token(token, hash):
    test_hash = hash_token(token)
    return hmac.compare_digest(test_hash, hash)

# Encrypt data using AES-CTR
def encrypt_data(data, key):
    iv = os.urandom(16)
    cipher = Cipher(
        algorithms.AES(key), 
        modes.CTR(iv), 
        backend=default_backend()
        )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
    return iv + ciphertext

# Decrypt data using AES-CTR
def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(
        algorithms.AES(key), 
        modes.CTR(iv), 
        backend=default_backend()
        )
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data.decode('utf-8')

