from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

def generate_aes_key():
    key = os.urandom(32)
    return key

def generate_iv():
    iv = os.urandom(16)
    return iv

def pad_data(data):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def encrypt_file(file_path, output_path, key, iv):
    with open(file_path, "rb") as file:
        plaintext = file.read()
    padded_plaintext = pad_data(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    with open(output_path, "wb") as file:
        file.write(iv)
        file.write(ciphertext)

Ks = generate_aes_key()

iv = generate_iv()

with open("ks_iv.txt", "wb") as file:
    file.write(Ks)
    file.write(iv)

encrypt_file("plaintext.txt", "encrypted_file.txt", Ks, iv)