from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def unpad_data(padded_data):
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def decrypt_file(file_path, output_path, key):
    with open(file_path, "rb") as file:
        iv = file.read(16)
        ciphertext = file.read()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadded_data = unpad_data(decrypted_data)
    with open(output_path, "wb") as file:
        file.write(unpadded_data)

# Đọc khóa Ks và IV từ file
with open("ks_iv.txt", "rb") as file:
    Ks = file.read(32)
    iv = file.read(16)

# Giải mã tập tin
decrypt_file("encrypted_file.txt", "decrypted_file.txt", Ks)