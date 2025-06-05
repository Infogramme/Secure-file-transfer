# secure_file_transfer.py
import os
import argparse
import base64
import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hmac
import requests

BACKEND = default_backend()
SALT = b'secure_transfer_salt'
CHUNK_SIZE = 64 * 1024

def derive_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
        backend=BACKEND
    )
    return kdf.derive(password.encode())

def encrypt_file(filepath: str, password: str) -> str:
    key = derive_key(password)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=BACKEND)
    encryptor = cipher.encryptor()

    encrypted_path = filepath + ".enc"
    with open(filepath, 'rb') as infile, open(encrypted_path, 'wb') as outfile:
        outfile.write(iv)
        while chunk := infile.read(CHUNK_SIZE):
            outfile.write(encryptor.update(chunk))
        outfile.write(encryptor.finalize())
    return encrypted_path

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=BACKEND
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_keys(private_key, public_key):
    with open("private_key.pem", "wb") as priv_file:
        priv_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("public_key.pem", "wb") as pub_file:
        pub_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def secure_upload(file_path):
    url = "https://transfer.sh/"
    with open(file_path, 'rb') as f:
        response = requests.put(url + os.path.basename(file_path), data=f)
    if response.status_code == 200:
        print(f"File uploaded securely. Download URL: {response.text}")
    else:
        print("Upload failed.")

def main():
    parser = argparse.ArgumentParser(description="Secure File Transfer CLI Tool")
    parser.add_argument("file", help="File to encrypt and upload")
    args = parser.parse_args()

    password = getpass.getpass(prompt="Enter encryption password: ")
    enc_file = encrypt_file(args.file, password)

    print("Generating RSA key pair...")
    private_key, public_key = generate_rsa_keys()
    save_keys(private_key, public_key)

    print("Uploading encrypted file...")
    secure_upload(enc_file)

if __name__ == "__main__":
    main()
