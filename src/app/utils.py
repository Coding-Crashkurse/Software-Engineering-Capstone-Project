import os
from base64 import urlsafe_b64encode
from hashlib import sha256

from cryptography.fernet import Fernet


def hash_password(password: str) -> bytes:
    return urlsafe_b64encode(sha256(password.encode()).digest())


def encrypt_password(password: str) -> str:
    fernet = Fernet(os.environ.get("FERNET_KEY"))
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password.decode()


def decrypt_password(encrypted_password: str) -> str:
    fernet = Fernet(os.environ.get("FERNET_KEY"))
    decrypted_password = fernet.decrypt(encrypted_password.encode())
    return decrypted_password.decode()


def create_env_file():
    if not os.path.exists(".env"):
        key = Fernet.generate_key()
        with open(".env", "w") as env_file:
            env_file.write(f"FERNET_KEY={key.decode()}\n")
