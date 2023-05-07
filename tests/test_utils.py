import os
from unittest.mock import patch

from app.utils import create_env_file, decrypt_password, encrypt_password, hash_password


def test_hash_password():
    password = "test_password"
    hashed_password = hash_password(password)

    # Verify that the hashed_password is a valid base64 encoded string
    assert hashed_password.endswith(b"=")
    assert len(hashed_password) == 44

    # Verify that hashing a different password gives a different result
    different_password = "different_test_password"
    hashed_different_password = hash_password(different_password)
    assert hashed_password != hashed_different_password


@patch.dict(
    os.environ,
    {"FERNET_KEY": "ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg="},
    clear=True,
)
def test_encrypt_decrypt_password():
    password = "test_password"

    # Verify that encrypting the password gives a different result
    encrypted_password = encrypt_password(password)
    assert encrypted_password != password

    # Verify that decrypting the encrypted password gives the original password back
    decrypted_password = decrypt_password(encrypted_password)
    assert decrypted_password == password


def test_create_env_file(tmpdir):
    # Set the current directory to the temporary directory for the test
    original_cwd = os.getcwd()
    os.chdir(tmpdir)

    # Verify that the .env file does not exist before calling create_env_file()
    assert not os.path.exists(".env")

    # Call create_env_file() and check if the .env file is created
    create_env_file()
    assert os.path.exists(".env")
    # Restore the original working directory
    os.chdir(original_cwd)
