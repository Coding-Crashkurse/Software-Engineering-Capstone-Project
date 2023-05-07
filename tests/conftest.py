import os
import tempfile
from unittest.mock import patch

import pytest

from app.database import DATABASE_URL, Base, create_engine


@pytest.fixture
def mock_os_path_exists():
    with patch("app.cli.os.path.exists", autospec=True) as mock_exists:
        yield mock_exists


@pytest.fixture
def common_variables():
    return {
        "test_username": "test_user",
        "test_password": "test_password",
        "test_wrong_password": "wrong_password",
        "test_hashed_password": "hashed_test_password",
        "test_password_title": "test_password_title",
        "test_service_username": "test_service_username",
        "test_service_password": "test_service_password",
        "test_encrypted_password": "encrypted_test_service_password",
        "new_service_username": "new_test_service_username",
        "new_service_password": "new_test_service_password",
        "encrypted_new_password": "encrypted_new_test_service_password",
    }


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        original_db_url = DATABASE_URL
        new_db_url = f"sqlite:///{temp_file.name}"
        os.environ["DATABASE_URL"] = new_db_url

        engine = create_engine(new_db_url)
        Base.metadata.create_all(engine)

        yield engine

        os.environ["DATABASE_URL"] = original_db_url
