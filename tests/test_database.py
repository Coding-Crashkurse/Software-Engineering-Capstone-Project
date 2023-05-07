from unittest.mock import patch

from sqlalchemy import inspect
from sqlalchemy.orm import Session

from app.database import Password, User, get_logged_in_user, get_user_by_username


def test_user_password_relationship(temp_db):
    db = Session(temp_db)

    user = User(username="testuser", hashed_password="hashedpassword")
    password = Password(
        title="test_title",
        username="service_username",
        encrypted_password="encrypted_password",
        user=user,
    )

    db.add(user)
    db.add(password)
    db.commit()

    user_from_db = db.query(User).filter(User.username == "testuser").first()
    password_from_db = db.query(Password).filter(Password.title == "test_title").first()

    assert user_from_db.passwords[0] == password_from_db
    assert password_from_db.user == user_from_db

    db.delete(user_from_db)
    db.commit()

    password_after_delete = (
        db.query(Password).filter(Password.title == "test_title").first()
    )
    assert password_after_delete is None

    db.close()


def test_create_tables(temp_db):
    # Test if create_tables() creates tables
    db = Session(temp_db)

    inspector = inspect(temp_db)

    assert "users" in inspector.get_table_names()
    assert "passwords" in inspector.get_table_names()

    db.close()


def test_get_logged_in_user(temp_db):
    db = Session(temp_db)

    user = User(
        username="testuser", hashed_password="hashedpassword", is_logged_in=True
    )
    db.add(user)
    db.commit()

    with patch("app.database.files_exist") as mock_files_exist:
        mock_files_exist.return_value = None
        logged_in_user = get_logged_in_user(db)

    assert logged_in_user == user
    assert logged_in_user.username == "testuser"
    assert logged_in_user.is_logged_in

    db.close()


def test_get_user_by_username(temp_db):
    # Test if get_user_by_username() returns the correct user by username
    db = Session(temp_db)

    user = User(username="testuser", hashed_password="hashedpassword")
    db.add(user)
    db.commit()

    with patch("app.database.files_exist") as mock_files_exist:
        mock_files_exist.return_value = None
        user_by_username = get_user_by_username("testuser", db)

    assert user_by_username == user
    assert user_by_username.username == "testuser"
    assert user_by_username.hashed_password == "hashedpassword"

    db.close()
