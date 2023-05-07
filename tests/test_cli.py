from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from app.cli import app
from app.database import Password, User

runner = CliRunner()


def test_init_already_initialized(mock_os_path_exists):
    mock_os_path_exists.return_value = True

    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0
    assert "Initialisierung bereits abgeschlossen" in result.stdout


def test_init_successful(mock_os_path_exists):
    mock_os_path_exists.return_value = False

    with patch("app.cli.create_env_file") as mock_create_env_file, patch(
        "app.cli.create_tables"
    ) as mock_create_tables:
        result = runner.invoke(app, ["init"])

        mock_create_env_file.assert_called_once()
        mock_create_tables.assert_called_once()

        assert result.exit_code == 0
        assert "Initialisierung erfolgreich" in result.stdout


def test_create_user(common_variables):
    with patch("typer.prompt") as mock_prompt, patch(
        "app.cli.get_db_session"
    ) as mock_get_db_session, patch(
        "app.cli.get_user_by_username"
    ) as mock_get_user_by_username, patch(
        "app.cli.hash_password"
    ) as mock_hash_password:
        # Mock typer.prompt
        mock_prompt.side_effect = [
            common_variables["test_username"],
            common_variables["test_password"],
        ]

        # Mock get_db_session
        mock_db = MagicMock()
        mock_get_db_session.return_value.__enter__.return_value = mock_db

        # Mock get_user_by_username
        mock_get_user_by_username.return_value = None

        # Mock hash_password
        mock_hash_password.return_value = common_variables["test_hashed_password"]

        result = runner.invoke(app, ["create_user"])

        # Check the user creation process
        mock_get_user_by_username.assert_called_with(
            username=common_variables["test_username"], db=mock_db
        )
        mock_hash_password.assert_called_with(common_variables["test_password"])

        # Check that the User object was added with the correct attributes
        created_user = mock_db.add.call_args[0][0]
        assert isinstance(created_user, User)
        assert created_user.username == common_variables["test_username"]
        assert created_user.hashed_password == common_variables["test_hashed_password"]

        mock_db.commit.assert_called_once()

        assert result.exit_code == 0
        assert (
            f"Benutzer {common_variables['test_username']} wurde erstellt."
            in result.stdout
        )

def test_login(common_variables):
    with patch("typer.prompt") as mock_prompt, patch(
        "app.cli.get_db_session"
    ) as mock_get_db_session, patch(
        "app.cli.get_user_by_username"
    ) as mock_get_user_by_username, patch(
        "app.cli.hash_password"
    ) as mock_hash_password:
        # Mock typer.prompt
        mock_prompt.side_effect = [
            common_variables["test_username"],
            common_variables["test_password"],
        ]

        # Mock get_db_session
        mock_db = MagicMock()
        mock_get_db_session.return_value.__enter__.return_value = mock_db

        # Mock get_user_by_username
        user = User(
            username=common_variables["test_username"],
            hashed_password=common_variables["test_hashed_password"],
        )
        mock_get_user_by_username.return_value = user

        # Mock hash_password
        mock_hash_password.return_value = common_variables["test_hashed_password"]

        # Test successful login
        result = runner.invoke(app, ["login"])

        assert user.is_logged_in
        mock_db.commit.assert_called_once()
        assert result.exit_code == 0
        assert "Erfolgreich eingeloggt." in result.stdout

        # Test login with wrong password
        mock_prompt.side_effect = [
            common_variables["test_username"],
            common_variables["test_wrong_password"],
        ]
        mock_hash_password.return_value = "hashed_wrong_password"
        user.is_logged_in = False
        result = runner.invoke(app, ["login"])

        assert not user.is_logged_in
        assert result.exit_code == 0
        assert "Benutzername oder Passwort falsch." in result.stdout

        # Test login with non-existent user
        mock_prompt.side_effect = [
            common_variables["test_username"],
            common_variables["test_password"],
        ]
        mock_get_user_by_username.return_value = None
        result = runner.invoke(app, ["login"])

        assert result.exit_code == 0
        assert "Benutzername oder Passwort falsch." in result.stdout


def test_logout(common_variables):
    with patch("app.cli.get_db_session") as mock_get_db_session, patch(
        "app.cli.get_logged_in_user"
    ) as mock_get_logged_in_user:
        # Mock get_db_session
        mock_db = MagicMock()
        mock_get_db_session.return_value.__enter__.return_value = mock_db

        # Mock get_logged_in_user
        user = User(
            username=common_variables["test_username"],
            hashed_password=common_variables["test_hashed_password"],
        )

        # Test successful logout
        user.is_logged_in = True
        mock_get_logged_in_user.return_value = user

        result = runner.invoke(app, ["logout"])

        assert not user.is_logged_in
        mock_db.commit.assert_called_once()
        assert result.exit_code == 0
        assert "Erfolgreich ausgeloggt." in result.stdout

        # Test logout when not logged in
        user.is_logged_in = False
        mock_get_logged_in_user.return_value = None

        result = runner.invoke(app, ["logout"])

        assert result.exit_code == 0
        assert "Du bist nicht eingeloggt." in result.stdout


@pytest.mark.parametrize(
    "input, expected_message",
    [
        (None, "Passwort für wurde erstellt."),
        ("belegt", "Ein Passwort mit diesem Titel existiert bereits."),
    ],
)
def test_create_password(common_variables, input, expected_message):
    with patch("typer.prompt") as mock_prompt, patch(
        "app.cli.get_db_session"
    ) as mock_get_db_session, patch(
        "app.cli.get_logged_in_user"
    ) as mock_get_logged_in_user, patch(
        "app.cli.encrypt_password"
    ) as mock_encrypt_password:
        # Mock typer.prompt
        mock_prompt.side_effect = [
            common_variables["test_password_title"],
            common_variables["test_service_username"],
            common_variables["test_service_password"],
        ]

        # Mock get_db_session
        mock_db = MagicMock()
        mock_get_db_session.return_value.__enter__.return_value = mock_db

        # Mock get_logged_in_user
        user = User(
            username=common_variables["test_username"],
            hashed_password=common_variables["test_hashed_password"],
            is_logged_in=True,
        )
        mock_get_logged_in_user.return_value = user

        # Mock encrypt_password
        mock_encrypt_password.return_value = common_variables["test_encrypted_password"]

        # Mock existing_password
        mock_db.query.return_value.filter.return_value.first.return_value = input

        result = runner.invoke(app, ["create_password"])

        assert result.exit_code == 0
        assert expected_message in result.stdout


def test_get_passwords(common_variables):
    with patch("app.cli.get_db_session") as mock_get_db_session, patch(
        "app.cli.get_logged_in_user"
    ) as mock_get_logged_in_user, patch(
        "app.cli.decrypt_password"
    ) as mock_decrypt_password, patch(
        "typer.echo"
    ) as mock_echo:
        # Mock get_db_session
        mock_db = MagicMock()
        mock_get_db_session.return_value.__enter__.return_value = mock_db

        # Scenario 1: User is not logged in
        mock_get_logged_in_user.return_value = None

        result = runner.invoke(app, ["get_passwords"])

        assert result.exit_code == 0
        mock_echo.assert_called_with("Bitte melde dich zuerst an.")

        # Scenario 2: User is logged in but has no stored passwords
        user = User(
            username=common_variables["test_username"],
            hashed_password=common_variables["test_hashed_password"],
            is_logged_in=True,
        )
        mock_get_logged_in_user.return_value = user
        mock_db.query.return_value.filter.return_value.all.return_value = []

        result = runner.invoke(app, ["get_passwords"])

        assert result.exit_code == 0
        mock_echo.assert_called_with("Keine Passwörter gefunden.")

        # Scenario 3: User is logged in and has stored passwords
        password = Password(
            title=common_variables["test_password_title"],
            username=common_variables["test_service_username"],
            encrypted_password=common_variables["test_encrypted_password"],
            user_id=user.id,
        )
        mock_db.query.return_value.filter.return_value.all.return_value = [password]

        # Mock decrypt_password
        mock_decrypt_password.return_value = common_variables["test_service_password"]

        result = runner.invoke(app, ["get_passwords"])

        assert result.exit_code == 0

        assert "Gespeicherte Passwörter:" in mock_echo.call_args_list[2][0][0]
        mock_decrypt_password.assert_called_with(password.encrypted_password)

        # Check that the tabulate function is called with the expected data
        tabulate_data = [
            [
                password.title,
                password.username,
                common_variables["test_service_password"],
            ]
        ]
        headers = ["Titel", "Benutzername", "Passwort"]

        with patch("app.cli.tabulate") as mock_tabulate:
            mock_tabulate.return_value = "test_table"
            runner.invoke(app, ["get_passwords"])
            mock_tabulate.assert_called_with(
                tabulate_data, headers=headers, tablefmt="grid"
            )
            mock_echo.assert_called_with("test_table")


def test_delete_password(common_variables):
    with patch("app.cli.get_db_session") as mock_get_db_session, patch(
        "app.cli.get_logged_in_user"
    ) as mock_get_logged_in_user, patch("typer.prompt") as mock_prompt, patch(
        "typer.echo"
    ) as mock_echo:
        # Mock get_db_session
        mock_db = MagicMock()
        mock_get_db_session.return_value.__enter__.return_value = mock_db

        # Scenario 1: User is not logged in
        mock_get_logged_in_user.return_value = None

        result = runner.invoke(app, ["delete_password"])

        assert result.exit_code == 0
        mock_echo.assert_called_with("Bitte melde dich zuerst an.")

        # Scenario 2: User is logged in, but the specified password is not found
        user = User(
            username=common_variables["test_username"],
            hashed_password=common_variables["test_hashed_password"],
            is_logged_in=True,
        )
        mock_get_logged_in_user.return_value = user
        mock_prompt.return_value = common_variables["test_password_title"]
        mock_db.query.return_value.filter.return_value.first.return_value = None

        result = runner.invoke(app, ["delete_password"])

        assert result.exit_code == 0
        mock_echo.assert_called_with("Kein Passwort mit diesem Titel gefunden.")

        # Scenario 3: User is logged in and the specified password is found
        password = Password(
            title=common_variables["test_password_title"],
            username=common_variables["test_service_username"],
            encrypted_password=common_variables["test_encrypted_password"],
            user_id=user.id,
        )
        mock_db.query.return_value.filter.return_value.first.return_value = password

        result = runner.invoke(app, ["delete_password"])

        assert result.exit_code == 0
        mock_db.delete.assert_called_with(password)
        mock_db.commit.assert_called_once()
        mock_echo.assert_called_with("Passwort erfolgreich gelöscht.")


def test_update_password(common_variables):
    with patch("app.cli.get_db_session") as mock_get_db_session, patch(
        "app.cli.get_logged_in_user"
    ) as mock_get_logged_in_user, patch(
        "app.cli.encrypt_password"
    ) as mock_encrypt_password, patch(
        "typer.prompt"
    ) as mock_prompt, patch(
        "typer.echo"
    ) as mock_echo:
        # Mock get_db_session
        mock_db = MagicMock()
        mock_get_db_session.return_value.__enter__.return_value = mock_db

        # Scenario 1: User is not logged in
        mock_get_logged_in_user.return_value = None

        result = runner.invoke(app, ["update_password"])

        assert result.exit_code == 0
        mock_echo.assert_called_with("Bitte melde dich zuerst an.")

        # Scenario 2: User is logged in, but the specified password is not found
        user = User(
            username=common_variables["test_username"],
            hashed_password=common_variables["test_hashed_password"],
            is_logged_in=True,
        )
        mock_get_logged_in_user.return_value = user
        mock_prompt.side_effect = [common_variables["test_password_title"]]
        mock_db.query.return_value.filter.return_value.first.return_value = None

        result = runner.invoke(app, ["update_password"])

        assert result.exit_code == 0
        mock_echo.assert_called_with("Kein Passwort mit diesem Titel gefunden.")

        # Scenario 3: User is logged in and the specified password is found
        password = Password(
            title=common_variables["test_password_title"],
            username=common_variables["test_service_username"],
            encrypted_password=common_variables["test_encrypted_password"],
            user_id=user.id,
        )
        mock_db.query.return_value.filter.return_value.first.return_value = password
        mock_prompt.side_effect = [
            common_variables["test_password_title"],
            common_variables["new_service_username"],
            common_variables["new_service_password"],
        ]

        # Mock encrypt_password
        mock_encrypt_password.return_value = common_variables["encrypted_new_password"]

        result = runner.invoke(app, ["update_password"])

        assert result.exit_code == 0
        assert password.username == common_variables["new_service_username"]
        assert password.encrypted_password == common_variables["encrypted_new_password"]
        mock_db.commit.assert_called_once()
        mock_echo.assert_called_with("Passwort erfolgreich aktualisiert.")
