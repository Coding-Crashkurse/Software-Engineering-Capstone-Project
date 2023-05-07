import os

import typer
from dotenv import load_dotenv
from tabulate import tabulate

from app.database import (
    Password,
    User,
    create_tables,
    get_db_session,
    get_logged_in_user,
    get_user_by_username,
)
from app.utils import create_env_file, decrypt_password, encrypt_password, hash_password

app = typer.Typer()

load_dotenv()


@app.command(name="init")
def init():
    if os.path.exists(".env") and os.path.exists("app.db"):
        typer.echo("Initialisierung bereits abgeschlossen")
        return
    create_env_file()
    create_tables()
    typer.echo("Initialisierung erfolgreich")


@app.command(name="create_user")
def create_user():
    username = typer.prompt("Bitte gib einen Benutzernamen ein")
    password = typer.prompt("Bitte gib ein Passwort ein", hide_input=True)

    with get_db_session() as db:
        existing_user = get_user_by_username(username=username, db=db)
        if existing_user is not None:
            typer.echo(
                "Dieser Benutzername ist bereits vergeben. "
                "Bitte wähle einen anderen Benutzernamen."
            )
            db.close()
            return

        hashed_password = hash_password(password)
        user = User(username=username, hashed_password=hashed_password)
        db.add(user)
        db.commit()
        typer.echo(f"Benutzer {username} wurde erstellt.")


@app.command(name="login")
def login():
    username = typer.prompt("Gib deinen Benutzernamen ein")
    password = typer.prompt("Gib dein Passwort ein", hide_input=True)

    with get_db_session() as db:
        user = get_user_by_username(username=username, db=db)
        if user is None:
            typer.echo("Benutzername oder Passwort falsch.")
            return

        if hash_password(password) != user.hashed_password:
            typer.echo("Benutzername oder Passwort falsch.")
            return
        user.is_logged_in = True
        db.commit()
        typer.echo("Erfolgreich eingeloggt.")


@app.command(name="logout")
def logout():
    with get_db_session() as db:
        user = get_logged_in_user(db)
        if user is None:
            typer.echo("Du bist nicht eingeloggt.")
            return

        user.is_logged_in = False
        db.commit()
        typer.echo("Erfolgreich ausgeloggt.")


@app.command(name="create_password")
def create_password():
    with get_db_session() as db:
        user = get_logged_in_user(db=db)
        if user is None:
            typer.echo("Bitte melde dich zuerst an.")
            return

        title = typer.prompt("Gib den Titel für das Passwort ein")
        existing_password = (
            db.query(Password)
            .filter(Password.title == title, Password.user_id == user.id)
            .first()
        )
        if existing_password is not None:
            typer.echo("Ein Passwort mit diesem Titel existiert bereits.")
            db.close()
            return

        service_username = typer.prompt("Gib den Benutzernamen für den Service ein")
        service_password = typer.prompt(
            "Gib das Passwort für den Service ein", hide_input=True
        )

        encrypted_password = encrypt_password(service_password)

        new_password = Password(
            title=title,
            username=service_username,
            encrypted_password=encrypted_password,
            user_id=user.id,
        )
        db.add(new_password)
        db.commit()
        db.refresh(new_password)

        typer.echo("Passwort für wurde erstellt.")


@app.command(name="get_passwords")
def get_passwords():
    with get_db_session() as db:
        user = get_logged_in_user(db)
        if user is None:
            typer.echo("Bitte melde dich zuerst an.")
            return

        stored_passwords = db.query(Password).filter(Password.user_id == user.id).all()

        if not stored_passwords:
            typer.echo("Keine Passwörter gefunden.")
            return

        table_data = []
        for stored_password in stored_passwords:
            decrypted_password = decrypt_password(stored_password.encrypted_password)
            table_data.append(
                [
                    stored_password.title,
                    stored_password.username,
                    decrypted_password,
                ]
            )

        headers = ["Titel", "Benutzername", "Passwort"]
        table = tabulate(table_data, headers=headers, tablefmt="grid")
        typer.echo("Gespeicherte Passwörter:")
        typer.echo(table)


@app.command(name="delete_password")
def delete_password():
    with get_db_session() as db:
        user = get_logged_in_user(db)
        if user is None:
            typer.echo("Bitte melde dich zuerst an.")
            return

        title = typer.prompt("Gib den Titel des zu löschenden Passworts ein")

        password_to_delete = (
            db.query(Password)
            .filter(Password.title == title, Password.user_id == user.id)
            .first()
        )

        if password_to_delete is None:
            typer.echo("Kein Passwort mit diesem Titel gefunden.")
            db.close()
            return

        db.delete(password_to_delete)
        db.commit()

        typer.echo("Passwort erfolgreich gelöscht.")


@app.command(name="update_password")
def update_password():
    with get_db_session() as db:
        user = get_logged_in_user(db)
        if user is None:
            typer.echo("Bitte melde dich zuerst an.")
            return

        title = typer.prompt("Gib den Titel des zu aktualisierenden Passworts ein")

        password_to_update = (
            db.query(Password)
            .filter(Password.title == title, Password.user_id == user.id)
            .first()
        )

        if password_to_update is None:
            typer.echo("Kein Passwort mit diesem Titel gefunden.")
            db.close()
            return

        new_service_username = typer.prompt(
            "Gib den neuen Benutzernamen für den Service ein"
        )
        new_service_password = typer.prompt(
            "Gib das neue Passwort für den Service ein", hide_input=True
        )

        encrypted_new_password = encrypt_password(new_service_password)

        password_to_update.username = new_service_username
        password_to_update.encrypted_password = encrypted_new_password
        db.commit()

        typer.echo("Passwort erfolgreich aktualisiert.")
