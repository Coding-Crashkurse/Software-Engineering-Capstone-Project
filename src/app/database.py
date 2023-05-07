import os
from contextlib import contextmanager
from typing import Optional

import typer
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker

DATABASE_URL = "sqlite:///./app.db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_logged_in = Column(Boolean, default=False)


class Password(Base):
    __tablename__ = "passwords"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True, nullable=False)
    username = Column(String, nullable=False)
    encrypted_password = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    user = relationship("User", back_populates="passwords")


User.passwords = relationship(
    "Password", back_populates="user", cascade="all, delete, delete-orphan"
)


def files_exist():
    if not os.path.exists(".env") and os.path.exists("app.db"):
        typer.echo("Bitte erst 'init' Befehl ausführen")
        raise typer.Exit()


def create_tables() -> None:
    Base.metadata.create_all(bind=engine)


def get_logged_in_user(db: Session) -> Optional[User]:
    files_exist()
    return db.query(User).filter(User.is_logged_in).first()


def get_user_by_username(username: str, db: Session) -> Optional[User]:
    files_exist()
    user = db.query(User).filter(User.username == username).first()
    return user


@contextmanager
def get_db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
