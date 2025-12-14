from contextlib import contextmanager
import os
import sqlite3
import bcrypt

from app.models import User
from app.security import hash_password, verify_password, get_pepper

db_path = "app.db"

def init_db(path: str):
    global db_path
    db_path = path
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                salt TEXT NOT NULL
            )
            """
        )
        conn.commit()


@contextmanager
def get_conn():
    conn = sqlite3.connect(db_path, check_same_thread=False)
    try:
        yield conn
    finally:
        conn.close()

def create_user(username: str, password: str):
    salt = os.urandom(16).hex()
    pepper = get_pepper()
    hashed_password = hash_password(password, salt, pepper)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (username, password, salt) VALUES (?, ?, ?)",
            (username, hashed_password, salt),
        )
        conn.commit()
        return {"username": username, "hash_mode": "bcrypt"}

def get_user(username: str) -> User | None:
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        result = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if result:
            return User(username=result["username"], password=result["password"], salt=result["salt"])
        return None