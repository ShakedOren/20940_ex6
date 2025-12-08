from contextlib import contextmanager
import sqlite3

from app.models import User

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
                password TEXT NOT NULL
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

def create_user(user: User):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (user.username, user.password),
        )

        conn.commit()

def get_user(username: str) -> User | None:
    with get_conn() as conn:
        result = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if result:
            return User(username=result[1], password=result[2])
        return None