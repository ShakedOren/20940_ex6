from contextlib import contextmanager
import sqlite3

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
                password_hash TEXT NOT NULL,
                type TEXT NOT NULL
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

def create_user(username: str, password_hash: str, type: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, type) VALUES (?, ?, ?)",
            (username, password_hash, type),
        )

        conn.commit()

def get_user(username: str) -> dict | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()