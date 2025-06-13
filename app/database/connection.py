import sqlite3
from contextlib import contextmanager
from app.config import config

@contextmanager
def get_db_connection():
    """Context manager do zarządzania połączeniami z bazą danych"""
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()