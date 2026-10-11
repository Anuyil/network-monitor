import sqlite3

DEFAULT_DB = "test_db.db"


def connect(path):
    """Ogni thread apre la propria connessione: SQLite non va condiviso."""
    con = sqlite3.connect(path, timeout=5)
    con.execute("PRAGMA journal_mode=WAL")
    return con
