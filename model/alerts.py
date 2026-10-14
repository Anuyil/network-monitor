SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id     INTEGER PRIMARY KEY,
    ts     REAL NOT NULL,
    kind   TEXT NOT NULL,
    pname  TEXT,
    detail TEXT)"""


def init(con):
    con.execute(SCHEMA)
    con.commit()


def add(con, ts, kind, pname, detail):
    con.execute("INSERT INTO alerts (ts, kind, pname, detail) VALUES (?, ?, ?, ?)",
                (ts, kind, pname, detail))
    con.commit()


def recent(con, limit=30):
    return con.execute(
        "SELECT ts, kind, pname, detail FROM alerts ORDER BY id DESC LIMIT ?",
        (limit,)).fetchall()
