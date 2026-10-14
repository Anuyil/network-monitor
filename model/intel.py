import ipaddress

SCHEMA = """
CREATE TABLE IF NOT EXISTS intel (
    value    TEXT NOT NULL,
    category TEXT,
    source   TEXT,
    PRIMARY KEY (value, source))"""


def init(con):
    con.execute(SCHEMA)
    con.commit()


def load(con, path, category, source):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line:
                continue
            rows.append((line.split()[-1].lower(), category, source))
    con.executemany("INSERT OR REPLACE INTO intel VALUES (?, ?, ?)", rows)
    con.commit()
    return len(rows)


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def lookup(con, name):
    """Match per suffisso: x.a.example.com prova x.a.example.com, a.example.com, example.com.
    Gli IP non vengono cercati: le liste sono di domini."""
    if _is_ip(name):
        return None
    parts = name.lower().split(".")
    for i in range(len(parts)):
        hit = con.execute("SELECT category, source FROM intel WHERE value = ? LIMIT 1",
                          (".".join(parts[i:]),)).fetchone()
        if hit:
            return hit
    return None
