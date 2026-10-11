SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id        INTEGER PRIMARY KEY,
    ts        REAL NOT NULL,
    iface     TEXT NOT NULL,
    direction TEXT,
    src       TEXT,
    dst       TEXT,
    sport     INTEGER,
    dport     INTEGER,
    proto     INTEGER,
    len       INTEGER,
    pid       INTEGER,
    pname     TEXT,
    domains   TEXT
)"""

INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_ts      ON packets(ts)",
    "CREATE INDEX IF NOT EXISTS idx_pname   ON packets(pname)",
    "CREATE INDEX IF NOT EXISTS idx_domains ON packets(domains)",
]

INSERT = """
INSERT INTO packets
    (ts, iface, direction, src, dst, sport, dport, proto, len, pid, pname, domains)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""


def init(con):
    con.execute(SCHEMA)
    for stmt in INDEXES:
        con.execute(stmt)
    con.commit()


def insert(con, info):
    con.execute(INSERT, (
        info["ts"], info["iface"], info["direction"], info["src"], info["dst"],
        info.get("sport"), info.get("dport"), info["proto"], info["len"],
        info["pid"], info["pname"], info["domains"] or None,
    ))
    con.commit()


def totals(con, since):
    return con.execute(
        "SELECT direction, COUNT(*), SUM(len) FROM packets "
        "WHERE ts > ? GROUP BY direction", (since,)).fetchall()


def top_procs(con, since, limit=10):
    return con.execute(
        "SELECT pname, COUNT(*), SUM(len) FROM packets "
        "WHERE direction = 'out' AND ts > ? "
        "GROUP BY pname ORDER BY SUM(len) DESC LIMIT ?", (since, limit)).fetchall()


def top_domains(con, since, limit=10):
    return con.execute(
        "SELECT domains, COUNT(*), SUM(len) FROM packets "
        "WHERE direction = 'out' AND domains IS NOT NULL AND ts > ? "
        "GROUP BY domains ORDER BY SUM(len) DESC LIMIT ?", (since, limit)).fetchall()


def app_destinations(con, since):
    """(pname, destinazioni separate da virgola, byte): usata da telemetria e detect."""
    return con.execute("""
        SELECT pname, COALESCE(domains, dst), SUM(len) FROM packets
        WHERE direction = 'out' AND pname != 'Unknown' AND ts > ?
        GROUP BY pname, COALESCE(domains, dst)""", (since,)).fetchall()
