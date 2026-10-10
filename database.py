import sqlite3


class Database:
    def __init__(self, path):
        self.con = sqlite3.connect(path)
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.execute("""
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
            )""")
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_pname   ON packets(pname)")
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_domains ON packets(domains)")
        self.con.commit()

    def insert(self, info):
        self.con.execute(
            """INSERT INTO packets
               (ts, iface, direction, src, dst, sport, dport, proto, len, pid, pname, domains)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (info["ts"], info["iface"], info["direction"], info["src"], info["dst"],
             info.get("sport"), info.get("dport"), info["proto"], info["len"],
             info["pid"], info["pname"], info["domains"] or None),
        )
        self.con.commit()

    def close(self):
        self.con.close()
