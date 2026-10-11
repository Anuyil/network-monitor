import logging
import sqlite3
import time
from collections import defaultdict

import alerts
import db
import packets

log = logging.getLogger(__name__)

WINDOW = 60                   # secondi della finestra delle regole
LEARN = 3600                  # secondi di apprendimento prima di segnalare novità
VOLUME_LIMIT = 5_000_000      # byte in uscita per processo, per finestra
QUIET = {"Calculator", "TextEdit", "Preview"}

# tabelle di stato di questo modulo: la baseline e l'inizio dell'apprendimento
SCHEMA = [
    """CREATE TABLE IF NOT EXISTS pairs (
        pname TEXT NOT NULL, key TEXT NOT NULL, first_seen REAL NOT NULL,
        PRIMARY KEY (pname, key))""",
    """CREATE TABLE IF NOT EXISTS meta (
        k TEXT PRIMARY KEY, v REAL)""",
]

_last = {}                    # (kind, pname, key) -> ultimo avviso, anti-ripetizione


def init(con):
    for stmt in SCHEMA:
        con.execute(stmt)
    con.commit()


def _alert(con, now, kind, pname, key, detail):
    k = (kind, pname, key)
    if now - _last.get(k, 0) < WINDOW:
        return
    _last[k] = now
    alerts.add(con, now, kind, pname, detail)


def _started(con, now):
    row = con.execute("SELECT v FROM meta WHERE k = 'started'").fetchone()
    if row is None:
        con.execute("INSERT INTO meta (k, v) VALUES ('started', ?)", (now,))
        con.commit()
        return now
    return row[0]


def scan(con, now):
    learning = now - _started(con, now) < LEARN
    per_proc = defaultdict(int)

    for pname, dest_str, nbytes in packets.app_destinations(con, now - WINDOW):
        per_proc[pname] += nbytes
        for key in filter(None, dest_str.split(",")):
            if pname in QUIET:
                _alert(con, now, "quiet", pname, key, f"contatta {key}")
            cur = con.execute(
                "INSERT OR IGNORE INTO pairs (pname, key, first_seen) VALUES (?, ?, ?)",
                (pname, key, now))
            if cur.rowcount and not learning:
                _alert(con, now, "new", pname, key, f"nuova destinazione {key}")

    for pname, nbytes in per_proc.items():
        if nbytes > VOLUME_LIMIT:
            _alert(con, now, "volume", pname, "", f"{nbytes} byte in uscita")
    con.commit()


def loop(db_path, stop, every=30):
    con = db.connect(db_path)
    try:
        while not stop.wait(every):     # torna subito se stop viene impostato
            try:
                scan(con, time.time())
            except sqlite3.OperationalError as e:
                log.error("detect: %s", e)
    finally:
        con.close()
