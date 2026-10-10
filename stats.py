import sqlite3
import sys
import time
import os

DB = "test_db.db"
WINDOW = 10      # secondi di finestra per le statistiche
REFRESH = 2      # secondi tra un aggiornamento e l'altro


def fetch(con, since):
    totals = con.execute(
        "SELECT direction, COUNT(*), SUM(len) FROM packets "
        "WHERE ts > ? GROUP BY direction", (since,)).fetchall()
    procs = con.execute(
        "SELECT pname, COUNT(*), SUM(len) FROM packets "
        "WHERE direction = 'out' AND ts > ? "
        "GROUP BY pname ORDER BY SUM(len) DESC LIMIT 10", (since,)).fetchall()
    doms = con.execute(
        "SELECT domains, COUNT(*), SUM(len) FROM packets "
        "WHERE direction = 'out' AND domains IS NOT NULL AND ts > ? "
        "GROUP BY domains ORDER BY SUM(len) DESC LIMIT 10", (since,)).fetchall()
    return totals, procs, doms


def render(totals, procs, doms):
    lines = [f"finestra {WINDOW}s   aggiornato {time.strftime('%H:%M:%S')}", ""]

    lines.append(f"{'DIREZIONE':<12} {'PKT':>8} {'BYTE':>12} {'B/s':>10}")
    for d, n, b in totals:
        lines.append(f"{d:<12} {n:>8} {b:>12} {b / WINDOW:>10.0f}")

    lines += ["", f"{'PROCESSO (out)':<26} {'PKT':>8} {'BYTE':>12}"]
    for p, n, b in procs:
        lines.append(f"{p:<26} {n:>8} {b:>12}")

    lines += ["", f"{'DOMINIO (out)':<40} {'PKT':>8} {'BYTE':>12}"]
    for d, n, b in doms:
        lines.append(f"{d[:40]:<40} {n:>8} {b:>12}")

    return "\n".join(lines)


def main():
    con = sqlite3.connect(DB)
    try:
        while True:
            since = time.time() - WINDOW
            out = render(*fetch(con, since))
            os.system("clear")
            print(out)
            time.sleep(REFRESH)
    except KeyboardInterrupt:
        pass
    finally:
        con.close()


if __name__ == "__main__":
    main()
