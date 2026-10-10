import argparse
import curses
import logging
import sqlite3
import time

import psutil

from database import Database
from registry import registryMonitor
from analyzer import Analyzer


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


def stats_lines(con, window):
    totals, procs, doms = fetch(con, time.time() - window)
    lines = [f"finestra {window}s   {time.strftime('%H:%M:%S')}", "",
             f"{'DIREZIONE':<12} {'PKT':>8} {'BYTE':>12} {'B/s':>10}"]
    lines += [f"{d:<12} {n:>8} {b:>12} {b / window:>10.0f}" for d, n, b in totals]
    lines += ["", f"{'PROCESSO (out)':<26} {'PKT':>8} {'BYTE':>12}"]
    lines += [f"{p:<26} {n:>8} {b:>12}" for p, n, b in procs]
    lines += ["", f"{'DOMINIO (out)':<40} {'PKT':>8} {'BYTE':>12}"]
    lines += [f"{d[:40]:<40} {n:>8} {b:>12}" for d, n, b in doms]
    return lines


def iface_lines(reg, names):
    out = []
    for name in names:
        m = reg.monitors.get(name)
        state = "in cattura" if m and m.running else "fermo"
        out.append(f"{name:<12} {state}")
    return out


def toggle(reg, iface):
    if iface not in reg.monitors:
        reg.add_interface(iface)
    if reg.monitors[iface].running:
        reg.stop_interface(iface)
    else:
        reg.start_interface(iface)


def draw(scr, header, lines, sel=None):
    scr.erase()
    h, w = scr.getmaxyx()
    scr.addnstr(0, 0, header, w - 1, curses.A_BOLD)
    for i, line in enumerate(lines[: h - 2]):
        attr = curses.A_REVERSE if i == sel else curses.A_NORMAL
        scr.addnstr(i + 2, 0, line, w - 1, attr)
    scr.refresh()


def tui(scr, db_path, reg, window):
    curses.curs_set(0)
    scr.timeout(1000)                  # getch torna ogni secondo: è il refresh
    con = sqlite3.connect(db_path)
    names = sorted(psutil.net_if_addrs())
    view, sel = 0, 0
    try:
        while True:
            if view == 0:
                try:
                    lines = stats_lines(con, window)
                except sqlite3.OperationalError:
                    lines = ["in attesa dei dati..."]
                draw(scr, "[1] statistiche  [2] interfacce  Tab cambia  q esci", lines)
            else:
                draw(scr, "[1] statistiche  [2] interfacce  frecce scegli  s avvia/ferma  q esci",
                     iface_lines(reg, names), sel)

            k = scr.getch()
            if k == ord("q"):
                break
            elif k == 9:                       # Tab
                view = 1 - view
            elif k == ord("1"):
                view = 0
            elif k == ord("2"):
                view = 1
            elif k == curses.KEY_DOWN:
                sel = min(sel + 1, len(names) - 1)
            elif k == curses.KEY_UP:
                sel = max(sel - 1, 0)
            elif k == ord("s") and view == 1:
                toggle(reg, names[sel])
    finally:
        con.close()


def main():
    p = argparse.ArgumentParser(prog="netmon", description="network monitor")
    p.add_argument("--db", default="test_db.db")
    p.add_argument("--window", type=int, default=10, help="finestra statistiche in secondi")
    args = p.parse_args()

    # i log vanno su file: stdout è occupato dalla TUI
    logging.basicConfig(filename="netmon.log", level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    Database(args.db).close()          # crea la tabella prima che parta la TUI
    reg = registryMonitor()
    analyzer = Analyzer(reg.queue, db_path=args.db)
    analyzer.start()
    try:
        curses.wrapper(tui, args.db, reg, args.window)
    finally:
        reg.stop_all()
        analyzer.stop()


if __name__ == "__main__":
    main()
