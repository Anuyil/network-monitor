import argparse
import curses
import logging
import sqlite3
import threading
import time

import psutil

import alerts
import db
import detect
import intel
import packets
import telemetry
from analyzer import Analyzer
from registry import Registry

HEADER = "[1] statistiche  [2] interfacce  [3] avvisi  [4] telemetria  Tab cambia  q esci"
VIEWS = 4


def capturable():
    """Solo interfacce con frame Ethernet: lo0, utun*, awdl* restano fuori."""
    return sorted(n for n in psutil.net_if_addrs() if n.startswith("en"))


def stats_lines(con, window):
    since = time.time() - window
    totals = packets.totals(con, since)
    procs = packets.top_procs(con, since)
    doms = packets.top_domains(con, since)
    lines = [f"finestra {window}s   {time.strftime('%H:%M:%S')}", "",
             f"{'DIREZIONE':<12} {'PKT':>8} {'BYTE':>12} {'B/s':>10}"]
    lines += [f"{d:<12} {n:>8} {b:>12} {b / window:>10.0f}" for d, n, b in totals]
    lines += ["", f"{'PROCESSO (out)':<26} {'PKT':>8} {'BYTE':>12}"]
    lines += [f"{p:<26} {n:>8} {b:>12}" for p, n, b in procs]
    lines += ["", f"{'DOMINIO (out)':<40} {'PKT':>8} {'BYTE':>12}"]
    lines += [f"{d[:40]:<40} {n:>8} {b:>12}" for d, n, b in doms]
    return lines


def alert_lines(con):
    rows = alerts.recent(con)
    return [f"{time.strftime('%H:%M:%S', time.localtime(ts))}  {kind:<7} {p or '':<20} {d}"
            for ts, kind, p, d in rows] or ["nessun avviso"]


def iface_lines(reg, names):
    st = reg.status()
    return [f"{n:<12} {'in cattura' if st.get(n) else 'fermo'}" for n in names]


def draw(scr, header, lines, sel=None):
    scr.erase()
    h, w = scr.getmaxyx()
    scr.addnstr(0, 0, header, w - 1, curses.A_BOLD)
    for i, line in enumerate(lines[: h - 2]):
        attr = curses.A_REVERSE if i == sel else curses.A_NORMAL
        scr.addnstr(i + 2, 0, line, w - 1, attr)
    scr.refresh()


def safe(fn, *args):
    """Una vista non deve far crashare la TUI se una tabella manca ancora."""
    try:
        return fn(*args)
    except sqlite3.OperationalError as e:
        return [f"in attesa dei dati ({e})"]


def tui(scr, db_path, reg, window):
    curses.curs_set(0)
    scr.timeout(1000)                   # getch torna ogni secondo: è il refresh
    con = db.connect(db_path)
    names = capturable()
    view = 0
    sel = 0                             # indice della riga evidenziata
    tel_rows: list[dict] = []           # app ordinate per punteggio
    tel_open = None                     # nome dell'app nel dettaglio, None = lista
    tel_sel_name = None                 # app evidenziata, segue il nome nei refresh
    try:
        while True:
            if view == 0:
                draw(scr, HEADER, safe(stats_lines, con, window))
            elif view == 1:
                draw(scr, HEADER + "  frecce scegli  s avvia/ferma",
                     iface_lines(reg, names), sel)
            elif view == 2:
                draw(scr, HEADER, safe(alert_lines, con))
            elif tel_open is None:
                try:
                    tel_rows = telemetry.scores(con, time.time() - telemetry.WINDOW)
                except sqlite3.OperationalError as e:
                    draw(scr, HEADER, [f"in attesa dei dati ({e})"])
                    tel_rows = []
                else:
                    app_names = [r["app"] for r in tel_rows]
                    if tel_sel_name in app_names:
                        sel = app_names.index(tel_sel_name)   # segue l'app se la lista si riordina
                    sel = min(sel, max(len(tel_rows) - 1, 0))
                    if tel_rows:
                        tel_sel_name = tel_rows[sel]["app"]   # sincronizza il nome con ciò che è a schermo
                    draw(scr, "[4] telemetria  frecce scegli  Invio dettaglio  q esci",
                         telemetry.list_lines(tel_rows), sel)
            else:
                draw(scr, f"[4] telemetria  {tel_open}  Esc torna  q esci",
                     telemetry.app_detail(tel_rows, tel_open))

            k = scr.getch()
            if k == ord("q"):
                break
            if k == 9:                                   # Tab
                view = (view + 1) % VIEWS
                tel_open, sel, tel_sel_name = None, 0, None
            elif ord("1") <= k <= ord("4"):
                view = k - ord("1")
                tel_open, sel, tel_sel_name = None, 0, None
            elif view == 1 and names and k == curses.KEY_DOWN:
                sel = min(sel + 1, len(names) - 1)
            elif view == 1 and names and k == curses.KEY_UP:
                sel = max(sel - 1, 0)
            elif view == 1 and names and k == ord("s"):
                reg.toggle(names[sel])
            elif view == 3 and tel_open is None:
                if k == curses.KEY_DOWN and tel_rows:
                    sel = min(sel + 1, len(tel_rows) - 1)
                    tel_sel_name = tel_rows[sel]["app"]
                elif k == curses.KEY_UP and tel_rows:
                    sel = max(sel - 1, 0)
                    tel_sel_name = tel_rows[sel]["app"]
                elif k in (10, 13, curses.KEY_ENTER) and tel_rows:
                    tel_open = tel_sel_name
            elif view == 3 and tel_open is not None and k in (27, curses.KEY_BACKSPACE):
                tel_open = None
    finally:
        con.close()

def main():
    p = argparse.ArgumentParser(prog="netmon", description="network monitor")
    p.add_argument("--db", default=db.DEFAULT_DB)
    p.add_argument("--window", type=int, default=10, help="finestra statistiche in secondi")
    args = p.parse_args()

    # i log vanno su file: stdout è occupato dalla TUI
    logging.basicConfig(filename="netmon.log", level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    # schema: una volta sola, prima che partano i thread
    con = db.connect(args.db)
    for mod in (packets, intel, alerts, detect):
        mod.init(con)
    con.close()

    reg = Registry()
    analyzer = Analyzer(reg.queue, args.db)
    analyzer.start()

    stop = threading.Event()
    det = threading.Thread(target=detect.loop, args=(args.db, stop), daemon=True)
    det.start()

    try:
        curses.wrapper(tui, args.db, reg, args.window)
    finally:
        stop.set()
        det.join(timeout=5)
        reg.stop_all()                  # prima i produttori
        analyzer.stop()                 # poi il consumatore


if __name__ == "__main__":
    main()
