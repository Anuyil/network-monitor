import time

import intel
import packets

WINDOW = 24 * 3600
WEIGHTS = {"tracker": 5, "dests": 0.5}
_cache = {"t": 0.0, "rows": []}


def scores(con, since):
    """Una riga per app, ordinata per punteggio."""
    apps = {}
    for pname, dest_str, nbytes in packets.app_destinations(con, since):
        a = apps.setdefault(pname, {"bytes": 0, "dests": {}})
        a["bytes"] += nbytes
        for dest in filter(None, dest_str.split(",")):
            a["dests"][dest] = intel.lookup(con, dest)   # None oppure (categoria, fonte)

    rows = []
    for pname, a in apps.items():
        trackers = sum(1 for v in a["dests"].values() if v)
        score = trackers * WEIGHTS["tracker"] + len(a["dests"]) * WEIGHTS["dests"]
        rows.append({"score": score, "app": pname, "bytes": a["bytes"],
                     "dests": a["dests"]})
    return sorted(rows, key=lambda r: r["score"], reverse=True)


def app_detail(rows, app):
    """Tutte le destinazioni di un'app, tracker in cima."""
    for r in rows:
        if r["app"] == app:
            items = sorted(r["dests"].items(),
                           key=lambda kv: (kv[1] is None, kv[0]))
            return [f"{dest:<50} {label(hit)}" for dest, hit in items]
    return ["app non trovata"]


def label(hit):
    return f"[{hit[0]}/{hit[1]}]" if hit else ""


def list_lines(rows):
    lines = [f"{'APP':<22} {'SCORE':>6} {'BYTE OUT':>12} {'DEST':>5} {'TRACKER':>8}", ""]
    for r in rows[:30]:
        n = sum(1 for v in r["dests"].values() if v)
        lines.append(f"{r['app'][:22]:<22} {r['score']:>6.1f} "
                     f"{r['bytes']:>12} {len(r['dests']):>5} {n:>8}")
    return lines


def lines(con, selected=None, window=WINDOW, every=10):
    """Restituisce la lista app, oppure il dettaglio se `selected` è un'app."""
    now = time.time()
    if now - _cache["t"] > every:
        _cache["rows"] = scores(con, now - window)
        _cache["t"] = now
    if selected is None:
        return list_lines(_cache["rows"])
    return app_detail(_cache["rows"], selected)
