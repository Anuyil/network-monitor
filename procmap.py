import psutil
import time
import socket

_TTL = 1.0      # la snapshot dura 1 secondo
_map = {}       # (porta_locale, ip_remoto, porta_remota) -> pid
_local = {}     # porta_locale_udp -> set di pid
_last = 0.0     # quando è stata fatta l'ultima snapshot
_proc = {}      # pid -> (create_time, nome)

def _resolve(pid):
    try:
        p = psutil.Process(pid)
        return p.create_time(), p.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

def _refresh():
    global _map, _local, _last
    m, loc = {}, {}
    for c in psutil.net_connections(kind="inet"):
        if not c.laddr or not c.pid:
            continue
        if c.raddr:
            m[(c.laddr.port, c.raddr.ip, c.raddr.port)] = c.pid
        elif c.type == socket.SocketKind.SOCK_DGRAM:
            loc.setdefault(c.laddr.port, set()).add(c.pid)

    _map, _local, _last = m, loc, time.monotonic()
    _refresh_names(set(m.values()) | set().union(*loc.values()))

def _refresh_names(pids):
    for pid in pids:
        info = _resolve(pid)
        if info is None:
            _proc.pop(pid, None) #non cachiamo gli errori
        elif pid not in _proc or _proc[pid][0] != info[0]:
            _proc[pid] = info #nuovo processo o pid riusato

    for pid in list(_proc):
        if pid not in pids:
            del _proc[pid]

def pid_for(lport, rip, rport, udp=False):
    if time.monotonic() - _last > _TTL:
        _refresh()
    pid = _map.get((lport, rip, rport))
    if pid is not None:
        return pid
    if udp:
        pids = _local.get(lport, set())
        if len(pids) == 1:
            return next(iter(pids))
    return None

def pname(pid):
    if pid is None or pid not in _proc:
        return "Unknown"
    return _proc[pid][1]
