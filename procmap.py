import logging
import socket
import time

import psutil

log = logging.getLogger(__name__)

_TTL = 1.0      # la snapshot dura 1 secondo
_map = {}       # (porta_locale, ip_remoto, porta_remota) -> pid
_local = {}     # porta_locale_udp -> set di pid
_last = 0.0     # istante dell'ultima snapshot
_proc = {}      # pid -> (create_time, nome)
_warned = False


def _resolve(pid):
    try:
        p = psutil.Process(pid)
        return p.create_time(), p.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def _refresh_names(pids):
    for pid in pids:
        info = _resolve(pid)
        if info is None:
            _proc.pop(pid, None)
        elif pid not in _proc or _proc[pid][0] != info[0]:
            _proc[pid] = info           # processo nuovo o PID riusato
    for pid in list(_proc):
        if pid not in pids:
            del _proc[pid]


def _refresh():
    global _map, _local, _last, _warned
    m, loc = {}, {}
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        if not _warned:
            log.warning("net_connections negato: serve sudo per attribuire i PID")
            _warned = True
        conns = []                      # _last viene aggiornato comunque: niente retry a ogni pacchetto

    for c in conns:
        if not c.laddr or not c.pid:
            continue
        if c.raddr:
            m[(c.laddr.port, c.raddr.ip, c.raddr.port)] = c.pid
        elif c.type == socket.SocketKind.SOCK_DGRAM:
            loc.setdefault(c.laddr.port, set()).add(c.pid)

    _map, _local, _last = m, loc, time.monotonic()
    _refresh_names(set(m.values()) | set().union(*loc.values()))


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
