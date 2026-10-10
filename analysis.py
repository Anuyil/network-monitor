import socket
import time
import psutil
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, TCP, UDP

MIN_TTL = 60   # secondi minimi di validità di una risposta DNS


def local_ipv4():
    return {a.address
            for addrs in psutil.net_if_addrs().values()
            for a in addrs if a.family == socket.AF_INET}


def parse(iface, ts, pkt, length):
    if IP not in pkt:
        return None
    ip = pkt[IP]
    info = {"iface": iface, "ts": ts, "src": ip.src, "dst": ip.dst,
            "proto": ip.proto, "len": length}
    if TCP in pkt:
        info["sport"], info["dport"] = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        info["sport"], info["dport"] = pkt[UDP].sport, pkt[UDP].dport
    return info


def get_dns(pkt, names):
    if DNS not in pkt or not pkt[DNS].qr:
        return

    now = time.monotonic()
    aliases = {}        # target -> alias
    a_records = []      # (nome, ip, ttl)

    for rr in pkt[DNS].an:
        name = rr.rrname.decode().rstrip(".")
        if rr.type == 5:                    # CNAME
            target = rr.rdata.decode().rstrip(".")
            aliases[target] = name
        elif rr.type == 1:                  # A
            a_records.append((name, rr.rdata, rr.ttl))
        rr = rr.payload

    for name, ip, ttl in a_records:
        chain = {name}
        while name in aliases and aliases[name] not in chain:
            name = aliases[name]
            chain.add(name)
        entry = names.setdefault(ip, {"names": set(), "expires": 0.0})
        entry["names"].update(chain)
        entry["expires"] = max(entry["expires"], now + max(ttl, MIN_TTL))


def name_for(ip, names):
    e = names.get(ip)
    if e is None or time.monotonic() > e["expires"]:
        return set()
    return e["names"]
