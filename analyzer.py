import queue
import threading
import socket
import psutil
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP
from database import Database
import analysis
import procmap


class Analyzer:
    def __init__(self, q: queue.Queue, db_path = "test_db.db") -> None:
        self.q = q
        self.db_path = db_path
        self.dns_names = {} # ip -> dominio
        self.local_ips = analysis.local_ipv4()

        self._stop_event = threading.Event()
        self._thread = None

        #self.count = 0 #usata per testing

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target = self._run, daemon = True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _run(self):
        db = Database(self.db_path)
        try:
            while not self._stop_event.is_set():
                try:
                    iface, ts, buf = self.q.get(timeout = 0.5)
                except queue.Empty:
                    continue
                try:
                    info = self._handle(iface, ts , buf)
                except Exception as e:      # un pacchetto malformato non deve uccidere il thread
                                    print(f"[analyzer] errore: {e}")
                                    continue
                if info is not None:
                    #print(f"{info['iface']} {info['src']} {info['dst']} {info['proto']}")
                    db.insert(info) #scrittura su DB

        finally:
                db.close()
                print("\nClosing db...")


    def _handle(self, iface, ts, buf):
        pkt = Ether(buf)
        if UDP in pkt and pkt[UDP].sport == 53:
            try:
                analysis.get_dns(pkt, self.dns_names)
            except Exception as e:
                print(f"[dns] {type(e).__name__}: {e}")
        info = analysis.parse(iface, ts, pkt, len(buf))
        if info is None:
            return None

        outbound = info["src"] in self.local_ips
        udp = info["proto"] == 17
        if "sport" in info:
            if outbound:
                info["pid"] = procmap.pid_for(info["sport"], info["dst"], info["dport"], udp)
            else:
                info["pid"] = procmap.pid_for(info["dport"], info["src"], info["sport"], udp)
        else:
            info["pid"] = None

        info["pname"] = procmap.pname(info["pid"])
        info["direction"] = "out" if outbound else "in"
        remote = info["dst"] if outbound else info["src"]
        info["domains"] = ",".join(sorted(analysis.name_for(remote, self.dns_names)))
        return info

#Ether
#  fields:  {dst, src, type}
#  payload ─▶ IP
#               fields:  {src, dst, proto, ttl, ...}
#               payload ─▶ UDP
#                            fields:  {sport, dport, len, chksum}
#                            payload ─▶ DNS
#                                         fields:  {id, qr, rd, qdcount, ancount, ...}
#                                         qd ─▶ DNSQR   (campo, non payload)
#                                         an ─▶ DNSRR ─payload─▶ DNSRR ─▶ ...  (campo)
