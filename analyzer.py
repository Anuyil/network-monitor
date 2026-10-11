import logging
import queue
import threading

from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether

import analysis
import db
import packets
import procmap

log = logging.getLogger(__name__)


class Analyzer:
    """Consuma la coda: decodifica, arricchisce, scrive in `packets`."""

    def __init__(self, q: queue.Queue, db_path: str) -> None:
        self.q = q
        self.db_path = db_path
        self.dns_names = {}                 # ip -> {"names", "expires"}
        self.local_ips = analysis.local_ipv4()
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _consume(self, con, item):
        iface, ts, buf = item
        try:
            info = self._handle(iface, ts, buf)
        except Exception as e:              # un pacchetto malformato non uccide il thread
            log.error("pacchetto scartato: %s: %s", type(e).__name__, e)
            return
        if info is not None:
            packets.insert(con, info)

    def _run(self):
        con = db.connect(self.db_path)
        try:
            while not self._stop_event.is_set():
                try:
                    item = self.q.get(timeout=0.5)
                except queue.Empty:
                    continue
                self._consume(con, item)
            while True:                     # drena la coda residua allo stop
                try:
                    item = self.q.get_nowait()
                except queue.Empty:
                    break
                self._consume(con, item)
        finally:
            con.close()

    def _handle(self, iface, ts, buf):
        pkt = Ether(buf)
        if UDP in pkt and pkt[UDP].sport == 53:
            try:
                analysis.learn_dns(pkt, self.dns_names)
            except Exception as e:
                log.error("dns: %s: %s", type(e).__name__, e)

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
