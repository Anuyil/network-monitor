import queue
import threading
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP

class Analyzer:
    def __init__(self, q: queue.Queue) -> None:
        self.q = q
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
        while not self._stop_event.is_set():
            try:
                iface, ts, buf = self.q.get(timeout = 0.5)
            except queue.Empty:
                continue
            info = self.parse(iface, ts , buf)
            if info is not None:
                print(f"{info['iface']} {info['src']} {info['dst']} {info['proto']}") #scrittura su DB

    def parse(self, iface, ts, buf):
        pkt = Ether(buf)
        if IP not in pkt:
            return None
        ip = pkt[IP]
        info = {"iface": iface, "ts": ts, "src":ip.src, "dst": ip.dst, "proto": ip.proto, "len": len(buf)}

        if TCP in pkt:
            info["sport"], info["dport"] = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            info["sport"], info["dport"] = pkt[UDP].sport, pkt[UDP].dport
        return info
