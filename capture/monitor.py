import logging
import threading

from pylibpcap.base import Sniff
from pylibpcap.exception import LibpcapError

log = logging.getLogger(__name__)


class Monitor:
    """Una interfaccia. Qui stanno tutti i default di cattura."""

    def __init__(self, iface, q, filters="", count=-1, promisc=1,
                 out_file="", timeout=500):
        self.iface = iface
        self.q = q
        self.filters = filters
        self.count = count
        self.promisc = promisc
        self.out_file = out_file
        self.timeout = timeout

        self.sniffobj = None
        self.running = False
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        if self.running:
            return
        self._stop_event.clear()
        self.running = True
        self._thread = threading.Thread(target=self.sniff_task, daemon=True)
        self._thread.start()

    def stop(self):
        if not self.running:
            return
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            if self._thread.is_alive():
                log.warning("[%s] il thread non si è fermato in tempo", self.iface)
                return          # non dichiarare fermo se gira ancora
        self.running = False

    def sniff_task(self):
        try:
            self.sniffobj = Sniff(self.iface, filters=self.filters, count=self.count,
                                  promisc=self.promisc, out_file=self.out_file,
                                  timeout=self.timeout)
            for plen, t, buf in self.sniffobj.capture():
                if self._stop_event.is_set():
                    break
                if plen == 0:           # tick di timeout, nessun pacchetto
                    continue
                self.q.put((self.iface, t, buf))
        except LibpcapError as e:
            log.error("[%s] %s", self.iface, e)
        finally:
            if self.sniffobj is not None:
                s = self.sniffobj.stats()
                log.info("[%s] %d pacchetti catturati", self.iface, s.capture_cnt)
            self.running = False
