import threading
import logging
import queue
from pylibpcap.base import Sniff
from pylibpcap.exception import LibpcapError

log = logging.getLogger(__name__)

class Monitor:
    def __init__(self, iface, filters, count, promisc, out_file, timeout, queue) -> None:
        self.iface = iface
        self.filters = filters
        self.count = count
        self.promisc = promisc
        self.out_file = out_file
        self.timeout = timeout
        self.queue = queue

        self.sniffobj = None
        self.running = False #stato thread
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        if self.running == True:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self.sniff_task, daemon=True)
        self.running = True
        self._thread.start()


    def stop(self):
        if self.running == False:
            return
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            if self._thread.is_alive():
                log.info(f"[{self.iface}] il thread non si è fermato")
                return   # non dichiarare fermo
        self.running = False

    def sniff_task(self):
        try:
            self.sniffobj = Sniff(self.iface, filters = self.filters, count = self.count, promisc = self.promisc, out_file = self.out_file, timeout = self.timeout)

            for plen, t, buf in self.sniffobj.capture():
                if self._stop_event.is_set():
                    break
                if plen == 0:  # tick di timeout, nessun pacchetto
                    continue
                if self.queue is not None:
                    self.queue.put((self.iface, t, buf))

                #print(f"[{self.iface}] len={plen} t={t}")

        except LibpcapError as e:
            log.error(e)

        finally:
            if self.sniffobj is not None:
                stats = self.sniffobj.stats()
                log.info(f"[{self.iface}] {stats.capture_cnt} packets captured")
            self.running = False
