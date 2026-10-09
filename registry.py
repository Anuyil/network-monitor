import queue
from monitor import Monitor

class registryMonitor:
    def __init__(self) -> None:
        self.monitors = {}
        self.queue = queue.Queue()

    def add_interface(self, iface, filters = '', count = -1, promisc = 1, out_file = ''):
        if iface in self.monitors:
            return

        self.monitors[iface] = Monitor(
            iface = iface,
            filters = filters,
            count = count,
            promisc = promisc,
            out_file = out_file,
            queue = self.queue
        )

    def start_interface(self, iface):
        self.monitors[iface].start()

    def stop_interface(self, iface):
        self.monitors[iface].stop()

    def remove_interfare(self, iface):
        monitor = self.monitors.pop(iface, None)

        if monitor is not None:
            monitor.stop()

    def start_all(self):
        for iface in self.monitors:
            self.start_interface(iface)

    def stop_all(self):
        for iface in self.monitors:
            self.stop_interface(iface)
