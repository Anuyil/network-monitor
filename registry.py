import queue

from monitor import Monitor


class Registry:
    """Possiede la coda condivisa e un Monitor per interfaccia.
    Non conosce i default di cattura: li decide Monitor."""

    def __init__(self):
        self.monitors = {}
        self.queue = queue.Queue()

    def _get(self, iface):
        m = self.monitors.get(iface)
        if m is None:
            raise ValueError(f"interfaccia {iface} non aggiunta")
        return m

    def add_interface(self, iface, **kwargs):
        if iface not in self.monitors:
            self.monitors[iface] = Monitor(iface, self.queue, **kwargs)

    def start_interface(self, iface):
        self._get(iface).start()

    def stop_interface(self, iface):
        self._get(iface).stop()

    def toggle(self, iface):
        if iface not in self.monitors:
            self.add_interface(iface)
        if self.monitors[iface].running:
            self.stop_interface(iface)
        else:
            self.start_interface(iface)

    def remove_interface(self, iface):
        m = self.monitors.pop(iface, None)
        if m is not None:
            m.stop()

    def status(self):
        return {i: m.running for i, m in self.monitors.items()}

    def start_all(self):
        for iface in list(self.monitors):
            self.start_interface(iface)

    def stop_all(self):
        for iface in list(self.monitors):
            self.stop_interface(iface)
