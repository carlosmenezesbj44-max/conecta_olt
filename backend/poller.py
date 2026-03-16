import threading

from backend.collectors import service


class PollingScheduler(threading.Thread):
    def __init__(self, interval_sec=15):
        super().__init__(daemon=True)
        self.interval_sec = interval_sec
        self._stop_event = threading.Event()

    def run(self):
        while not self._stop_event.wait(self.interval_sec):
            try:
                service.poll_due_connections()
            except Exception:
                # O servidor continua respondendo mesmo que uma coleta falhe.
                pass

    def stop(self):
        self._stop_event.set()
