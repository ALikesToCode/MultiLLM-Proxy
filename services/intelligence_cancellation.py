"""Observe caller disconnects without reading or taking ownership of WSGI sockets."""

import select
import threading


class CallerCancellation(threading.Event):
    """Check the server's socket at every bounded transport cancellation check.

    Gunicorn and Werkzeug expose the accepted socket. Linux POLLRDHUP reports
    the caller's close even before a response write, so a silent upstream cannot
    postpone cancellation until the overall deadline. Other WSGI servers retain
    explicit cancellation and deadline enforcement without socket inspection.
    """

    def __init__(self, environ):
        super().__init__()
        self._poller = None
        self._poll_lock = threading.Lock()
        connection = environ.get("gunicorn.socket", environ.get("werkzeug.socket"))
        if connection is None or not hasattr(select, "poll"):
            return
        self._disconnect_flags = (
            select.POLLHUP
            | select.POLLERR
            | select.POLLNVAL
            | getattr(select, "POLLRDHUP", 0)
        )
        try:
            self._poller = select.poll()
            self._poller.register(connection.fileno(), self._disconnect_flags)
        except (OSError, ValueError):
            self._poller = None
            self.set()

    def is_set(self):
        if not super().is_set() and self._poller is not None:
            with self._poll_lock:
                if any(
                    flags & self._disconnect_flags for _, flags in self._poller.poll(0)
                ):
                    self.set()
        return super().is_set()
