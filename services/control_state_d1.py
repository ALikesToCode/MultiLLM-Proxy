"""Control-plane state in the Worker's D1 database, reached through the private outbound handler.

Container disk is reset whenever the Container sleeps or is replaced, and more than one
Container instance may serve the gateway. Whenever the Worker provides its durable store
(the INTELLIGENCE_DB binding sets INTELLIGENCE_STORAGE_BACKEND=d1), request usage, login
throttling, model overrides, free-route cooldowns, workbench records and the provider
catalog live in D1, behind fixed Worker operations under /v1/state. Every domain keeps
an in-memory copy, so a D1 outage degrades to that copy with a logged warning instead of
failing requests; admin saves that cannot be stored fail visibly.

State read on every request (usage, cooldowns) never waits on D1: one background thread
per process flushes and refreshes it every few seconds.
"""

import atexit
import logging
import os
import threading

# A module reference, not its names: intelligence_d1_store imports this package indirectly.
from services import intelligence_d1_store

logger = logging.getLogger(__name__)

TICK_SECONDS = 1.0
# Tests switch the thread off and run each domain's sync directly.
BACKGROUND = True
_tasks = []
_lock = threading.Lock()
_wake = threading.Event()
_worker = {"thread": None, "pid": None}


def using_d1():
    """Whether the Worker provides D1. An invalid backend value is the intelligence store's error to report."""
    return os.environ.get("INTELLIGENCE_STORAGE_BACKEND", "").strip() == "d1"


def call(endpoint, operation, **values):
    return intelligence_d1_store.request_private_intelligence({"operation": operation, **values}, endpoint=endpoint)


def cause(error):
    """A bounded description of a failed private call, for logs."""
    if isinstance(error, intelligence_d1_store.PrivateIntelligenceError):
        return f"{error.status} {error.code}"
    return getattr(error, "code", None) or type(error).__name__


def refused(error):
    """Whether the Worker rejected the request itself, so sending it again cannot succeed."""
    return isinstance(error, intelligence_d1_store.PrivateIntelligenceError) and 400 <= error.status < 500


def register(task):
    """Run task(final) on every background tick; final is True once, at process exit."""
    with _lock:
        if task not in _tasks:
            _tasks.append(task)


def ensure_running():
    thread = _worker["thread"]
    if not BACKGROUND or (thread is not None and thread.is_alive() and _worker["pid"] == os.getpid()):
        return
    with _lock:
        thread = _worker["thread"]
        if thread is None or not thread.is_alive() or _worker["pid"] != os.getpid():
            thread = threading.Thread(target=_run, daemon=True, name="control-state-sync")
            _worker["thread"], _worker["pid"] = thread, os.getpid()
            thread.start()


def wake():
    """Run a background tick now, for example when a new identity needs its shared usage."""
    ensure_running()
    _wake.set()


def run_tasks(final=False):
    if not using_d1():
        return
    for task in list(_tasks):
        try:
            task(final)
        except Exception as error:  # noqa: BLE001 - one domain must not stop the others.
            logger.warning("Control state sync failed (%s)", type(error).__name__)


def _run():
    while True:
        _wake.wait(TICK_SECONDS)
        _wake.clear()
        run_tasks()


@atexit.register
def _flush_at_exit():
    # A Container that is sleeping or being replaced stops gracefully; send what is pending.
    if _worker["thread"] is not None and _worker["pid"] == os.getpid():
        run_tasks(final=True)
