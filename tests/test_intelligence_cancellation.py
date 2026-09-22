import json
import select
import socket
import threading
import time
from contextlib import closing

import pytest
from werkzeug.serving import make_server

from services.control_plane_backup import capture
from services.intelligence_cancellation import CallerCancellation
from tests.intelligence_fixtures import IntelligenceApiTestCase, upstream


@pytest.mark.parametrize("socket_key", ["gunicorn.socket", "werkzeug.socket"])
def test_cancellation_observes_disconnect_without_consuming_or_closing_socket(
    socket_key,
):
    server, client = socket.socketpair()
    with closing(server), closing(client):
        cancelled = CallerCancellation({socket_key: server})
        client.sendall(b"synthetic-body")
        assert not cancelled.is_set()
        assert server.recv(14) == b"synthetic-body"
        client.close()
        assert cancelled.is_set()
        assert server.fileno() >= 0


def test_servers_without_a_socket_keep_explicit_cancellation():
    cancelled = CallerCancellation({})
    assert not cancelled.is_set()
    cancelled.set()
    assert cancelled.is_set()


@pytest.mark.skipif(
    not hasattr(select, "POLLRDHUP"), reason="Linux socket disconnect events required"
)
class IntelligenceDisconnectTests(IntelligenceApiTestCase):
    def test_nonstreaming_disconnect_cancels_header_wait_without_fallback(self):
        self.seed()
        entered, release = threading.Event(), threading.Event()

        def blocked_provider(**kwargs):
            entered.set()
            release.wait(3)
            return upstream({}, 429)

        server = make_server("127.0.0.1", 0, self.app, threaded=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        body = json.dumps(
            {
                "model": "auto:intelligence",
                "messages": [{"role": "user", "content": "test"}],
            }
        ).encode()
        wire = (
            f"POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\n"
            f"Authorization: Bearer admin-test-key\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode() + body
        rows = []
        try:
            with self.requests(side_effect=blocked_provider) as send:
                with socket.create_connection(
                    ("127.0.0.1", server.server_port)
                ) as client:
                    client.sendall(wire)
                    assert entered.wait(1)
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    rows = capture()["tables"]["intelligence_reservations"]
                    if rows and rows[0]["state"] == "unknown":
                        break
                    time.sleep(0.01)
                assert rows and rows[0]["state"] == "unknown"
                release.set()
                assert send.call_count == 1
        finally:
            release.set()
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)
