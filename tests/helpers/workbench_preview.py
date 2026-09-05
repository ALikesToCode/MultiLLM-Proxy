"""Loopback-only browser fixture. Run from a secret-free source snapshot."""

import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

from werkzeug.serving import make_server

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from error_handlers import APIError  # noqa: E402


class PreviewStream:
    raw = object()
    ok = True
    is_redirect = False
    status_code = 200
    headers = {"Content-Type": "text/event-stream", "X-Roleplay-Session-ID": "recovery-preview-branch"}

    def iter_content(self, chunk_size=None):
        for text in ["<think>Synthetic hidden reasoning.</think>", "Iona sets down the brass watch. ", '"The courier left at noon," she says. ', "The sealed blue letter stays on the desk."]:
            time.sleep(0.15)
            yield ("data: " + json.dumps({"choices": [{"delta": {"content": text}}]}) + "\n\n").encode()
        yield b'data: {"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"completion_tokens":40}}\n\n'
        yield b"data: [DONE]\n\n"

    def close(self):
        pass


class PreviewWorker:
    def __init__(self):
        self.revision = 1
        self.summary = "The letter is blue. The bridge is closed."
        self.pins = ["Iona wears a brass watch."]
        self.calls = 0

    def json(self, path, *, method="GET", payload=None, params=None):
        if path.endswith("/models"):
            return {"data": [dict(provider="nanogpt", model=model, billing_mode="subscription") for model in
                             ("z-ai/glm-5.3-flash", "z-ai/glm-5.3-flash-uncensored", "zai-org/glm-5.2")]}
        if path.endswith("/status"):
            return {"build_id": "preview-worker-different", "compatibility": 1, "version_id": "synthetic-version"}
        if path.endswith("/receipt"):
            return {"valid": True, "validation": "synthetic configured catalog; no provider call",
                    "selected": {"provider": "nanogpt", "model": payload["routing"]["model"], "wireEffort": "xhigh", "providerAcknowledged": False}}
        if path.endswith("/timeline"):
            return {"retention": "Synthetic preview only", "records": [{"id": "synthetic-trace", "phase": "completed", "provider": "nanogpt", "model": "z-ai/glm-5.3-flash",
                    "events": [{"phase": phase, "elapsedMs": ms} for phase, ms in (("queued", 0), ("connecting", 10), ("reasoning", 20), ("visible", 40), ("completed", 100))], "metrics": {"firstContentMs": 40}, "parameters": {"requestedEffort": "max", "wireEffort": "xhigh", "providerAcknowledged": False}}]}
        if path.endswith("/branch"):
            return {"session_id": "branch-synthetic-preview", "label": payload["label"], "created": True}
        if path.endswith("/recovery"):
            return {"partial": "Iona picks up the letter. ", "token": "synthetic-recovery-token", "reason": "incomplete_eof", "expiresAt": (time.time() + 3600) * 1000, "truncated": False}
        if path.endswith("/memory"):
            if payload["action"] == "update":
                if payload["revision"] != str(self.revision):
                    raise APIError("Memory changed; inspect again", status_code=409)
                self.summary = payload["summary"]
                self.pins = payload["pins"]
                self.revision += 1
            return {"revision": str(self.revision), "memory": {"summary": self.summary}, "pins": self.pins,
                    "retainedMessageCount": 4, "completedTurns": 2, "profile": {}, "branch": None,
                    **({"retainedMessages": [{"role": "user", "content": "Synthetic private context"}], "protectedDirectives": []} if payload.get("include_context") else {})}
        raise AssertionError("Unexpected fixture operation")

    def stream(self, path, **kwargs):
        self.calls += 1
        return PreviewStream()


def main():
    if os.environ.get("MULTILLM_SYNTHETIC_PREVIEW") != "1":
        raise SystemExit("Requires the explicit synthetic preview environment")
    if os.environ.get("ADMIN_API_KEY") != "synthetic-workbench-key":
        raise SystemExit("Only the synthetic fixture credential is accepted")
    from app import create_app
    app = create_app()
    fixture = PreviewWorker()
    app.add_url_rule("/__fixture/calls", view_func=lambda: {"calls": fixture.calls})
    with patch("routes.workbench.worker_json", fixture.json), patch("routes.workbench.call_worker", fixture.stream), patch(
        "routes.workbench.compatibility_probes", lambda origin: {"scope": "synthetic fixture; not live network proof", "checks": []}
    ):
        server = make_server("127.0.0.1", 0, app, threaded=True)
        print(f"Synthetic workbench: http://127.0.0.1:{server.server_port}/workbench", flush=True)
        try:
            server.serve_forever()
        finally:
            server.server_close()


if __name__ == "__main__":
    main()
