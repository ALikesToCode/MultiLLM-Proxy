#!/usr/bin/env python3
"""Optional SessionStart context for Claude Code and Codex; silent within one second."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import queue
import sys
import threading

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from handoff import load
from handoff_contracts import render


def hint(event, args, *, fetch=load, now=None):
    if not isinstance(event, dict) or event.get("hook_event_name") != "SessionStart":
        return None
    if not isinstance(event.get("cwd"), str):
        return None
    args.cwd = event["cwd"]
    record = fetch(args, timeout=0.8).get("record")
    if not isinstance(record, dict):
        return None
    created = datetime.fromisoformat(record["created_at"].replace("Z", "+00:00"))
    current = now or datetime.now(timezone.utc)
    age = (current - created).total_seconds()
    expires = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
    if not 0 <= age < 48 * 3600 or expires <= current:
        return None
    markdown = render(record)
    return {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": markdown}}


class QuietParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("Invalid hook arguments")


def main(argv=None):
    results = queue.Queue(maxsize=1)

    def work():
        try:
            parser = QuietParser(add_help=False)
            parser.add_argument("--agent", choices=("claude", "codex"), required=True)
            parser.add_argument("--base-url")
            parser.add_argument("--key-file")
            args = parser.parse_args(argv)
            text = sys.stdin.read(65537)
            if len(text.encode()) > 65536:
                return
            value = hint(json.loads(text), args)
            if value:
                results.put(value)
        except BaseException:
            # Context is optional; argument, JSON, git, credential and network failures are silent.
            pass

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(timeout=0.9)
    if not thread.is_alive() and not results.empty():
        print(json.dumps(results.get_nowait(), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
