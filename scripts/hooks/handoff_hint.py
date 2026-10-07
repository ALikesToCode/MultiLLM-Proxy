#!/usr/bin/env python3
"""Optional SessionStart context for Claude Code and Codex; silent within one second."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import queue
import shlex
import sys
import threading

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from handoff import load
from handoff_contracts import render

# A live handoff read takes about 0.7 s, so leave headroom within the 2 s hook timeout.
TIMEOUT = 1.5


def clipped(value, maximum):
    return value.encode("utf-8")[:maximum].decode("utf-8", "ignore")


def pointer(record, age):
    project, branch = record["project"], record.get("branch", "")
    title = " ".join(record["title"].split())[:120]
    duration = f"{int(age // 3600)} hours" if age >= 3600 else f"{int(age // 60)} minutes"
    command = "python3 " + shlex.quote(str(ROOT / "scripts/handoff.py")) + " load"
    query = json.dumps({"project": project, "branch": branch}, ensure_ascii=False)
    action = ("If this session continues that task, load it with knowledge_handoff_get " + query
              + f" or run {command}.")
    def message(project, branch, title, action):
        return (f'Handoff available for {project} ({branch}) from {record["source"]["agent"]}, '
                f'{duration} ago: "{title}". {action}')
    text = message(project, branch, title, action)
    if len(text.encode("utf-8")) > 600:
        # CLI loading preserves complete identities when they exceed the pointer budget.
        action = f"If this session continues that task, run {command}."
        budget = max(0, 600 - len(message("", "", "", action).encode("utf-8")))
        labels = []
        for value, maximum in ((project, 64), (branch, 64), (title, 160)):
            label = clipped(value, min(maximum, budget))
            labels.append(label)
            budget -= len(label.encode("utf-8"))
        text = message(*labels, action)
    return text


def hint(event, args, *, fetch=load, now=None):
    if not isinstance(event, dict) or event.get("hook_event_name") != "SessionStart":
        return None
    if event.get("source", "startup") not in {"startup", "clear"}:
        return None
    if not isinstance(event.get("cwd"), str):
        return None
    args.cwd = event["cwd"]
    record = fetch(args, timeout=TIMEOUT).get("record")
    if not isinstance(record, dict):
        return None
    created = datetime.fromisoformat(record["created_at"].replace("Z", "+00:00"))
    current = now or datetime.now(timezone.utc)
    age = (current - created).total_seconds()
    expires = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
    if not 0 <= age < 48 * 3600 or expires <= current:
        return None
    markdown = render(record) if getattr(args, "mode", "pointer") == "full" else pointer(record, age)
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
            parser.add_argument("--mode", choices=("pointer", "full"), default="pointer")
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
    thread.join(timeout=TIMEOUT + 0.1)
    if not thread.is_alive() and not results.empty():
        print(json.dumps(results.get_nowait(), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
