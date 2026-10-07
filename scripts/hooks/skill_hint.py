#!/usr/bin/env python3
"""Optional UserPromptSubmit context for Claude Code and Codex; errors stay silent."""

import argparse
import json
import contextlib
import io
import math
import os
import queue
import re
import sys
import threading
import time
import urllib.parse
import urllib.request

TIMEOUT = 0.8
MIN_SCORE = 0.2
MAX_CONTEXT_BYTES = 600


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(prompt, base_url, key):
    url = urllib.parse.urlsplit(base_url)
    if (url.username or url.password or url.query or url.fragment
            or url.scheme != "https" and not (url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1", "::1"})):
        return []
    query = urllib.parse.urlencode({"query": prompt[:2000], "mode": "fast", "limit": 3})
    request = urllib.request.Request(base_url.rstrip("/") + "/v1/knowledge/skills?" + query,
                                     headers={"Authorization": "Bearer " + key})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=TIMEOUT) as response:
        raw = response.read(32769)
    if len(raw) > 32768:
        return []
    return json.loads(raw)


def context(results):
    if not isinstance(results, list):
        return ""
    lines = []
    for item in results[:3]:
        if not isinstance(item, dict):
            continue
        score = item.get("score")
        identity = item.get("skill_id", "")
        name, description = item.get("name"), item.get("description")
        if (not isinstance(score, (float, int)) or isinstance(score, bool) or not math.isfinite(score) or score < MIN_SCORE
                or not isinstance(identity, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", identity) or len(identity) > 100
                or not isinstance(name, str) or not isinstance(description, str)):
            continue
        clean = lambda value: " ".join(value.split())
        line = f"{clean(name)[:60]} - {clean(description)[:100]} (load with knowledge_skills_get skill_id={identity})"
        candidate = "Relevant skills: " + "; ".join(lines + [line])
        if len(candidate.encode()) <= MAX_CONTEXT_BYTES:
            lines.append(line)
    return "Relevant skills: " + "; ".join(lines) if lines else ""


def hint(event, agent=None, *, fetcher=fetch, deadline=None):
    deadline = deadline or time.monotonic() + TIMEOUT - 0.05
    if not isinstance(event, dict) or event.get("hook_event_name", "UserPromptSubmit") != "UserPromptSubmit":
        return None
    prompt = event.get("prompt")
    if not isinstance(prompt, str) or len(prompt.strip()) < 12:
        return None
    agent = agent or ("codex" if "turn_id" in event else "claude")
    if agent not in {"claude", "codex"}:
        return None
    base_url, key = os.environ.get("MULTILLM_BASE_URL"), os.environ.get("MULTILLM_KNOWLEDGE_API_KEY")
    if not base_url or not key:
        return None
    results = queue.Queue(maxsize=1)
    def run():
        try:
            results.put(fetcher(prompt, base_url, key))
        except Exception:
            results.put([])
    # Socket timeouts reset after reads and DNS may block: enforce a total wall deadline.
    threading.Thread(target=run, daemon=True).start()
    try:
        value = results.get(timeout=max(0, deadline - time.monotonic()))
    except queue.Empty:
        return None
    additional = context(value)
    if not additional:
        return None
    return {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": additional}}


def main():
    deadline = time.monotonic() + TIMEOUT - 0.05
    try:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--agent", choices=("claude", "codex"))
        with contextlib.redirect_stderr(io.StringIO()):
            args = parser.parse_args()
        raw = sys.stdin.read(65537)
        if len(raw.encode()) > 65536:
            return 0
        output = hint(json.loads(raw), args.agent, deadline=deadline)
        if output and time.monotonic() < deadline:
            print(json.dumps(output, ensure_ascii=False))
    except BaseException:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
