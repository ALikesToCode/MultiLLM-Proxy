"""Bounded deterministic transcript extraction; tool outputs are never copied."""
from collections import deque
import itertools
import json
from pathlib import Path
import re
import subprocess

from services.secret_scan import redact_payload, redact_text, scan_text

MAX_TRANSCRIPT_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_FILES_DISCOVERED = 20000


def clean(value, maximum=500):
    if not isinstance(value, str):
        return ""
    # Refuse oversized facts rather than leave a secret outside the scanner's bound.
    if len(value.encode("utf-8")) > MAX_LINE_BYTES:
        return "[oversized fact omitted]"
    value = redact_text(value, scan_text(value))
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)[:maximum]


def sanitized(value):
    result, report = redact_payload(value, mode="redact")
    if report["truncated"]:
        raise ValueError("Handoff exceeds secret scan bounds")
    return result


def records(path):
    consumed = 0
    with Path(path).open("rb") as stream:
        while consumed < MAX_TRANSCRIPT_BYTES:
            line = stream.readline(MAX_LINE_BYTES + 1)
            if not line:
                return
            consumed += len(line)
            if len(line) > MAX_LINE_BYTES or consumed > MAX_TRANSCRIPT_BYTES:
                raise ValueError("Transcript exceeds extraction bounds")
            try:
                value = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                continue
            if isinstance(value, dict):
                yield value
        if stream.read(1):
            raise ValueError("Transcript exceeds extraction bounds")


def cwd_matches(recorded, cwd):
    if not isinstance(recorded, str) or not recorded:
        return False
    try:
        return Path(recorded).resolve(strict=False) == Path(cwd).resolve()
    except (OSError, RuntimeError, ValueError, TypeError):
        return False


def prefix_matches(path, cwd, count, *, codex=False):
    try:
        with path.open("rb") as stream:
            for _ in range(count):
                line = stream.readline(MAX_LINE_BYTES + 1)
                if not line or len(line) > MAX_LINE_BYTES:
                    break
                try:
                    item = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    continue
                if not isinstance(item, dict):
                    continue
                value = item.get("payload") if codex and item.get("type") == "session_meta" else item if not codex else None
                if isinstance(value, dict) and cwd_matches(value.get("cwd"), cwd):
                    return True
    except OSError:
        pass
    return False


def newest_codex(directory, cwd):
    examined = 0
    dates = sorted(itertools.islice(directory.glob("*/*/*"), MAX_FILES_DISCOVERED), reverse=True)
    for date in dates:
        paths = sorted(itertools.islice(date.glob("rollout-*.jsonl"), MAX_FILES_DISCOVERED - examined), reverse=True)
        for path in paths:
            examined += 1
            if prefix_matches(path, cwd, 5, codex=True):
                return path
        if examined >= MAX_FILES_DISCOVERED:
            break
    return None


def discover(cwd, home=None, agent=None):
    home = Path(home or Path.home())
    cwd = str(Path(cwd).resolve())
    candidates = []
    if agent in (None, "claude"):
        projects = home / ".claude/projects"
        directory = projects / re.sub(r"[^A-Za-z0-9]", "-", cwd)
        if directory.is_dir():
            candidates.extend((path, "claude") for path in itertools.islice(directory.glob("*.jsonl"), MAX_FILES_DISCOVERED))
        else:
            for path in itertools.islice(projects.glob("*/*.jsonl"), MAX_FILES_DISCOVERED):
                if prefix_matches(path, cwd, 20):
                    candidates.append((path, "claude"))
    if agent in (None, "codex"):
        path = newest_codex(home / ".codex/sessions", cwd)
        if path:
            candidates.append((path, "codex"))
    if not candidates:
        raise ValueError("No matching transcript")
    return max(candidates, key=lambda pair: pair[0].stat().st_mtime)


def git(cwd, *args):
    try:
        result = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, timeout=2, check=False)
        if result.returncode == 0:
            return clean(result.stdout.decode("utf-8", "replace"), 4000).strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return ""


def project_identity(cwd, origin=None):
    origin = git(cwd, "remote", "get-url", "origin") if origin is None else origin
    # Drop credentials, ports and host names; only owner/name leaves this function.
    match = re.search(r"(?:[:/])([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$", origin)
    return ("/".join(match.groups()) if match else Path(cwd).resolve().name)[:200]


def message_text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(item.get("text", "") for item in content if isinstance(item, dict)
                         and item.get("type") in {"text", "input_text", "output_text"}
                         and isinstance(item.get("text"), str))
    return ""


def parse_arguments(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except ValueError:
            pass
    return {}


class Facts:
    def __init__(self):
        self.files = {}
        self.pending = {}
        self.sessions = {}
        self.failures = deque(maxlen=30)
        self.users = deque(maxlen=3)
        self.goal = ""
        self.final = ""
        self.thread_id = ""
        self.agent = "other"

    @staticmethod
    def remember(mapping, identifier, command):
        if len(mapping) >= 100 and identifier not in mapping:
            mapping.pop(next(iter(mapping)))
        mapping[identifier] = command

    def tool(self, name, value, identifier):
        if name in {"Edit", "Write", "MultiEdit", "NotebookEdit"}:
            path = clean(value.get("file_path") or value.get("notebook_path"))
            if path and len(self.files) < 100:
                self.files[path] = "Edited" if name != "Write" else "Written"
        if name in {"Bash", "exec_command", "shell", "shell_command"}:
            command = value.get("command", value.get("cmd", ""))
            if isinstance(command, list):
                command = " ".join(item for item in command if isinstance(item, str))
            command = clean(command)
            if command and isinstance(identifier, str):
                # Match only the latest bounded set of shell calls to their exits.
                self.remember(self.pending, identifier, command)
        if name == "write_stdin" and isinstance(identifier, str):
            session = value.get("session_id")
            if type(session) is int and session in self.sessions:
                self.remember(self.pending, identifier, self.sessions.pop(session))

    def patch(self, value):
        if not isinstance(value, str):
            return
        for match in itertools.islice(re.finditer(r"^\*\*\* (Add File|Update File|Delete File|Move to): (.+)$", value, re.M), 100):
            path = clean(match[2])
            if path and len(self.files) < 100:
                self.files[path] = match[1]

    def output(self, identifier, output, explicit=None, failed=False):
        command = self.pending.pop(identifier, None) if isinstance(identifier, str) else None
        if not command:
            return
        exit_code = explicit
        parsed = parse_arguments(output) if isinstance(output, str) else output
        if isinstance(parsed, dict) and "exit_code" in parsed:
            exit_code = parsed["exit_code"]
        elif isinstance(output, str):
            match = re.search(r"^(?:Process exited with code|Exit code|exit_code)[\s:\"]+(-?\d+)", output[:4096], re.I | re.M)
            if match:
                exit_code = int(match[1])
        if isinstance(parsed, dict) and type(parsed.get("session_id")) is int and exit_code is None:
            self.remember(self.sessions, parsed["session_id"], command)
        if type(exit_code) is int and exit_code != 0:
            self.failures.append({"command": command, "outcome": f"Exit {exit_code}"})
        elif failed:
            self.failures.append({"command": command, "outcome": "Tool reported failure"})

    def user(self, text):
        start = text.lstrip()
        if (not start or re.match(r"<[A-Za-z0-9_-]+(?:>| )", start)
                or start.startswith(("# AGENTS.md instructions", "[Request interrupted"))):
            return
        value = clean(text)
        if not self.goal:
            self.goal = value
        self.users.append(value)

    def claude(self, record):
        self.agent = "claude"
        self.thread_id = clean(record.get("sessionId", self.thread_id), 200)
        message = record.get("message", {})
        if not isinstance(message, dict):
            return
        content = message.get("content", [])
        text = message_text(content)
        if record.get("type") == "user" and not any(record.get(flag) is True for flag in ("isMeta", "isCompactSummary", "isSidechain")):
            self.user(text)
        elif record.get("type") == "assistant" and text:
            self.final = clean(text, 4000)
        if not isinstance(content, list):
            return
        for item in content[:100]:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "tool_use":
                self.tool(item.get("name"), parse_arguments(item.get("input")), item.get("id"))
            elif item.get("type") == "tool_result":
                self.output(item.get("tool_use_id"), message_text(item.get("content")), failed=item.get("is_error") is True)

    def codex(self, record):
        value = record.get("payload", {})
        if not isinstance(value, dict):
            return
        if record.get("type") == "session_meta":
            self.agent = "codex"
            self.thread_id = clean(value.get("id"), 200)
        if record.get("type") != "response_item":
            return
        kind = value.get("type")
        if kind == "message":
            text = message_text(value.get("content"))
            if value.get("role") == "user":
                self.user(text)
            elif value.get("role") == "assistant" and value.get("phase") in (None, "final_answer", "final") and text:
                self.final = clean(text, 4000)
        if kind in {"function_call", "custom_tool_call"}:
            if value.get("name", "").split(".")[-1] == "apply_patch":
                self.patch(value.get("input", value.get("arguments")))
            else:
                self.tool(value.get("name", "").split(".")[-1], parse_arguments(value.get("arguments")), value.get("call_id"))
        elif kind in {"function_call_output", "custom_tool_call_output"}:
            self.output(value.get("call_id"), value.get("output"))


def extract(path, cwd, agent=None):
    facts = Facts()
    for record in records(path):
        if "payload" in record:
            facts.codex(record)
        else:
            facts.claude(record)
    branch = git(cwd, "branch", "--show-current")[:200]
    head = git(cwd, "rev-parse", "HEAD")
    status = git(cwd, "status", "--short")
    section = {"goal": facts.goal or "Continue the task",
               "state": clean(facts.final) or "Transcript ended without a final response",
               "files": [{"path": path, "change": change} for path, change in facts.files.items()],
               "decisions": [clean("User: " + text) for text in facts.users],
               "failed_attempts": [clean(item["command"] + ": " + item["outcome"]) for item in facts.failures],
               "commands": [*facts.failures, {"command": "git rev-parse HEAD", "outcome": clean(head)},
                            {"command": "git status --short", "outcome": clean(status)}][-30:],
               "next_steps": [], "open_questions": []}
    source = {"agent": agent or facts.agent}
    if facts.thread_id:
        source["thread_id"] = facts.thread_id
    return sanitized({"branch": branch, "source": source, "sections": section, "summary": facts.final})
