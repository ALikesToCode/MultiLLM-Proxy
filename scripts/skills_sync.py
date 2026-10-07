#!/usr/bin/env python3
"""Upload a bounded operator skills library; retain root-specific sync receipts."""

import argparse
import base64
import hashlib
from itertools import islice
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import urllib.parse
import urllib.request

# Only the local detector is shared; no application initialization or dotenv loading.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.secret_scan import scan_text

ROOTS = ("claude", "claude-library", "codex", "agents")
DEFAULT_ROOTS = dict(zip(ROOTS, ("~/.claude/skills", "~/.claude/skills-library", "~/.codex/skills", "~/.agents/skills")))
MAX_BATCH_BYTES = 8 * 1024 * 1024 - 4096
USER_AGENT = "multillm-skills/1"
MAX_SKILLS = 2000
# Mirrors worker/knowledge/skills-validation.mjs. Only SKILL.md limits reject a skill;
# extra files over a limit are skipped and counted, so large skills still sync their instructions.
SKILL_FILE_BYTES = 128 * 1024
FILE_BYTES = 256 * 1024
SKILL_BYTES = 5 * 1024 * 1024
MAX_FILES = 40
MAX_REFERENCES = 200


class PlanError(ValueError):
    pass


def secret_types(text):
    return sorted({item["type"] for item in scan_text("skill file\n" + text) if item["confidence"] == "high"})


def frontmatter(text):
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        raise PlanError("missing_frontmatter")
    try:
        end = lines.index("---", 1)
    except ValueError:
        raise PlanError("missing_frontmatter") from None
    fields = {}
    index = 1
    while index < end:
        line = lines[index]
        match = re.match(r"^(name|description):\s*(.*)$", line)
        index += 1
        if not match:
            continue
        key, value = match.groups()
        if key in fields:
            raise PlanError("duplicate_frontmatter")
        if value in {"|", "|-", "|+", ">", ">-", ">+"}:
            parts = []
            while index < end and (not lines[index].strip() or lines[index].startswith((" ", "\t"))):
                parts.append(lines[index].strip())
                index += 1
            value = (" " if value.startswith(">") else "\n").join(parts).strip()
        elif value.startswith('"'):
            try:
                value = json.loads(value)
            except ValueError:
                raise PlanError("invalid_frontmatter") from None
        elif value.startswith("'") and value.endswith("'"):
            value = value[1:-1].replace("''", "'")
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        if not isinstance(value, str) or not value.strip() or re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", value):
            raise PlanError("invalid_frontmatter")
        # API metadata is one line; retain the original SKILL.md bytes and hash.
        fields[key] = " ".join(value.split())
    if set(fields) != {"name", "description"} or len(fields["name"]) > 100 or len(fields["description"]) > 2000:
        raise PlanError("invalid_frontmatter")
    return fields


def slug(name):
    import unicodedata
    return re.sub(r"[^a-z0-9]+", "-", unicodedata.normalize("NFKD", name.lower())).strip("-")


def referenced(text):
    links = re.findall(r"\[[^]\n]*\]\(([^)\s]+)(?:[^)]*)\)", text)
    code = re.findall(r"`([^`\n]+)`", text)
    paths = re.findall(r"(?<![\w:/])(?:scripts|references|assets|templates|examples)/[\w./*-]+", text)
    return [value.removeprefix("./").split("#", 1)[0] for value in links + code + paths
            if not urllib.parse.urlsplit(value).scheme]


def collect_skill(directory, root, skipped_files=None):
    skipped_files = skipped_files if skipped_files is not None else []
    directory = directory.resolve()
    queue = ["SKILL.md"]
    seen, files, dropped = set(), [], set()
    total = 0
    metadata = None

    def enqueue(entry):
        if entry in seen or entry in queue:
            return
        if len(queue) + len(seen) >= MAX_REFERENCES:
            dropped.add(entry)
            return
        queue.append(entry)

    while queue:
        relative = queue.pop(0)
        if relative in seen:
            continue
        seen.add(relative)
        main = relative == "SKILL.md"
        path = directory / relative
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            if relative == "SKILL.md":
                raise PlanError("missing_skill") from None
            continue
        if not resolved.is_relative_to(directory):
            skipped_files.append(relative)
            continue
        if resolved.is_dir():
            if relative == "SKILL.md":
                raise PlanError("invalid_file")
            # Only directories explicitly referenced by a loaded file are explored.
            for child in sorted(islice(path.iterdir(), MAX_REFERENCES + 1)):
                enqueue(str(child.relative_to(directory)))
            continue
        if not resolved.is_file():
            if main:
                raise PlanError("invalid_file")
            skipped_files.append(relative)
            continue
        if len(relative) > 240 or re.search(r"[\\\x00-\x1f\x7f:%?#]", relative) or len(files) >= MAX_FILES:
            skipped_files.append(relative)
            continue
        maximum = SKILL_FILE_BYTES if main else FILE_BYTES
        with resolved.open("rb") as handle:
            content = handle.read(maximum + 1)
        if main and len(content) > maximum:
            raise PlanError("skill_limits")
        if len(content) > maximum or total + len(content) > SKILL_BYTES:
            skipped_files.append(relative)
            continue
        total += len(content)
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            if relative == "SKILL.md":
                raise PlanError("invalid_utf8") from None
            text = content.decode("latin-1")
            encoding = {"content_base64": base64.b64encode(content).decode("ascii")}
        else:
            encoding = {"content": text}
            binary = {"content_base64": base64.b64encode(content).decode("ascii")}
            # Escaped control characters can otherwise exceed the encoded batch bound.
            if len(json.dumps(encoding, ensure_ascii=False).encode()) > len(json.dumps(binary).encode()):
                encoding = binary
            # Resolve links relative to the file containing them.
            for reference in referenced(text):
                reference_path = Path(reference)
                # Mentions of external paths are not files belonging to this skill.
                if reference_path.is_absolute() or reference.startswith("~") or ".." in reference_path.parts:
                    continue
                candidate = directory / Path(relative).parent / reference_path
                if candidate.exists():
                    # Preserve the lexical path so collection can skip/count escaping symlinks.
                    enqueue(str(candidate.relative_to(directory)))
        types = secret_types(text)
        if types:
            raise PlanError("secret_detected:" + relative + ":" + ",".join(types))
        if relative == "SKILL.md":
            metadata = frontmatter(text)
            if secret_types(metadata["name"] + ": " + metadata["description"]):
                raise PlanError("secret_detected:SKILL.md:metadata")
        files.append({"path": relative, "sha256": hashlib.sha256(content).hexdigest(), **encoding})
    skipped_files.extend(sorted(dropped))
    if metadata is None:
        raise PlanError("missing_skill")
    identity = slug(metadata["name"])
    if not identity or len(identity) > 100:
        raise PlanError("invalid_slug")
    return {"root": root, "skill_id": identity, **metadata, "files": sorted(files, key=lambda file: file["path"])}


def build_plan(roots, previous):
    skills, rejected, present = [], [], {root: set() for root in roots}
    available, identities = set(), {}
    duplicates, conflicts, skipped_files = 0, [], []
    for root, raw in roots.items():
        path = Path(raw).expanduser()
        if not path.is_dir():
            rejected.append({"root": root, "reason": "root_unavailable"})
            continue
        available.add(root)
        directories = sorted(islice(path.iterdir(), 10001))
        if len(directories) > 10000:
            raise PlanError("root_entries_limit")
        for directory in directories:
            if not directory.is_dir() or not (directory / "SKILL.md").is_file():
                continue
            identity = directory.name
            try:
                if not (directory / "SKILL.md").resolve().is_relative_to(directory.resolve()):
                    skipped_files.append("SKILL.md")
                    available.discard(root)
                    continue
                # Keep invalid or secret-bearing local skills from deleting their last safe revision.
                with (directory / "SKILL.md").open("rb") as handle:
                    raw_skill = handle.read(SKILL_FILE_BYTES + 1)
                if len(raw_skill) > SKILL_FILE_BYTES:
                    raise PlanError("skill_limits")
                identity = slug(frontmatter(raw_skill.decode("utf-8"))["name"])
                present[root].add(identity)
                content_hash = hashlib.sha256(raw_skill).hexdigest()
                if identity in identities:
                    kept = identities[identity]
                    if content_hash == kept["hash"]:
                        duplicates += 1
                    else:
                        conflicts.append({"skill_id": identity, "reason": "duplicate_conflict",
                                          "kept_root": kept["root"], "skipped_root": root})
                    continue
                skill = collect_skill(directory, root, skipped_files)
                if len(skills) >= MAX_SKILLS:
                    raise PlanError("skills_limit")
                identities[skill["skill_id"]] = {"root": root, "hash": content_hash}
                skills.append(skill)
            except (OSError, UnicodeError, PlanError) as error:
                # Any unreadable entry disables pruning for its root.
                available.discard(root)
                reason = str(error) if isinstance(error, PlanError) else "unreadable_skill"
                rejected.append({"root": root, "skill_id": identity, "reason": reason})
    deletes = sorted({identity for root in available for identity in previous.get(root, [])
                      if identity not in present[root] and identity not in identities})
    return {"skills": skills, "delete": deletes, "rejected": rejected, "duplicates": duplicates,
            "conflicts": conflicts, "skipped_files": len(skipped_files)}


def batches(plan):
    current = []
    for skill in plan["skills"]:
        candidate = {"skills": current + [skill]}
        if current and (len(current) >= 16 or len(json.dumps(candidate, ensure_ascii=False).encode()) > MAX_BATCH_BYTES):
            yield {"skills": current}
            current = []
        if len(json.dumps({"skills": [skill]}, ensure_ascii=False).encode()) > MAX_BATCH_BYTES:
            raise PlanError("batch_bytes_limit")
        current.append(skill)
    if current:
        yield {"skills": current}
    for offset in range(0, len(plan["delete"]), MAX_SKILLS):
        yield {"skills": [], "delete": plan["delete"][offset:offset + MAX_SKILLS]}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def sync_batch(base_url, key, payload):
    url = urllib.parse.urlsplit(base_url)
    if (url.username or url.password or url.query or url.fragment
            or url.scheme != "https" and not (url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1", "::1"})):
        raise PlanError("invalid_base_url")
    request = urllib.request.Request(base_url.rstrip("/") + "/v1/knowledge/skills",
                                     data=json.dumps(payload, ensure_ascii=False).encode(), method="POST",
                                     headers={"Authorization": "Bearer " + key, "Content-Type": "application/json", "User-Agent": USER_AGENT})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=55) as response:
        raw = response.read(1048577)
    if len(raw) > 1048576:
        raise PlanError("response_limit")
    result = json.loads(raw)
    if not isinstance(result, dict) or not isinstance(result.get("results"), list):
        raise PlanError("invalid_response")
    return result["results"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="append", metavar="LABEL=PATH")
    parser.add_argument("--base-url", default=os.environ.get("MULTILLM_BASE_URL"))
    parser.add_argument("--key-file", type=Path)
    parser.add_argument("--state-file", type=Path, default=Path.home() / ".config/multillm/skills-sync-state.json")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        roots = DEFAULT_ROOTS if not args.root else dict(item.split("=", 1) for item in args.root)
        if set(roots) - set(ROOTS):
            raise PlanError("invalid_root")
        if args.state_file.exists():
            with args.state_file.open("rb") as handle:
                state = handle.read(1048577)
            if len(state) > 1048576:
                raise PlanError("state_bytes_limit")
            previous = json.loads(state)
        else:
            previous = {}
        if not isinstance(previous, dict) or any(root not in ROOTS or not isinstance(ids, list) or len(ids) > MAX_SKILLS
                                                or any(not isinstance(identity, str) or len(identity) > 100 or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", identity) for identity in ids) for root, ids in previous.items()):
            raise PlanError("invalid_state")
        plan = build_plan(roots, previous)
        if args.dry_run:
            print(json.dumps({"skills": [{"root": item["root"], "skill_id": item["skill_id"], "files": [file["path"] for file in item["files"]]} for item in plan["skills"]],
                              "delete": plan["delete"], "rejected": plan["rejected"], "duplicates": plan["duplicates"],
                              "conflicts": plan["conflicts"], "skipped_files": plan["skipped_files"]}, indent=2))
            return 0
        key = args.key_file.read_text().strip() if args.key_file else os.environ.get("MULTILLM_KNOWLEDGE_API_KEY")
        if not key or not args.base_url:
            raise PlanError("base_url_and_key_required")
        by_id = {item["skill_id"]: item for item in plan["skills"]}
        counts = {status: 0 for status in ("created", "updated", "unchanged", "deleted", "rejected")}
        rejected = list(plan["rejected"])
        for batch in batches(plan):
            results = sync_batch(args.base_url, key, batch)
            expected = {item["skill_id"] for item in batch["skills"]} | set(batch.get("delete", []))
            if ({item.get("skill_id") for item in results} != expected or len(results) != len(expected)
                    or any(item.get("status") not in {"created", "updated", "unchanged", "deleted", "rejected"} for item in results)):
                raise PlanError("invalid_receipts")
            for result in results:
                status, identity = result["status"], result["skill_id"]
                counts[status] += 1
                if status == "rejected":
                    rejected.append({"skill_id": identity, "reason": result.get("reason", "rejected")})
                if status in {"created", "updated", "unchanged"} and identity in by_id:
                    root = by_id[identity]["root"]
                    previous[root] = sorted(set(previous.get(root, [])) | {identity})
                elif status in {"deleted", "unchanged"} and identity in batch.get("delete", []):
                    previous = {root: [value for value in ids if value != identity] for root, ids in previous.items()}
            args.state_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(mode="w", dir=args.state_file.parent, prefix=".skills-receipt-", delete=False) as handle:
                temporary = Path(handle.name)
                os.fchmod(handle.fileno(), 0o600)
                handle.write(json.dumps(previous, indent=2) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.replace(temporary, args.state_file)
            finally:
                temporary.unlink(missing_ok=True)
        print(json.dumps({"synced": counts, "local_rejected": len(plan["rejected"]), "rejected": rejected,
                          "duplicates": plan["duplicates"], "conflicts": plan["conflicts"], "skipped_files": plan["skipped_files"]}))
        return 0
    except Exception:
        # HTTP failures may include private request URLs or credential headers.
        print("Skills sync failed; local receipts preserved. Check roots, configuration and service availability.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
