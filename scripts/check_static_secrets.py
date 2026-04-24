#!/usr/bin/env python3
import math
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent

SCAN_ROOTS = [
    REPO_ROOT / "static",
    REPO_ROOT / "templates",
    REPO_ROOT / ".env.example",
]

FORBIDDEN_PATTERNS = [
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE),
    re.compile(r"\bADMIN_API_KEY\b"),
    re.compile(r"\bapiKey\s*=", re.IGNORECASE),
]

HIGH_ENTROPY_PATTERN = re.compile(r"['\"]([A-Za-z0-9+/=_-]{32,})['\"]")

ALLOWLISTED_ENV_PLACEHOLDERS = {
    "ADMIN_API_KEY",
}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def iter_files():
    for root in SCAN_ROOTS:
        if root.is_file():
            yield root
        elif root.is_dir():
            for path in root.rglob("*"):
                if path.is_file():
                    yield path


def is_allowlisted(path: Path, match_text: str) -> bool:
    if match_text.strip().upper() == "BEARER YOUR_API_KEY":
        return True
    if path.name == ".env.example":
        return any(name in match_text for name in ALLOWLISTED_ENV_PLACEHOLDERS)
    return False


def main() -> int:
    findings = []
    for path in iter_files():
        if path.suffix.lower() in {".ico", ".png", ".jpg", ".jpeg", ".webp"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        for pattern in FORBIDDEN_PATTERNS:
            for match in pattern.finditer(text):
                if not is_allowlisted(path, match.group(0)):
                    findings.append(f"{path}: forbidden secret-like pattern: {match.group(0)[:24]}")

        for match in HIGH_ENTROPY_PATTERN.finditer(text):
            value = match.group(1)
            if shannon_entropy(value) >= 4.5 and not is_allowlisted(path, value):
                findings.append(f"{path}: high entropy literal: {value[:12]}...")

    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
