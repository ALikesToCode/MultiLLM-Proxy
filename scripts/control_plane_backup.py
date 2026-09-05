"""Offline encrypted backup and empty-target migration. Never prints records."""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.control_plane_backup import read_backup, restore_empty, validate, write_backup


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("backup", "check", "restore-empty"))
    parser.add_argument("path", type=Path)
    parser.add_argument("--apply", action="store_true", help="Required to restore into an empty destination")
    args = parser.parse_args()
    key = os.environ.get("CONTROL_PLANE_BACKUP_KEY", "").encode()
    if not key:
        parser.error("Set CONTROL_PLANE_BACKUP_KEY to a Fernet key through your secret manager")
    if args.operation == "restore-empty" and not args.apply:
        parser.error("Restoration requires --apply and a stopped application with an empty destination")
    try:
        if args.operation == "backup":
            counts = write_backup(args.path, key)
        else:
            document = read_backup(args.path, key)
            counts = restore_empty(document) if args.operation == "restore-empty" else validate(document)
    except Exception as error:
        print(f"Operation failed ({type(error).__name__}); no records or credentials logged", file=sys.stderr)
        return 1
    print(json.dumps({"operation": args.operation, "row_counts": counts}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
