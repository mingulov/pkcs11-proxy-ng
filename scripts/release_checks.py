#!/usr/bin/env python3
"""Inspect source-bound Cargo release archives."""

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from release.package_archives import inspect_archives  # noqa: E402
from release.package_model import ReleaseError  # noqa: E402


def main(argv=None, *, repo=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    archives = commands.add_parser("archives")
    archives.add_argument("--package-dir", required=True, type=Path)
    archives.add_argument("--expect-inventory", type=Path)
    args = parser.parse_args(argv)
    try:
        repo = Path(__file__).resolve().parents[1] if repo is None else Path(repo)
        inventory = inspect_archives(repo, args.package_dir)
        if args.expect_inventory:
            expected = json.loads(args.expect_inventory.read_text(encoding="utf-8"))
            if expected != inventory:
                raise ReleaseError("inventory differs from expected source/version/package checksums")
            if args.expect_inventory.resolve() == (args.package_dir / "inventory.json").resolve():
                print(f"archives: verified {len(inventory['packages'])} packages against existing inventory")
                return 0
        inspect_archives(repo, args.package_dir, write=True)
        print(f"archives: verified {len(inventory['packages'])} packages at {inventory['source_commit']}")
        return 0
    except (ReleaseError, OSError, ValueError) as exc:
        print(f"release check failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
