#!/usr/bin/env python3
"""Verify release archives, source refs, CI results, and staging probes."""

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from release.package_archives import inspect_archives  # noqa: E402
from release.package_binaries import build_binaries  # noqa: E402
from release.package_consumers import archive_consumer, registry_consumer  # noqa: E402
from release.package_model import ReleaseError  # noqa: E402
from release.package_refs import preflight, verify_ci_results  # noqa: E402
from release.package_registry import Registry, publication_state, read_inventory, verify_publication  # noqa: E402
from release.package_staging import staging_probe  # noqa: E402


def main(argv=None, *, repo=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    archives = commands.add_parser("archives")
    archives.add_argument("--package-dir", required=True, type=Path)
    archives.add_argument("--expect-inventory", type=Path)
    consumer = commands.add_parser("consumer")
    consumer.add_argument("--package-dir", required=True, type=Path)
    consumer.add_argument("--toolchain", default="1.88.0")
    state = commands.add_parser("registry-state")
    state.add_argument("--inventory", required=True, type=Path)
    state.add_argument("--package", default="workspace")
    verify = commands.add_parser("registry-verify")
    verify.add_argument("--inventory", required=True, type=Path)
    verify.add_argument("--package")
    registry_build = commands.add_parser("registry-consumer")
    registry_build.add_argument("--inventory", required=True, type=Path)
    registry_build.add_argument("--toolchain", default="1.88.0")
    binary = commands.add_parser("binary-build")
    binary.add_argument("--inventory", required=True, type=Path)
    binary.add_argument("--package-dir", required=True, type=Path)
    binary.add_argument("--source", required=True, choices=("archive", "registry"))
    binary.add_argument("--target", required=True,
                        choices=("x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"))
    binary.add_argument("--output", required=True, type=Path)
    binary.add_argument("--toolchain", default="1.98.1")
    refs = commands.add_parser("preflight")
    refs.add_argument("--ref", required=True)
    refs.add_argument("--require-main", action="store_true")
    refs.add_argument("--mode", default="dry-run")
    refs.add_argument("--package", default="workspace")
    refs.add_argument("--qualification-url")
    refs.add_argument("--qualification-subject")
    probe = commands.add_parser("staging-probe")
    probe.add_argument("--destination", required=True, type=Path)
    probe.add_argument("--run-id", required=True)
    probe.add_argument("--attempt", required=True)
    probe.add_argument("--registry", default="staging")
    ci = commands.add_parser("ci-results")
    ci.add_argument("--needs-json", required=True)
    args = parser.parse_args(argv)
    try:
        repo = Path(__file__).resolve().parents[1] if repo is None else Path(repo)
        if args.command == "preflight":
            version, head, frozen_parent = preflight(
                repo, args.ref, args.require_main, args.mode, args.package,
                args.qualification_subject, args.qualification_url)
            print(f"preflight: package {args.package} version {version}; tag commit {head}; "
                  f"frozen parent {frozen_parent}")
            return 0
        if args.command == "staging-probe":
            version = staging_probe(repo, args.destination, args.run_id,
                                    args.attempt, args.registry)
            print(f"staging probe: {args.destination} version {version}")
            return 0
        if args.command == "ci-results":
            count = verify_ci_results(args.needs_json)
            print(f"ci-results: {count} required jobs succeeded")
            return 0
        if args.command == "consumer":
            result = archive_consumer(repo, args.package_dir, args.toolchain)
            print(json.dumps({"consumer": result}, sort_keys=True))
            return 0
        if args.command == "registry-state":
            result = publication_state(read_inventory(args.inventory), args.package, Registry())
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.command == "registry-verify":
            result = verify_publication(read_inventory(args.inventory), Registry(),
                                        selected=args.package)
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.command == "registry-consumer":
            result = registry_consumer(repo, args.inventory, args.toolchain)
            print(json.dumps({"registry_consumer": result}, sort_keys=True))
            return 0
        if args.command == "binary-build":
            result = build_binaries(repo, args.inventory, args.package_dir, args.source,
                                    args.target, args.output, args.toolchain)
            print(json.dumps({"binary_build": result}, sort_keys=True))
            return 0
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
