#!/usr/bin/env python3
"""Validate version-1 portable release evidence; see doc/release/evidence-schema.md."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import sys


KINDS = (
    "environment", "build", "direct-provider", "proxy-provider", "comparison",
    "abi", "transport", "privacy", "performance", "package", "standalone",
)
IDENTITIES = ("framework", "corpora", "provider", "config", "selection")
WINDOWS_DEVICES = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {
    prefix + number for prefix in ("COM", "LPT") for number in "123456789¹²³"
}


class ReceiptError(ValueError):
    """Invalid receipt, binding, or referenced evidence."""


def _object(value, label, fields=None):
    if not isinstance(value, dict):
        raise ReceiptError(f"{label} must be an object")
    if fields is not None:
        missing = set(fields) - value.keys()
        unknown = value.keys() - set(fields)
        if missing:
            raise ReceiptError(f"{label} missing fields: {', '.join(sorted(missing))}")
        if unknown:
            raise ReceiptError(f"{label} unknown fields: {', '.join(sorted(unknown))}")
    return value


def _text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ReceiptError(f"{label} must be a nonempty string")
    return value


def _digest(value, label, lengths=(64,)):
    _text(value, label)
    if len(value) not in lengths or re.fullmatch(r"[0-9a-f]+", value) is None:
        raise ReceiptError(f"{label} must be a full lowercase hex digest")


def _portable_parts(name, label, seen_paths):
    parts = name.split("/")
    for part in parts:
        if (part in ("", ".", "..") or part.endswith((".", " "))
                or any(ord(char) < 32 or ord(char) == 127 or char in '<>:"\\|?*'
                       for char in part)
                or part.split(".", 1)[0].rstrip(" ").upper() in WINDOWS_DEVICES):
            raise ReceiptError(f"{label}.path must be a portable relative artifact path")
    # Trailing-dot/space normalization is unnecessary because those names are
    # forbidden above. Casefolding deliberately applies identically on every OS.
    normalized = name.casefold()
    previous = seen_paths.setdefault(normalized, name)
    if previous != name:
        raise ReceiptError(f"{label}.path has a portable path collision: {previous!r}, {name!r}")
    return parts


def _artifact(reference, root, label, seen_paths):
    _object(reference, label, ("path", "sha256"))
    name = _text(reference["path"], f"{label}.path")
    _digest(reference["sha256"], f"{label}.sha256")
    parts = _portable_parts(name, label, seen_paths)
    path = root
    try:
        for part in parts:
            path = path / part
            if path.is_symlink():
                raise ReceiptError(f"{label}.path contains a symlink")
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise ReceiptError(f"{label}.path escapes artifact root")
        if not stat.S_ISREG(resolved.stat().st_mode):
            raise ReceiptError(f"{label}.path is not a regular artifact file")
        digest = hashlib.sha256()
        with resolved.open("rb") as artifact:
            for block in iter(lambda: artifact.read(1024 * 1024), b""):
                digest.update(block)
    except (OSError, ValueError, RuntimeError) as error:
        if isinstance(error, ReceiptError):
            raise
        raise ReceiptError(f"{label} artifact path cannot be read: {error}") from error
    if digest.hexdigest() != reference["sha256"]:
        raise ReceiptError(f"{label} artifact sha256 mismatch: {name}")


def validate_receipt(receipt, artifact_root, *, expected_commit=None,
                     expected_tree=None, expected_lock_sha256=None,
                     require_candidate=False):
    """Raise ReceiptError unless the envelope, bindings and artifact bytes validate."""
    _object(receipt, "receipt", (
        "schema_version", "kind", "classification", "source", "toolchain",
        "binaries", "identities", "completion", "artifacts",
    ))
    if type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1:
        raise ReceiptError("unsupported schema_version")
    if receipt["kind"] not in KINDS:
        raise ReceiptError("unsupported receipt kind")
    classification = receipt["classification"]
    if classification not in ("diagnostic", "candidate-bound"):
        raise ReceiptError("unsupported classification")
    if require_candidate and classification != "candidate-bound":
        raise ReceiptError("diagnostic evidence cannot satisfy a candidate gate")
    if classification == "candidate-bound" and any(
        value is None for value in (expected_commit, expected_tree, expected_lock_sha256)
    ):
        raise ReceiptError("candidate evidence requires expected source commit, tree and lock sha256")

    source = _object(receipt["source"], "source", ("commit", "tree", "lock"))
    _object(source["lock"], "source.lock", ("path", "sha256"))
    for field, actual, expected, lengths in (
        ("commit", source["commit"], expected_commit, (40, 64)),
        ("tree", source["tree"], expected_tree, (40, 64)),
        ("lock.sha256", source["lock"]["sha256"], expected_lock_sha256, (64,)),
    ):
        _digest(actual, f"source.{field}", lengths)
        if expected is not None:
            _digest(expected, f"expected {field}", lengths)
            if actual != expected:
                raise ReceiptError(f"source.{field} mismatch with expected candidate binding")

    toolchain = _object(receipt["toolchain"], "toolchain", ("rustc", "cargo", "target"))
    for key, value in toolchain.items():
        _text(value, f"toolchain.{key}")
    completion = _object(receipt["completion"], "completion", ("complete", "outcome"))
    complete, outcome = completion["complete"], completion["outcome"]
    if type(complete) is not bool or outcome not in ("passed", "failed", "incomplete"):
        raise ReceiptError("completion requires a boolean complete and known outcome")
    if (outcome == "passed" and not complete) or (outcome == "incomplete" and complete):
        raise ReceiptError("completion and outcome are inconsistent")
    if classification == "candidate-bound" and (not complete or outcome != "passed"):
        raise ReceiptError("candidate completion requires complete=true and outcome=passed")

    binaries = _object(receipt["binaries"], "binaries")
    identities = _object(receipt["identities"], "identities", IDENTITIES)
    artifacts = _object(receipt["artifacts"], "artifacts")
    if not artifacts:
        raise ReceiptError("artifacts must contain evidence")
    try:
        root = Path(artifact_root).resolve(strict=True)
        if not root.is_dir():
            raise ReceiptError("artifact root must be a directory")
    except (OSError, ValueError, RuntimeError) as error:
        raise ReceiptError(f"invalid artifact root: {error}") from error
    seen_paths = {}
    _artifact(source["lock"], root, "source.lock", seen_paths)
    for group, entries in (("binaries", binaries), ("artifacts", artifacts)):
        for role, reference in entries.items():
            _text(role, f"{group} role")
            _artifact(reference, root, f"{group}.{role}", seen_paths)
    for role, reference in identities.items():
        label = f"identities.{role}"
        _object(reference, label)
        if "not_applicable" in reference:
            _object(reference, label, ("not_applicable",))
            _text(reference["not_applicable"], f"{label}.not_applicable")
        else:
            _artifact(reference, root, label, seen_paths)


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ReceiptError(f"nonstandard JSON constant: {value}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path, help="JSON receipt to validate")
    parser.add_argument("--artifact-root", required=True, type=Path,
                        help="immutable directory containing all referenced artifacts")
    parser.add_argument("--require-candidate", action="store_true",
                        help="reject diagnostic evidence")
    parser.add_argument("--source-commit", help="independent expected source commit")
    parser.add_argument("--source-tree", help="independent expected source tree")
    parser.add_argument("--lock-sha256", help="independent expected Cargo.lock digest")
    args = parser.parse_args(argv)
    try:
        with args.receipt.open(encoding="utf-8") as stream:
            receipt = json.load(stream, object_pairs_hook=_unique_keys,
                                parse_constant=_invalid_constant)
        validate_receipt(
            receipt, args.artifact_root, expected_commit=args.source_commit,
            expected_tree=args.source_tree, expected_lock_sha256=args.lock_sha256,
            require_candidate=args.require_candidate,
        )
    except (ReceiptError, OSError, UnicodeError, ValueError, RecursionError) as error:
        print(f"invalid receipt: {error}", file=sys.stderr)
        return 1
    print(f"valid {receipt['classification']} {receipt['kind']} receipt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
