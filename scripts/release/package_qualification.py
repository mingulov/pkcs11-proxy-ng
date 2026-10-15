"""Pre-publication provider-qualification gate (Q12/RO-02).

Validates that a release's provider qualification evidence is
immutable, complete, and bound to the frozen source — before any
publication credential use or external mutation. A quality-only URL,
a mutable or unbound provider record, a missing provider row, an
incomplete or failed comparison, a wrong source/tree/lock, a changed
referenced artifact, or a mismatched framework/provider/config/test
selection all refuse.

The gate consumes a local evidence directory (downloaded read-only
from the immutable ``provider-qualification`` artifact of the
qualification run named by the ``qualification-run-id`` workflow
input)::

    evidence/
      receipt.json          # portable candidate-bound comparison receipt
      bundle/
        Cargo.lock
        framework.json corpora.json provider.json config.json
        selection.json comparison.json pool-evidence.json

Every expectation (source commit/tree/lock, framework commit, run
identity, receipt/record digests, qualification URL) is supplied
independently of the record being validated — from workflow inputs
and the release checkout's own git objects, never copied out of the
record. See ``doc/release/qualification-binding-contract.md``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from .package_model import ReleaseError, require
from .package_refs import qualification_url
from .support_matrix import SupportMatrixError
from .support_matrix import validate as validate_export
from .validate_receipt import ReceiptError
from .validate_receipt import validate_receipt


# Current release policy: the explicit 30-provider non-mock matrix.
# Mirrors the pooled-runner matrix minus pkcs11-mock and minus the
# heavy/manual OP-TEE targets. A narrower claim is a separate
# explicit product decision; this gate never relabels omitted rows
# as success and offers no waiver flag.
REQUIRED_PROVIDERS = (
    "bouncyhsm",
    "corepkcs11",
    "corepkcs11-main",
    "cosmian",
    "craton-hsm",
    "cryptech",
    "freehsm-c",
    "jcardsim",
    "kmsp11",
    "kryoptic",
    "kryoptic-fips",
    "kryoptic-main",
    "nethsm",
    "nss",
    "nss-main",
    "nss-main-slot0",
    "nss-pqc",
    "nss-pqc-slot0",
    "nss-slot0",
    "opencryptoki",
    "opencryptoki-master",
    "pico-hsm",
    "softhsm2",
    "softhsm2-generated-iv",
    "softhsm2-main",
    "tpm2",
    "wolfpkcs11",
    "wolfpkcs11-master",
    "wolfpkcs11-tpm",
    "wolfpkcs11-tpm-release",
)
REQUIRED_PROVIDER_SET = frozenset(REQUIRED_PROVIDERS)

EVIDENCE_ARTIFACT_NAME = "provider-qualification"
RECEIPT_FILENAME = "receipt.json"
RECORD_FILENAME = "pool-evidence.json"
RECORD_ROLE = "pool_evidence"
RECEIPT_KIND = "comparison"

# URL path segments that name a floating ref rather than an immutable
# subject or version. Case-sensitive: git refs are case-sensitive.
FLOATING_SEGMENTS = frozenset(
    {"main", "master", "HEAD", "latest", "trunk", "stable", "default"})
# Immutable markers: a full hex subject, a release download/tag, a
# version segment, or an immutable workflow-run locator.
IMMUTABLE_MARKERS = (
    re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?"),
    re.compile(r"releases/download/"),
    re.compile(r"releases/tag/"),
    re.compile(r"/v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"),
    re.compile(r"actions/runs/[1-9][0-9]*"),
)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
RUN_ID = re.compile(r"[1-9][0-9]*\Z")


def immutable_qualification_url(url: str) -> bool:
    """Check the URL names immutable qualification evidence.

    Beyond the credential-free HTTPS shape, the path must carry an
    immutable subject/version marker and must not reference a
    floating ref such as ``main`` (the v0.2.2 ``/blob/main/`` failure
    mode). Digest pinning, not this check, carries content integrity.
    """
    if not qualification_url(url):
        return False
    path = url.split("?", 1)[0].split("://", 1)[1]
    segments = [segment for segment in path.split("/") if segment]
    if any(segment in FLOATING_SEGMENTS for segment in segments):
        return False
    return any(marker.search(path) is not None
               for marker in IMMUTABLE_MARKERS)


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(path: Path, label: str):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"),
                          object_pairs_hook=_unique_keys)
    except ReleaseError:
        raise
    except (OSError, ValueError, UnicodeError) as exc:
        raise ReleaseError(
            f"cannot read {label} {path}: {exc}") from exc


def _sha256_file(path: Path, label: str) -> str:
    try:
        digest = hashlib.sha256()
        with Path(path).open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise ReleaseError(
            f"cannot read {label} {path}: {exc}") from exc
    return digest.hexdigest()


def _check_shapes(expect_commit: str, expect_tree: str,
                  expect_lock_sha256: str, expect_framework: str,
                  expect_run_id: str, expect_record_sha256: str,
                  expect_receipt_sha256: str) -> None:
    require(isinstance(expect_commit, str)
            and HEX40.match(expect_commit) is not None,
            "expected source commit must be a 40-hex SHA")
    require(isinstance(expect_tree, str)
            and HEX40.match(expect_tree) is not None,
            "expected source tree must be a 40-hex SHA")
    require(isinstance(expect_lock_sha256, str)
            and HEX64.match(expect_lock_sha256) is not None,
            "expected Cargo.lock sha256 must be 64-hex")
    require(isinstance(expect_framework, str)
            and HEX40.match(expect_framework) is not None,
            "expected framework commit must be a 40-hex SHA")
    require(isinstance(expect_run_id, str)
            and RUN_ID.match(expect_run_id) is not None,
            "expected qualification run id must be a positive integer")
    require(isinstance(expect_record_sha256, str)
            and HEX64.match(expect_record_sha256) is not None,
            "expected record sha256 must be 64-hex")
    require(isinstance(expect_receipt_sha256, str)
            and HEX64.match(expect_receipt_sha256) is not None,
            "expected receipt sha256 must be 64-hex")


def _manifest(bundle: Path, identities: dict, role: str) -> dict:
    reference = identities.get(role)
    require(isinstance(reference, dict),
            f"identities.{role} must be a bound artifact reference")
    require("not_applicable" not in reference,
            f"identities.{role} is not bound to evidence; refusing")
    name = reference.get("path")
    require(isinstance(name, str) and bool(name),
            f"identities.{role} has no artifact path")
    manifest = _load_json(bundle / name, f"identities.{role}")
    require(isinstance(manifest, dict),
            f"identities.{role} manifest must be a JSON object")
    return manifest


def verify_qualification(evidence_dir: Path | str, *,
                         expect_commit: str, expect_tree: str,
                         expect_lock_sha256: str, expect_framework: str,
                         expect_run_id: str, expect_url: str,
                         expect_record_sha256: str,
                         expect_receipt_sha256: str) -> dict:
    """Verify qualification evidence against independent expectations.

    Returns a summary mapping on success; raises ReleaseError on any
    defect. Every ``expect_*`` value must come from the release
    inputs/checkout, never from the evidence being validated.
    """
    _check_shapes(expect_commit, expect_tree, expect_lock_sha256,
                  expect_framework, expect_run_id,
                  expect_record_sha256, expect_receipt_sha256)
    require(immutable_qualification_url(expect_url),
            "qualification URL must be immutable credential-free HTTPS "
            "naming a subject, version, or workflow run")
    root = Path(evidence_dir)
    receipt_path = root / RECEIPT_FILENAME
    bundle = root / "bundle"
    require(receipt_path.is_file(),
            f"qualification evidence {receipt_path} is missing; a "
            "quality-only URL cannot satisfy qualification")
    actual_receipt = _sha256_file(receipt_path, "qualification receipt")
    require(actual_receipt == expect_receipt_sha256,
            "qualification receipt sha256 does not match the pinned "
            "evidence digest")
    receipt = _load_json(receipt_path, "qualification receipt")
    require(isinstance(receipt, dict)
            and receipt.get("kind") == RECEIPT_KIND,
            "qualification receipt must be a candidate-bound "
            f"{RECEIPT_KIND} receipt")
    try:
        validate_receipt(receipt, bundle, expected_commit=expect_commit,
                         expected_tree=expect_tree,
                         expected_lock_sha256=expect_lock_sha256,
                         require_candidate=True)
    except ReceiptError as exc:
        raise ReleaseError(f"qualification receipt refused: {exc}") from exc
    record_path = bundle / RECORD_FILENAME
    require(record_path.is_file(),
            f"provider-selection record {record_path} is missing")
    actual_record = _sha256_file(record_path, "provider-selection record")
    require(actual_record == expect_record_sha256,
            "provider-selection record sha256 does not match the "
            "pinned evidence digest")
    artifacts = receipt.get("artifacts", {})
    reference = artifacts.get(RECORD_ROLE)
    require(isinstance(reference, dict)
            and reference.get("path") == RECORD_FILENAME
            and reference.get("sha256") == actual_record,
            f"receipt must bind {RECORD_FILENAME} as {RECORD_ROLE!r}")
    record = _load_json(record_path, "provider-selection record")
    try:
        validate_export(record)
    except SupportMatrixError as exc:
        raise ReleaseError(
            f"provider-selection record refused: {exc}") from exc
    require(record.get("run_id") == expect_run_id,
            "provider-selection run id does not match the expected "
            "qualification run")
    require(record.get("candidate", {}).get("commit") == expect_commit,
            "provider-selection candidate does not match the frozen subject")
    require(record.get("framework", {}).get("commit") == expect_framework,
            "provider-selection framework does not match the expected "
            "framework commit")
    providers = record.get("providers", {})
    require(set(providers) == REQUIRED_PROVIDER_SET,
            "provider-selection must hold exactly the required "
            "30-provider non-mock matrix")
    for name in sorted(providers):
        require(providers[name].get("gate") == "PASS",
                f"provider {name!r} has no passing comparison; "
                "incomplete or failed rows cannot satisfy qualification")
    identities = receipt.get("identities", {})
    framework_manifest = _manifest(bundle, identities, "framework")
    require(framework_manifest.get("commit") == expect_framework,
            "framework identity does not match the expected framework commit")
    provider_manifest = _manifest(bundle, identities, "provider")
    require(provider_manifest.get("providers")
            == sorted(REQUIRED_PROVIDERS),
            "provider identity does not name the required 30-provider "
            "matrix")
    selection_manifest = _manifest(bundle, identities, "selection")
    require(selection_manifest.get("run_id") == expect_run_id,
            "test-selection identity does not match the expected "
            "qualification run")
    require(isinstance(selection_manifest.get("test_selection"), str)
            and bool(selection_manifest["test_selection"].strip()),
            "test-selection identity names no test selection")
    config_manifest = _manifest(bundle, identities, "config")
    require(isinstance(config_manifest.get("config"), str)
            and bool(config_manifest["config"].strip()),
            "config identity names no configuration")
    _manifest(bundle, identities, "corpora")
    return {"subject": expect_commit, "framework": expect_framework,
            "run_id": expect_run_id, "providers": len(REQUIRED_PROVIDERS),
            "record_sha256": actual_record,
            "receipt_sha256": actual_receipt}
